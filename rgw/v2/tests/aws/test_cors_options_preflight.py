"""
Usage: test_cors_options_preflight.py -c <input_yaml>

<input_yaml>
    configs/test_aws_cors_options_multi_rule_preflight.yaml
    configs/test_aws_cors_options_no_config_segfault.yaml

Operation:
    CORS OPTIONS scenarios via test_ops (if/else in test_exec):

    - options_no_cors_segfault: true  (IBMCEPH-20773 / 20785, PR #72756)
      Anonymous OPTIONS with *no* CORS must not SIGSEGV:
      3A OPTIONS /  3B missing bucket  3C existing no-CORS  3D object
      Then last: enable rgw_gcors_*, OPTIONS on missing bucket (expect
      Allow-Origin, no crash), then clear GCORS.

    - else (policy_document + preflight_checks):
      multi-rule CORS OPTIONS preflight after put-bucket-cors

    Works with http, https, haproxy via get_endpoint (config.ssl/haproxy).
"""

import argparse
import json
import logging
import os
import re
import sys
import tempfile
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    endpoint = aws_reusable.get_endpoint(
        ssh_con, ssl=config.ssl, haproxy=config.haproxy
    )
    log.info(f"RGW endpoint: {endpoint}")

    if config.test_ops.get("options_no_cors_segfault", False):
        # IBMCEPH-20773: anonymous OPTIONS with no CORS must not SIGSEGV
        origin = config.test_ops.get("origin", "http://example.com")
        method = config.test_ops.get("request_method", "GET")
        repeat = int(config.test_ops.get("options_repeat", 3))
        expected_status = int(config.test_ops.get("expected_status", 403))
        strict = config.test_ops.get("strict", True)
        timeout = int(config.test_ops.get("curl_timeout", 30))
        object_name = config.test_ops.get("object_name", "obj")
        delete_bucket = config.test_ops.get("delete_bucket", True)

        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        user = user_info[0]
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=0)
        missing_bucket = (
            f"bucket-not-exists-"
            f"{utils.gen_bucket_name_from_userid(user['user_id'], rand_no=99)}"
        )
        body_path = os.path.join(TEST_DATA_PATH, f"{object_name}.bin")
        bucket_created = False
        object_uploaded = False
        gcors_set = False
        ceph_conf = CephConfOp(ssh_con)
        rgw_service = RGWService()
        gcors_origins = config.test_ops.get("gcors_allow_origins", '"*"')
        gcors_headers = config.test_ops.get("gcors_allow_headers", '"*"')
        gcors_methods = config.test_ops.get(
            "gcors_allow_methods", "GET,PUT,POST,DELETE,HEAD,OPTIONS"
        )
        gcors_expected_status = int(config.test_ops.get("gcors_expected_status", 200))

        try:
            log.info("pre-check: endpoint reachable")
            if not aws_reusable.curl_health_head(endpoint, timeout=timeout):
                raise TestExecError("endpoint not reachable before the test")

            log.info(f"Create bucket {bucket_name} with NO CORS")
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            bucket_created = True

            with open(body_path, "wb") as fh:
                fh.write(b"x")
            aws_reusable.put_object(
                cli_aws, bucket_name, object_name, endpoint, body=body_path
            )
            object_uploaded = True
            if config.local_file_delete:
                utils.exec_shell_cmd(f"rm -f {body_path}")

            try:
                cmd = cli_aws.command(
                    operation="get-bucket-cors",
                    params=[f"--bucket {bucket_name} --endpoint-url {endpoint}"],
                )
                cors_out = utils.exec_shell_cmd(cmd)
                if cors_out and cors_out is not False:
                    log.warning(f"unexpected CORS config present: {cors_out}")
            except Exception as e:
                log.info(f"ok: no CORS config ({e})")

            scenarios = [
                ("3A", "OPTIONS / (Qualys case)", "/"),
                (
                    "3B",
                    f"OPTIONS /{missing_bucket} (non-existent bucket)",
                    f"/{missing_bucket}",
                ),
                (
                    "3C",
                    f"OPTIONS /{bucket_name} (existing bucket, no CORS)",
                    f"/{bucket_name}",
                ),
                (
                    "3D",
                    f"OPTIONS /{bucket_name}/{object_name} (object, no CORS)",
                    f"/{bucket_name}/{object_name}",
                ),
            ]
            for label, desc, path in scenarios:
                aws_reusable.verify_anonymous_options_no_cors(
                    endpoint,
                    path,
                    origin,
                    method,
                    label,
                    desc,
                    repeat=repeat,
                    expected_status=expected_status,
                    strict=strict,
                    timeout=timeout,
                    expect_access_denied=True,
                    expect_allow_origin=False,
                )

            # Last scenario: global CORS + OPTIONS on non-existent bucket
            log.info("Enable global CORS (rgw_gcors_*) for missing-bucket scenario")
            ceph_conf.set_to_ceph_conf(
                "global",
                "rgw_gcors_allow_origins",
                gcors_origins,
                ssh_con,
                set_to_all=True,
            )
            ceph_conf.set_to_ceph_conf(
                "global",
                "rgw_gcors_allow_headers",
                gcors_headers,
                ssh_con,
                set_to_all=True,
            )
            ceph_conf.set_to_ceph_conf(
                "global",
                "rgw_gcors_allow_methods",
                gcors_methods,
                ssh_con,
                set_to_all=True,
            )
            gcors_set = True
            log.info("Restart RGW so global CORS takes effect")
            if rgw_service.restart(ssh_con) is False:
                raise TestExecError("RGW service restart failed after enabling GCORS")
            time.sleep(30)
            endpoint = aws_reusable.get_endpoint(
                ssh_con, ssl=config.ssl, haproxy=config.haproxy
            )
            if not aws_reusable.curl_health_head(endpoint, timeout=timeout):
                raise TestExecError("endpoint not reachable after GCORS RGW restart")

            aws_reusable.verify_anonymous_options_no_cors(
                endpoint,
                f"/{missing_bucket}",
                origin,
                method,
                "3E",
                f"OPTIONS /{missing_bucket} with global CORS (no bucket)",
                repeat=repeat,
                expected_status=gcors_expected_status,
                strict=strict,
                timeout=timeout,
                expect_access_denied=False,
                expect_allow_origin=True,
            )
            log.info(
                f"OVERALL: PASS — 3A-3D (no CORS) + 3E (global CORS missing bucket), "
                f"repeat={repeat}"
            )
        finally:
            if gcors_set:
                try:
                    log.info("Clear global CORS settings")
                    ceph_conf.set_to_ceph_conf(
                        "global",
                        "rgw_gcors_allow_origins",
                        '""',
                        ssh_con,
                        set_to_all=True,
                    )
                    ceph_conf.set_to_ceph_conf(
                        "global",
                        "rgw_gcors_allow_headers",
                        '""',
                        ssh_con,
                        set_to_all=True,
                    )
                    ceph_conf.set_to_ceph_conf(
                        "global",
                        "rgw_gcors_allow_methods",
                        '""',
                        ssh_con,
                        set_to_all=True,
                    )
                    rgw_service.restart(ssh_con)
                    time.sleep(20)
                except Exception as e:
                    log.warning(f"Failed to clear global CORS: {e}")
            if object_uploaded:
                try:
                    aws_reusable.delete_object(
                        cli_aws, bucket_name, object_name, endpoint
                    )
                except Exception as e:
                    log.warning(f"delete_object {object_name}: {e}")
            if bucket_created and delete_bucket:
                try:
                    aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)
                except Exception as e:
                    log.warning(f"Failed to delete bucket {bucket_name}: {e}")
            if config.user_remove is True:
                for u in user_info:
                    try:
                        s3_reusable.remove_user(u)
                    except Exception as e:
                        log.warning(f"Failed to remove user {u.get('user_id')}: {e}")

        crash_info = s3_reusable.check_for_crash()
        if crash_info:
            raise TestExecError("ceph daemon crash found!")

    else:
        # multi-rule CORS OPTIONS preflight (put-bucket-cors then OPTIONS)
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        policy_document = config.test_ops.get("policy_document")
        if not policy_document:
            raise TestExecError("test_ops.policy_document is required")
        preflight_checks = config.test_ops.get("preflight_checks")
        if not preflight_checks:
            raise TestExecError("test_ops.preflight_checks is required")

        for user in user_info:
            user_name = user["user_id"]
            log.info(user_name)
            cli_aws = AWS(ssl=config.ssl)
            aws_auth.do_auth_aws(user)

            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                log.info(f"Bucket {bucket_name} created")

                cors_path = None
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".json", delete=False
                    ) as cors_file:
                        cors_file.write(json.dumps(policy_document, indent=2))
                        cors_path = cors_file.name
                    aws_reusable.put_bucket_cors(
                        cli_aws, bucket_name, cors_path, endpoint
                    )
                    log.info(f"Put CORS configuration on {bucket_name}")
                finally:
                    if cors_path and os.path.exists(cors_path):
                        os.remove(cors_path)

                for check in preflight_checks:
                    name = check.get("name", "preflight")
                    origin = check["origin"]
                    method = check["method"]
                    request_headers = check.get("request_headers")
                    expected_status = int(check["expected_status"])
                    log.info(
                        f"Preflight '{name}': origin={origin}, method={method}, "
                        f"request_headers={request_headers}, "
                        f"expected_status={expected_status}"
                    )
                    insecure = " -k" if endpoint.startswith("https://") else ""
                    curl_cmd = (
                        f'curl -si{insecure} -X OPTIONS "{endpoint}/{bucket_name}"'
                        f' -H "Origin: {origin}"'
                        f' -H "Access-Control-Request-Method: {method}"'
                    )
                    if request_headers:
                        curl_cmd += (
                            f' -H "Access-Control-Request-Headers: {request_headers}"'
                        )
                    log.info(f"Executing: {curl_cmd}")
                    response = utils.exec_shell_cmd(curl_cmd)
                    if response is False:
                        raise TestExecError(
                            f"OPTIONS curl failed for bucket={bucket_name}, "
                            f"method={method}"
                        )
                    response = str(response)
                    log.info(f"OPTIONS response:\n{response}")
                    response_oneline = " ".join(response.split())
                    status_match = re.search(r"HTTP/\S+\s+(\d+)", response)
                    if not status_match:
                        raise TestExecError(
                            f"Could not parse status code from OPTIONS response: "
                            f"endpoint={endpoint}, bucket={bucket_name}, "
                            f"method={method}, response={response_oneline}"
                        )
                    status = int(status_match.group(1))
                    if status != expected_status:
                        raise AssertionError(
                            f"Preflight '{name}': expected status code "
                            f"{expected_status}, found status code {status}, "
                            f"endpoint={endpoint}, origin={origin}, "
                            f"method={method}, request_headers={request_headers}, "
                            f"response={response_oneline}"
                        )
                    if expected_status == 200:
                        if "Access-Control-Allow-Origin" not in response:
                            raise AssertionError(
                                f"Preflight '{name}': missing "
                                f"Access-Control-Allow-Origin, endpoint={endpoint}, "
                                f"origin={origin}, method={method}, "
                                f"response={response_oneline}"
                            )
                        if (
                            origin not in response
                            and "Access-Control-Allow-Origin: *" not in response
                        ):
                            raise AssertionError(
                                f"Preflight '{name}': Allow-Origin mismatch for "
                                f"{origin}, endpoint={endpoint}, method={method}, "
                                f"response={response_oneline}"
                            )
                        if method not in response:
                            raise AssertionError(
                                f"Preflight '{name}': missing method {method} in "
                                f"Allow-Methods, endpoint={endpoint}, "
                                f"origin={origin}, response={response_oneline}"
                            )
                    log.info(
                        f"Preflight '{name}' passed: status code {status}, "
                        f"endpoint={endpoint}"
                    )

                if config.test_ops.get("delete_bucket", True):
                    aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)
                    log.info(f"Bucket {bucket_name} deleted")

        if config.user_remove is True:
            for user in user_info:
                s3_reusable.remove_user(user)

        crash_info = s3_reusable.check_for_crash()
        if crash_info:
            raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW CORS OPTIONS preflight scenarios")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW CORS OPTIONS preflight")
        parser.add_argument("-c", dest="config", help="input yaml config")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = resource_op.Config(yaml_file)
        config.read(ssh_con)
        no_cors = config.test_ops.get("options_no_cors_segfault", False)
        if config.mapped_sizes is None and not no_cors:
            if config.objects_size_range is None:
                raise TestExecError(
                    "objects_size_range is required in config yaml "
                    "(min/max) for make_mapped_sizes"
                )
            config.mapped_sizes = utils.make_mapped_sizes(config)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
