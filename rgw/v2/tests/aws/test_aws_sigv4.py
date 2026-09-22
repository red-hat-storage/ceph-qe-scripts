"""
Usage: test_aws_sigv4.py -c <input_yaml>

<input_yaml>
    configs/test_sigv4_unsigned_content_type.yaml

Operation:
    SigV4 scenarios selected via test_ops flags.
"""

import argparse
import logging
import os
import sys
import traceback
import urllib.parse

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import requests
import urllib3
from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.curl import reusable as curl_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    region = config.test_ops.get("region", "us-east-1")
    verify_tls = bool(config.ssl) and config.test_ops.get("verify_tls", False)
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    for user in user_info:
        user_name = user["user_id"]
        log.info(f"user: {user_name}")
        auth = s3_reusable.get_auth(user, ssh_con, config.ssl, config.haproxy)
        rgw_s3_client = auth.do_auth_using_client(
            signature_version="s3v4",
            region_name=region,
        )
        cli_aws = AWS(ssl=config.ssl)
        endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info(f"Bucket {bucket_name} created")
            objects = []

            if config.test_ops.get("unsigned_content_type_put", False):
                unsigned_ct = config.test_ops.get("unsigned_content_type", "image/png")
                run_curl = config.test_ops.get("curl_sigv4_path", False)
                run_mpu = config.test_ops.get("multipart_contrast", False)
                key = "avatar.png"
                payload = b'{"hello":"world"}'
                objects.append(key)

                if not verify_tls:
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                log.info("presigned put_object without ContentType")
                url = rgw_s3_client.generate_presigned_url(
                    ClientMethod="put_object",
                    Params={"Bucket": bucket_name, "Key": key},
                    ExpiresIn=3600,
                    HttpMethod="PUT",
                )
                qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
                signed = qs.get("X-Amz-SignedHeaders", "")
                log.info(f"X-Amz-SignedHeaders={signed}")
                if "content-type" in signed.lower():
                    raise TestExecError(f"content-type in SignedHeaders: {signed}")
                if "host" not in signed.lower():
                    raise TestExecError(f"host missing from SignedHeaders: {signed}")

                resp = requests.put(url, data=payload, verify=verify_tls)
                log.info(f"presigned PUT without Content-Type: HTTP {resp.status_code}")
                if resp.status_code != 200:
                    raise TestExecError(
                        f"presigned PUT without Content-Type: "
                        f"expected 200, got {resp.status_code}"
                    )

                resp = requests.put(
                    url,
                    data=payload,
                    headers={"Content-Type": unsigned_ct},
                    verify=verify_tls,
                )
                log.info(
                    f"presigned PUT with unsigned Content-Type: "
                    f"HTTP {resp.status_code}"
                )
                if resp.status_code != 200:
                    raise TestExecError(
                        f"presigned PUT with unsigned Content-Type: "
                        f"expected 200, got {resp.status_code}"
                    )

                if run_mpu:
                    mpu_key = "mpu-test"
                    log.info("multipart upload contrast")
                    mpu = rgw_s3_client.create_multipart_upload(
                        Bucket=bucket_name,
                        Key=mpu_key,
                        ContentType="application/octet-stream",
                    )
                    part = rgw_s3_client.upload_part(
                        Bucket=bucket_name,
                        Key=mpu_key,
                        PartNumber=1,
                        UploadId=mpu["UploadId"],
                        Body=os.urandom(6 * 1024 * 1024),
                    )
                    rgw_s3_client.complete_multipart_upload(
                        Bucket=bucket_name,
                        Key=mpu_key,
                        UploadId=mpu["UploadId"],
                        MultipartUpload={
                            "Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]
                        },
                    )
                    objects.append(mpu_key)

                if run_curl:
                    curl_reusable.install_curl(version="7.88.1")
                    curl_key = "sigv4-avatar.png"
                    payload_path = os.path.join(
                        TEST_DATA_PATH, f"payload_{bucket_name}.json"
                    )
                    with open(payload_path, "wb") as fh:
                        fh.write(payload)
                    object_url = f"{endpoint}/{bucket_name}/{curl_key}"
                    status = curl_reusable.curl_put_http_status(
                        object_url,
                        payload_path,
                        content_type=None,
                        ssl=config.ssl,
                        access_key=user["access_key"],
                        secret_key=user["secret_key"],
                        region=region,
                    )
                    if status != 200:
                        raise TestExecError(
                            f"curl sigv4 PUT without Content-Type: "
                            f"expected 200, got {status}"
                        )
                    status = curl_reusable.curl_put_http_status(
                        object_url,
                        payload_path,
                        content_type=unsigned_ct,
                        ssl=config.ssl,
                        access_key=user["access_key"],
                        secret_key=user["secret_key"],
                        region=region,
                    )
                    if status != 200:
                        raise TestExecError(
                            f"curl sigv4 PUT with unsigned Content-Type: expected 200, got {status}"
                        )
                    objects.append(curl_key)
                    if config.local_file_delete:
                        utils.exec_shell_cmd(f"rm -f {payload_path}")

            for key in objects:
                try:
                    aws_reusable.delete_object(cli_aws, bucket_name, key, endpoint)
                except Exception as e:
                    log.warning(f"delete_object {key}: {e}")
            aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)

        if config.user_remove:
            s3_reusable.remove_user(user)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW SigV4 tests")
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW SigV4 tests")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
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
