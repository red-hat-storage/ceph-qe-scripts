"""
Usage: test_aws_bucket_logging.py -c <input_yaml>

<input_yaml>
    configs/test_aws_bucket_logging.yaml

Operation:
    Automates S3 bucket access logging (AWS CLI):
    1. Create source and log buckets
    2. put-bucket-policy on log bucket (logging service principal)
    3. put-bucket-logging on source bucket
    4. radosgw-admin bucket logging info on log bucket (source listed)
    5. Upload objects, GET one object, flush logs
    6. Verify log object under target prefix in log bucket
    7. Delete source bucket; verify removal and cleared logging info

    Works with http and https via get_endpoint (yaml ssl or auto-detect from
    rgw_frontends). AWS CLI uses --no-verify-ssl on https endpoints.
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback
import uuid

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.tests.s3_swift.reusables import server_access_logging as bkt_logging
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    yaml_ssl = config.doc["config"].get("ssl")
    endpoint = aws_reusable.get_endpoint(ssh_con, ssl=yaml_ssl, haproxy=config.haproxy)
    use_ssl = endpoint.startswith("https://")
    log.info(f"Using endpoint {endpoint} (ssl={use_ssl})")
    target_prefix = config.test_ops.get("target_prefix", "src-logs/")
    region = config.test_ops.get("region")
    objects_count = config.objects_count or 3
    policy_template = config.test_ops.get("policy_document")
    if not policy_template:
        raise TestExecError("test_ops.policy_document is required")

    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    for user in user_info:
        user_name = user["user_id"]
        tenant_name = user.get("tenant") or ""
        log.info(user_name)
        cli_aws = AWS(ssl=use_ssl)
        aws_auth.do_auth_aws(user)

        suffix = uuid.uuid4().hex[:8]
        src_bucket = f"src-bucket-{suffix}"
        log_bucket = f"log-bucket-{suffix}"

        aws_reusable.create_bucket(cli_aws, src_bucket, endpoint)
        aws_reusable.create_bucket(cli_aws, log_bucket, endpoint)
        log.info(f"Created source bucket {src_bucket} and log bucket {log_bucket}")

        policy = json.dumps(policy_template)
        policy = policy.replace("<dest_bucket_name>", log_bucket)
        policy = policy.replace("<source_bucket_name>", src_bucket)
        policy = policy.replace("<source_user_name>", user_name)
        policy = policy.replace("<tenant_name>", tenant_name)
        policy_document = json.loads(policy)

        aws_reusable.put_bucket_policy(cli_aws, log_bucket, endpoint, policy_document)
        aws_reusable.put_bucket_logging(
            cli_aws, src_bucket, endpoint, log_bucket, target_prefix
        )

        logging_conf = aws_reusable.get_bucket_logging(cli_aws, src_bucket, endpoint)
        enabled = logging_conf.get("LoggingEnabled")
        if not enabled:
            raise TestExecError(
                f"LoggingEnabled missing for {src_bucket}: {logging_conf}"
            )
        if enabled["TargetBucket"] != log_bucket:
            raise TestExecError(
                f"Unexpected log target bucket: {logging_conf['LoggingEnabled']}"
            )

        log.info(f"radosgw-admin bucket logging info on log bucket {log_bucket}")
        logging_info = bkt_logging.rgw_admin_logging_info(log_bucket, tenant_name)
        if not logging_info or not any(
            entry.get("name") == src_bucket for entry in logging_info
        ):
            raise TestExecError(
                f"Source bucket {src_bucket} not listed in logging info for {log_bucket}: {logging_info}"
            )

        object_keys = []
        for i in range(1, objects_count + 1):
            key = f"object-{i}.txt"
            aws_reusable.s3_upload_from_stdin(
                src_bucket, key, endpoint, f"data-{key}", use_ssl, region
            )
            object_keys.append(key)

        aws_reusable.get_object(
            cli_aws, src_bucket, object_keys[0], endpoint, download_path="/dev/null"
        )

        flushed_key = bkt_logging.rgw_admin_logging_flush(src_bucket, tenant_name)
        if not flushed_key:
            raise TestExecError(f"bucket logging flush failed for {src_bucket}")
        log.info(f"Flushed log object key: {flushed_key}")

        time.sleep(5)
        list_out = aws_reusable.list_objects(cli_aws, log_bucket, endpoint)
        if list_out is False:
            raise TestExecError(f"list-objects failed for {log_bucket} on {endpoint}")
        list_data = json.loads(list_out)
        prefix_keys = [
            obj["Key"]
            for obj in list_data.get("Contents", [])
            if obj["Key"].startswith(target_prefix)
        ]
        if not prefix_keys:
            raise TestExecError(
                f"No log objects under prefix {target_prefix} in {log_bucket}"
            )
        if flushed_key not in prefix_keys:
            raise TestExecError(
                f"Flushed key {flushed_key} not found under {target_prefix}: {prefix_keys}"
            )

        aws_reusable.empty_and_remove_bucket(
            src_bucket, endpoint, ssl=use_ssl, region=region
        )

        buckets_out = aws_reusable.list_buckets(cli_aws, endpoint)
        if src_bucket in buckets_out:
            raise TestExecError(
                f"Source bucket {src_bucket} still listed after deletion"
            )

        aws_reusable.head_bucket(cli_aws, src_bucket, endpoint, expect_not_found=True)

        if config.test_ops.get("verify_logging_info_cleared", True):
            log.info(
                f"Verify radosgw-admin bucket logging info on {log_bucket} is empty "
                f"after source bucket deletion"
            )
            logging_info = bkt_logging.rgw_admin_logging_info(log_bucket, tenant_name)
            if logging_info:
                raise TestExecError(
                    f"Logging info on {log_bucket} not cleared after deleting "
                    f"{src_bucket}: {logging_info}"
                )

        if config.test_ops.get("delete_log_bucket", True):
            aws_reusable.empty_and_remove_bucket(
                log_bucket, endpoint, ssl=use_ssl, region=region
            )

    if config.user_remove is True:
        for user in user_info:
            s3_reusable.remove_user(user)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW AWS CLI bucket access logging")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW AWS CLI bucket access logging"
        )
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
        if config.mapped_sizes is None and config.objects_size_range is not None:
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
