"""
Public Access Block (S3) with RGW account IAM users (tenanted or non-tenanted).

Same scenarios as test_bucket_policy_ops.py for PublicAccessBlockConfiguration,
but users are created via rgw_accounts.create_rgw_account_with_iam_user (account + IAM user).

Set ``use_tenanted_account: false`` in test_ops for non-tenanted accounts; anonymous curl
URLs use ``/bucket/key`` instead of ``/tenant:bucket/key``.

Usage:
  test_public_access_block_rgw_accounts.py -c configs/test_public_access_block_rgw_accounts_acl.yaml

See also configs:
  test_public_access_block_rgw_accounts_ignore_acl.yaml
  test_public_access_block_rgw_accounts_ignore_acl_non_tenanted.yaml
  test_public_access_block_rgw_accounts_pre_bucket_policy.yaml
  test_public_access_block_rgw_accounts_post_bucket_policy.yaml
  test_public_access_block_rgw_accounts_restricted.yaml
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import botocore.exceptions as boto3exception
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_accounts as accounts
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def _path_style_bucket_base_url(rgw_endpoint_url, bucket_name, tenant_name=None):
    """Path-style base URL for anonymous curl (``tenant:bucket`` vs ``bucket``)."""
    if tenant_name:
        return f"{rgw_endpoint_url}/{tenant_name}:{bucket_name}"
    return f"{rgw_endpoint_url}/{bucket_name}"


def _policy_json_str(config, bucket_name, tenant_name, user_id):
    doc = config.test_ops["policy_document"]
    s = json.dumps(doc)
    s = s.replace("<bucket_name>", bucket_name)
    s = s.replace("<tenant_name>", tenant_name or "")
    s = s.replace("<user_name>", user_id)
    return s


def verify_public_acl_tests(
    rgw_s3_client, bucket_name, tenant_name, public_access_block, rgw_endpoint_url
):
    """BlockPublicAcls / IgnorePublicAcls checks (aligned with test_bucket_policy_ops)."""
    if public_access_block.get("BlockPublicAcls", False):
        log.info("testing public_access_block BlockPublicAcls")
        try:
            reusable.put_get_bucket_acl(
                rgw_s3_client, bucket_name, "public-read-write"
            )
            raise TestExecError(
                "put bucket acl passed even after BlockPublicAcls is set"
            )
        except boto3exception.ClientError:
            log.info("put bucket acl failed as expected as BlockPublicAcls is set")

        log.info("upload object obj1 into bucket %s", bucket_name)
        resp = rgw_s3_client.put_object(
            Bucket=bucket_name, Key="obj1", Body="randomtext1"
        )
        log.info("upload object obj1 resp: %s", resp)
        try:
            reusable.set_get_object_acl(
                "obj1", bucket_name, rgw_s3_client, "public-read-write"
            )
            raise TestExecError(
                "put object acl passed even after BlockPublicAcls is set"
            )
        except boto3exception.ClientError:
            log.info("put object acl failed as expected as BlockPublicAcls is set")

        try:
            log.info(
                "upload object obj2 with public acl into bucket %s", bucket_name
            )
            rgw_s3_client.put_object(
                Bucket=bucket_name,
                Key="obj2",
                Body="randomtext2",
                ACL="public-read-write",
            )
            raise TestExecError(
                "put object with public acl passed even after BlockPublicAcls is set"
            )
        except boto3exception.ClientError:
            log.info(
                "put object with public acl failed as expected as BlockPublicAcls is set"
            )

    if public_access_block.get("IgnorePublicAcls", False):
        log.info("testing public_access_block IgnorePublicAcls")
        log.info(
            "upload object obj3 with public acl into bucket %s", bucket_name
        )
        resp = rgw_s3_client.put_object(
            Bucket=bucket_name,
            Key="obj3",
            Body="randomtext3",
            ACL="public-read-write",
        )
        log.info("upload object obj3 resp: %s", resp)

        log.info("download object obj3 without auth %s", bucket_name)
        base = _path_style_bucket_base_url(rgw_endpoint_url, bucket_name, tenant_name)
        out = utils.exec_shell_cmd(
            f"curl --show-error --fail-with-body -v -s -X GET "
            f"'{base}/obj3' -o obj3.download"
        )
        if out is False:
            log.info(
                "get public object failed as expected as IgnorePublicAcls is set"
            )
        else:
            raise TestExecError(
                "get public object passed even after IgnorePublicAcls is set"
            )


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()
    if config.test_ops.get("verify_policy"):
        ceph_config_set.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_enable_static_website,
            True,
            ssh_con,
        )
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    log.info("RGW service restarted")

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
    tenanted = config.test_ops.get("use_tenanted_account", True)
    tenant_name = (
        config.test_ops.get("tenant_name", "rgwacctenant") if tenanted else ""
    )
    region = config.test_ops.get("region", "shared")

    all_users_info = accounts.create_rgw_account_with_iam_user(
        config, tenant_name if tenanted else "", region, tenanted=tenanted
    )

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_s3_client = auth.do_auth_using_client()

        bucket_name_str = utils.gen_bucket_name_from_userid(
            each_user["user_id"], rand_no=1
        )
        bucket = reusable.create_bucket(
            bucket_name_str, rgw_conn, each_user, ip_and_port
        )

        public_access_block = config.test_ops.get("public_access_block_config", {})
        rgw_endpoint_url = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)

        if config.test_ops.get("put_public_access_block", False):
            reusable.put_get_public_access_block(
                rgw_s3_client, bucket.name, public_access_block
            )

        if config.test_ops.get("verify_public_acl", False):
            verify_public_acl_tests(
                rgw_s3_client,
                bucket.name,
                tenant_name,
                public_access_block,
                rgw_endpoint_url,
            )
            reusable.delete_objects(bucket)
            reusable.delete_bucket(bucket)
            continue

        if not config.test_ops.get("policy_document"):
            raise TestExecError(
                "policy_document is required in test_ops when verify_public_acl is false"
            )

        policy_str = _policy_json_str(
            config, bucket.name, tenant_name, each_user["user_id"]
        )
        log.info("bucket policy json: %s", policy_str)

        put_failed = False
        try:
            rgw_s3_client.put_bucket_policy(Bucket=bucket.name, Policy=policy_str)
        except boto3exception.ClientError as e:
            put_failed = True
            log.info("put_bucket_policy ClientError: %s", e)

        if config.test_ops.get("test_public_access_block_pre_bucket_policy", False):
            if not put_failed:
                raise TestExecError(
                    "put bucket policy passed even after BlockPublicPolicy is set "
                    "in public_access_block"
                )
            log.info(
                "put bucket policy failed as expected as BlockPublicPolicy is set"
            )
            reusable.delete_objects(bucket)
            reusable.delete_bucket(bucket)
            continue

        if put_failed:
            raise TestExecError("put bucket policy failed unexpectedly")

        log.info("bucket policy created")
        get_policy = rgw_s3_client.get_bucket_policy(Bucket=bucket.name)
        log.info("got bucket policy: %s", get_policy.get("Policy"))

        if config.test_ops.get("put_public_access_block_post_bucket_policy", False):
            log.info(
                "setting public_access_block after bucket policy; existing policy "
                "should still allow anonymous access where applicable"
            )
            reusable.put_get_public_access_block(
                rgw_s3_client,
                bucket.name,
                config.test_ops.get("public_access_block_config", {}),
            )
            time.sleep(5)

            log.info(
                "put object obj4 into bucket %s without auth", bucket.name
            )
            base = _path_style_bucket_base_url(
                rgw_endpoint_url, bucket.name, tenant_name or None
            )
            out = utils.exec_shell_cmd(
                f"curl --show-error --fail-with-body -v -s -d 'randomdata4' -X PUT "
                f"'{base}/obj4'"
            )
            if out is False:
                raise TestExecError(
                    "public access PUT should not fail; policy was set before "
                    "BlockPublicPolicy"
                )
            log.info("put obj4 output: %s", out)

            log.info("list objects in bucket %s without auth", bucket.name)
            out = utils.exec_shell_cmd(
                f"curl --show-error --fail-with-body -v -s -X GET "
                f"'{base}/'"
            )
            if out is False:
                raise TestExecError(
                    "public list should not fail; policy was set before BlockPublicPolicy"
                )
            log.info("list objects output: %s", out)

        if config.test_ops.get("verify_restricted_public_buckets", False):
            log.info("verify_restricted_public_buckets")
            rb = _path_style_bucket_base_url(
                rgw_endpoint_url, bucket.name, tenant_name or None
            )
            out = utils.exec_shell_cmd(
                f"curl --show-error --fail-with-body -v -s -d 'randomdata5' -X PUT "
                f"'{rb}/obj5'"
            )
            if out is False:
                log.info(
                    "public access denied as expected (RestrictPublicBuckets): %s",
                    out,
                )
            else:
                raise TestExecError(
                    "public PUT should not succeed when RestrictPublicBuckets is set"
                )

            out = utils.exec_shell_cmd(
                f"curl --show-error --fail-with-body -v -s -X GET "
                f"'{rb}/'"
            )
            if out is False:
                log.info(
                    "public list denied as expected (RestrictPublicBuckets): %s",
                    out,
                )
            else:
                raise TestExecError(
                    "public list should not succeed when RestrictPublicBuckets is set"
                )

        reusable.delete_objects(bucket)
        reusable.delete_bucket(bucket)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("test public access block with RGW account IAM users")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s", TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW S3 Automation")
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
        config = Config(yaml_file)
        config.read(ssh_con)
        if config.test_ops.get("upload_type"):
            if config.mapped_sizes is None:
                config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
