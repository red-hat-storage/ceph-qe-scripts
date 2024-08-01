"""
Usage: test_sts_rename_large_object.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_sts_rename_large_object.yaml
    configs/test_s3copyObj_admin_user.yaml

Operation:
    s1: Create 2 Users[t1user, t2user], where t1user is the admin user and t2user is the sts user
    s2: Create a bucket for t1user
    s3: Add role caps to the t1user and create a role, that can be assumed by t2user
    s4: Attach role policy to role created
    s5: Get role and verify the role information
    s6: create a large file, 1 GB or more
    s7: Invoke Assumerole in a script the snippet
    s8: Copy these credentials in aws credentials file under 'sts' profile --> please note that the credentials will be valid only for 900 seconds or 15 minutes as DurationSeconds is 900 in the AssumeRole call.
    s9: aws s3 cp sample.txt s3://my-bucket --endpoint=http://localhost:8000 --profile=sts -->profile 'sts' contains temp creds as stated above
    s10: aws s3 mv s3://my-bucket/sample.txt s3://my-bucket/sample.out --endpoint=http://localhost:8000 --profile=sts --> this fails without the fix, and must pass with the fix.
"""


import argparse
import json
import logging
import os
import random
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

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
    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()

    if config.sts is None:
        raise TestExecError("sts policies are missing in yaml config")

    user_info = resource_op.create_users(no_of_users_to_create=2)
    # user1 is the owner
    user1, user2 = user_info[0], user_info[1]
    aws_auth.do_auth_aws(user1)
    bucket_name = utils.gen_bucket_name_from_userid(user1["user_id"])
    log.info(f"creating bucket with name: {bucket_name}")
    cli_aws = AWS(ssl=config.ssl)
    endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
    aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
    log.info(f"Bucket {bucket_name} created")

    if config.test_ops.get("enable_version", False):
        log.info(f"bucket versioning test on bucket: {bucket_name}")
        aws_reusable.put_get_bucket_versioning(cli_aws, bucket_name, endpoint)

    log.info("adding sts config to ceph.conf")
    session_encryption_token = "abcdefghijklmnoq"
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, session_encryption_token, ssh_con
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_s3_auth_use_sts, "True", ssh_con
    )

    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    auth = Auth(user1, ssh_con, ssl=config.ssl)
    iam_client = auth.do_auth_iam_client()

    policy_document = json.dumps(config.sts["policy_document"]).replace(" ", "")
    policy_document = policy_document.replace("<user_name>", user2["user_id"])

    role_policy = json.dumps(config.sts["role_policy"]).replace(" ", "")
    role_policy = role_policy.replace("<bucket_name>", bucket_name)

    add_caps_cmd = (
        'sudo radosgw-admin caps add --uid="{user_id}" --caps="roles=*"'.format(
            user_id=user1["user_id"]
        )
    )
    utils.exec_shell_cmd(add_caps_cmd)

    role_name = f"S3RoleOf.{user1['user_id']}"
    log.info(f"creating role: {role_name}")
    create_role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path="/",
        RoleName=role_name,
    )
    log.info(f"create_role_response {create_role_response}")

    policy_name = f"policy.{user1['user_id']}"
    log.info(f"putting role policy: {policy_name}")
    try:
        put_policy_response = iam_client.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
        )

        log.info(f"put_policy_response {put_policy_response}")

        auth = Auth(user2, ssh_con, ssl=config.ssl)
        sts_client = auth.do_auth_sts_client()

        assume_role_response = sts_client.assume_role(
            RoleArn=create_role_response["Role"]["Arn"],
            RoleSessionName=user2["user_id"],
            DurationSeconds=900,
        )

        log.info(f"assuming role {assume_role_response}")

        assumed_role_user_info = {
            "access_key": assume_role_response["Credentials"]["AccessKeyId"],
            "secret_key": assume_role_response["Credentials"]["SecretAccessKey"],
            "session_token": assume_role_response["Credentials"]["SessionToken"],
            "user_id": user2["user_id"],
        }

        log.info(f"Got the credentials after assume role {assumed_role_user_info}")
        # Copy these credentials in aws credentials file under 'sts' profile
        aws_reusable.update_aws_file_with_sts_user(assumed_role_user_info)

        source_file = "obj1_1g.txt"
        utils.exec_shell_cmd(f"fallocate -l 1G {source_file}")
        aws_cli = "/usr/local/bin/aws s3"
        if config.ssl:
            aws_cli = aws_cli + " --no-verify-ssl"

        if config.s3_copy_obj:
            add_admin_flag = (
                'sudo radosgw-admin user modify --uid="{user_id}" --admin true'.format(
                    user_id=user1["user_id"]
                )
            )

            utils.exec_shell_cmd(add_admin_flag)
            log.info("Test s3_copy_obj for an rgw user with admin flag true.")
            utils.exec_shell_cmd(
                f"{aws_cli} cp {source_file} s3://{bucket_name}/all_buckets/{source_file} --endpoint {endpoint} "
            )

            copy_cmd = f"/usr/local/bin/aws s3api copy-object --copy-source {bucket_name}/all_buckets/{source_file} --key all_buckets/{source_file} --bucket {bucket_name}  --endpoint {endpoint}"
            if config.ssl:
                copy_cmd = copy_cmd + " --no-verify-ssl"
            utils.exec_shell_cmd(copy_cmd)
        else:
            utils.exec_shell_cmd(
                f"{aws_cli} cp {source_file} s3://{bucket_name} --endpoint {endpoint} --profile=sts"
            )
            utils.exec_shell_cmd(
                f"{aws_cli} mv s3://{bucket_name}/{source_file} s3://{bucket_name}/obj2_1g.txt --endpoint {endpoint} --profile=sts"
            )

    except ClientError as e:
        raise TestExecError(f"Rename of large object using sts user failed: {e}")

    s3_reusable.remove_user(user1)
    s3_reusable.remove_user(user2)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test rename of large object using sts user through awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW S3 rename of large object using sts user through AWS"
        )
        parser.add_argument(
            "-c",
            dest="config",
            help="RGW S3 rename of large object using sts user through AWS",
        )
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
        config.read()
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
