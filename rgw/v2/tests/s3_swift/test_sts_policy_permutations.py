"""
test_sts_using_boto_session_policy.py - Test STS using boto

Usage: test_sts_using_boto_session_policy.py -c <input_yaml>
<input_yaml>
    configs/test_sts_using_boto_permissive_session_policy.yaml
    configs/test_sts_using_boto_restricted_session_policy.yaml
    test_sts_using_boto_verify_session_policy_allow_actions.yaml
    test_sts_using_boto_verify_session_policy_deny_actions.yaml
    test_sts_using_boto_verify_session_policy_allow_put_object_and_deny_abort_multipart.yaml
    test_sts_using_boto_verify_session_policy_deny_sns_topic_actions.yaml

Operation:
    s1: Create 2 Users.
        user1 will be the owner and will give permisison to create bucket to user2
    s2: add caps to user1 for creating create role - use radosgw-admin
    s3: create iam_client object using user1 credentials
    s4: gen a policy_doc added with user2 uid added in it.
    s5: gen a session policy that would be passed while invoking the assume_role API
    s5: create role
    s6: put role
    s7: get sts client object
    s8: assume role, this will return credentials and token
    s9: The s3 operations like create_bucket or upload_object will be allowed as per the permissions obtained by the intersection of the role and the inline session policies.
    s10: Try s3 operations with a permissive session policy and restricted session policies compared to the role policy
    s11: with above credentials create s3 object and start the io
        create bucket
        upload object

permutations:
1. same/different principal
2. with only role policy and role+session policy
2. effect: allow/deny
3. resource: arn_access_all_buckets_and_objects,
4. for each s3 action

"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.tests.s3_swift.reusables.bucket_policy_ops as bucket_policy_ops
import v2.utils.utils as utils
import v2.tests.s3_swift.reusables.sts_permutations as sts_permutations
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    if config.sts is None:
        raise TestExecError("sts policies are missing in yaml config")

    # create users
    config.user_count = 3
    users_info = s3lib.create_users(config.user_count)
    # user1 is the owner
    user1, user2, user3 = users_info[0], users_info[1], users_info[2]
    log.info("adding sts config to ceph.conf")
    sesison_encryption_token = "abcdefghijklmnoq"
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, sesison_encryption_token, ssh_con
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_s3_auth_use_sts, "True", ssh_con
    )
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
    else:
        log.info("RGW service restarted")

    auth = Auth(user1, ssh_con, ssl=config.ssl)
    iam_client = auth.do_auth_iam_client()
    user1_rgw_client = auth.do_auth_using_client()

    policy_document = json.dumps(config.sts["policy_document"]).replace(" ", "")
    policy_document = policy_document.replace("<user_name>", user2["user_id"])

    role_policy = json.dumps(config.sts["role_policy"]).replace(" ", "")

    session_policy = json.dumps(config.sts["session_policy"]).replace(" ", "")

    add_caps_cmd = (
        'sudo radosgw-admin caps add --uid="{user_id}" --caps="roles=*"'.format(
            user_id=user1["user_id"]
        )
    )
    utils.exec_shell_cmd(add_caps_cmd)

    # role_name = f"S3RoleOf.{user1['user_id']}"
    # log.info(f"role_name: {role_name}")
    #
    # log.info("creating role")
    # create_role_response = iam_client.create_role(
    #     AssumeRolePolicyDocument=policy_document,
    #     Path="/",
    #     RoleName=role_name,
    # )
    # log.info("create_role_response")
    # log.info(create_role_response)
    #
    # policy_name = f"policy.{user1['user_id']}"
    # log.info(f"policy_name: {policy_name}")
    #
    # log.info("putting role policy")
    # put_policy_response = iam_client.put_role_policy(
    #     RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
    # )
    #
    # log.info("put_policy_response")
    # log.info(put_policy_response)
    #
    # auth = Auth(user2, ssh_con, ssl=config.ssl)
    # sts_client = auth.do_auth_sts_client()
    #
    # log.info("assuming role")
    # assume_role_response = sts_client.assume_role(
    #     RoleArn=create_role_response["Role"]["Arn"],
    #     RoleSessionName=user1["user_id"],
    #     Policy=session_policy,
    #     DurationSeconds=3600,
    # )
    #
    # log.info(assume_role_response)
    #
    # assumed_role_user_info = {
    #     "access_key": assume_role_response["Credentials"]["AccessKeyId"],
    #     "secret_key": assume_role_response["Credentials"]["SecretAccessKey"],
    #     "session_token": assume_role_response["Credentials"]["SessionToken"],
    #     "user_id": user2["user_id"],
    # }
    #
    # log.info("got the credentials after assume role")
    # s3client = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
    # s3_client_rgw = s3client.do_auth()
    # sts_user_rgw_client = s3client.do_auth_using_client()
    # sts_user_rgw_sns_client = auth.do_auth_sns_client()
    #
    # io_info_initialize.initialize(basic_io_structure.initial())
    # write_user_info = AddUserInfo()
    # basic_io_structure = BasicIOInfoStructure()
    # user_info = basic_io_structure.user(
    #     **{
    #         "user_id": assumed_role_user_info["user_id"],
    #         "access_key": assumed_role_user_info["access_key"],
    #         "secret_key": assumed_role_user_info["secret_key"],
    #     }
    # )
    # write_user_info.add_user_info(user_info)
    #
    # if config.test_ops.get("verify_policy"):
    #     verify_policy = config.test_ops.get("verify_policy", "session_policy")
    #     bucket_name = f"{assumed_role_user_info['user_id']}-bkt1"
    #     s3_object_name = f"Key_{bucket_name}"
    #     bucket_policy_ops.CreateBucket(
    #         rgw_client=user1_rgw_client, bucket_name=bucket_name
    #     )
    #     for i in range(1, 10):
    #         bucket_policy_ops.PutObject(
    #             rgw_client=user1_rgw_client,
    #             bucket_name=bucket_name,
    #             object_name=f"obj{i}",
    #         )
    #     bucket_policy_ops.verify_policy(
    #         config=config,
    #         bucket_owner_rgw_client=user1_rgw_client,
    #         rgw_client=sts_user_rgw_client,
    #         bucket_name=bucket_name,
    #         object_name=s3_object_name,
    #         rgw_s3_resource=s3_client_rgw,
    #         sns_client=sts_user_rgw_sns_client,
    #         policy_document=config.sts.get(verify_policy),
    #     )
    # else:
    #     if config.test_ops["create_bucket"] is True:
    #         log.info(f"no of buckets to create: {config.bucket_count}")
    #         for bc in range(config.bucket_count):
    #             bucket_name_to_create = utils.gen_bucket_name_from_userid(
    #                 assumed_role_user_info["user_id"], rand_no=bc
    #             )
    #             log.info(f"creating bucket with name: {bucket_name_to_create}")
    #             bucket = reusable.create_bucket(
    #                 bucket_name_to_create,
    #                 s3_client_rgw,
    #                 assumed_role_user_info,
    #                 ip_and_port,
    #             )
    #             if config.test_ops["create_object"] is True:
    #                 # uploading data
    #                 log.info(f"s3 objects to create: {config.objects_count}")
    #                 for oc, size in list(config.mapped_sizes.items()):
    #                     config.obj_size = size
    #                     s3_object_name = utils.gen_s3_object_name(
    #                         bucket_name_to_create, oc
    #                     )
    #                     log.info(f"s3 object name: {s3_object_name}")
    #                     s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    #                     log.info(f"s3 object path: {s3_object_path}")
    #                     reusable.failed_upload_object(
    #                         s3_object_name,
    #                         bucket,
    #                         TEST_DATA_PATH,
    #                         config,
    #                         assumed_role_user_info,
    #                     )
    if config.test_ops.get("verify_policy"):

        utils.exec_shell_cmd("fallocate -l 9KB /home/cephuser/obj9KB")
        utils.exec_shell_cmd("fallocate -l 12MB /home/cephuser/obj12MB")
        utils.exec_shell_cmd("mkdir -p /home/cephuser/obj12MB.parts/")
        utils.exec_shell_cmd("split -b 6m /home/cephuser/obj12MB /home/cephuser/obj12MB.parts/")
        sts_permutations.test_sts_policy_permutations(user1, user2, user3, ssh_con, config)

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("create m buckets with n objects")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 STS automation")
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
