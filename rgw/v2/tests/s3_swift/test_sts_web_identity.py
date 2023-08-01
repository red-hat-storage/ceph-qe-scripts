"""
test_sts_using_boto.py - Test STS using boto

Usage: test_sts_using_boto.py -c <input_yaml>
<input_yaml>
    test_sts_using_boto.yaml

Operation:
    s1: Create 2 Users.
        user1 will be the owner and will give permisison to create bucket to user2
    s2: add caps to user1 for creating create role - use radosgw-admin
    s3: create iam_client object using user1 credentials
    s4: gen a policy_doc added with user2 uid added in it.
    s5: create role
    s6: put role
    s7: get sts client object
    s8: assume role, this will return credentials and token
    s9: with above credentials create s3 object and start the io
        create bucket
        upload object


"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import time
import traceback

import boto3
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables.sts import Keycloak
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
    local_ip_addr = utils.get_localhost_ip_address()
    keycloack = Keycloak(
        client_id="sts_client", client_secret="client_secret1", ip_addr=local_ip_addr
    )

    if config.sts is None:
        raise TestExecError("sts policies are missing in yaml config")

    # create users
    config.user_count = 2
    users_info = s3lib.create_users(config.user_count)
    # user1 is the owner
    user1, user2 = users_info[0], users_info[1]
    log.info("adding sts config to ceph.conf")
    sesison_encryption_token = "abcdefghijklmnoq"
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, sesison_encryption_token, ssh_con
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
    user1_client = auth.do_auth_using_client()

    auth2 = Auth(user2, ssh_con, ssl=config.ssl)
    iam_client2 = auth2.do_auth_iam_client()
    sts_client = auth2.do_auth_sts_client()
    log.info(f"sts client: {sts_client}")

    policy_document = json.dumps(config.sts["policy_document"]).replace(" ", "")
    policy_document = policy_document.replace("ip_addr", local_ip_addr)
    log.info(policy_document)

    role_policy = json.dumps(config.sts["role_policy"]).replace(" ", "")

    add_caps_cmd = (
        'sudo radosgw-admin caps add --uid="{user_id}" --caps="roles=*"'.format(
            user_id=user1["user_id"]
        )
    )
    utils.exec_shell_cmd(add_caps_cmd)

    add_caps_cmd = (
        'radosgw-admin caps add --uid="{user_id}" --caps="oidc-provider=*"'.format(
            user_id=user1["user_id"]
        )
    )
    utils.exec_shell_cmd(add_caps_cmd)

    add_caps_cmd = (
        'sudo radosgw-admin caps add --uid="{user_id}" --caps="roles=*"'.format(
            user_id=user2["user_id"]
        )
    )
    utils.exec_shell_cmd(add_caps_cmd)

    add_caps_cmd = (
        'radosgw-admin caps add --uid="{user_id}" --caps="oidc-provider=*"'.format(
            user_id=user2["user_id"]
        )
    )
    utils.exec_shell_cmd(add_caps_cmd)

    keycloack.list_open_id_connect_provider(iam_client)
    keycloack.delete_open_id_connect_provider(iam_client)
    keycloack.list_open_id_connect_provider(iam_client)
    keycloack.create_open_id_connect_provider(iam_client)
    keycloack.list_open_id_connect_provider(iam_client)

    role_name = f"S3RoleOf.{user1['user_id']}"
    log.info(f"role_name: {role_name}")
    tags_list = [{"Key": "project", "Value": "ceph"}]
    log.info("creating role")
    if config.test_ops.get("create_role_tagging"):
        create_role_response = iam_client.create_role(
            AssumeRolePolicyDocument=policy_document,
            Path="/",
            RoleName=role_name,
            Tags=tags_list,
        )
    else:
        create_role_response = iam_client.create_role(
            AssumeRolePolicyDocument=policy_document, Path="/", RoleName=role_name
        )
    log.info(f"create_role_response: {create_role_response}")

    if config.test_ops.get("iam_resource_tag"):
        print("Adding tags to role\n")
        response = iam_client.tag_role(RoleName=role_name, Tags=tags_list)
        log.info("tag_role_response")
        log.info(response)

    policy_name = f"policy.{user1['user_id']}"
    log.info(f"policy_name: {policy_name}")

    log.info("putting role policy")
    put_policy_response = iam_client.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
    )
    log.info("put_policy_response")
    log.info(put_policy_response)

    web_token = keycloack.get_keycloak_web_acccess_token()
    log.info(f"web token: {web_token}")
    keycloack.introspect_token(web_token)
    assumed_role_user_info = sts_client.assume_role_with_web_identity(
        RoleArn=create_role_response["Role"]["Arn"],
        RoleSessionName=user1["user_id"],
        DurationSeconds=3600,
        WebIdentityToken=web_token,
    )
    log.info(f"assume role with web identity response: {assumed_role_user_info}")

    s3_auth = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
    s3_client_rgw = s3_auth.do_auth()

    io_info_initialize.initialize(basic_io_structure.initial())
    write_user_info = AddUserInfo()
    basic_io_structure = BasicIOInfoStructure()
    user_info = basic_io_structure.user(
        **{
            "user_id": assumed_role_user_info["user_id"],
            "access_key": assumed_role_user_info["access_key"],
            "secret_key": assumed_role_user_info["secret_key"],
        }
    )
    write_user_info.add_user_info(user_info)

    if config.test_ops["create_bucket"]:
        log.info(f"Number of buckets to create {config.bucket_count}")
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(
                assumed_role_user_info["user_id"], rand_no=bc
            )
            log.info("creating bucket with name: %s" % bucket_name_to_create)
            bucket = reusable.create_bucket(
                bucket_name_to_create, s3_client_rgw, assumed_role_user_info
            )
            if config.test_ops.get("bucket_tagging"):
                response = user1_client.put_bucket_tagging(
                    Bucket=bucket_name_to_create,
                    Tagging={
                        "TagSet": [
                            {
                                "Key": "project",
                                "Value": "ceph",
                            }
                        ],
                    },
                )
                log.info(f"put bucket tagging response: {response}")
            if config.test_ops["create_object"]:
                # uploading data
                log.info("s3 objects to create: %s" % config.objects_count)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                    log.info("s3 object name: %s" % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info("s3 object path: %s" % s3_object_path)
                    if config.test_ops.get("upload_type") == "multipart":
                        log.info("upload type: multipart")
                        reusable.upload_mutipart_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            assumed_role_user_info,
                        )
                    else:
                        log.info("upload type: normal")
                        if config.test_ops.get("object_tagging"):
                            tags = "project=ceph"
                            reusable.upload_object_with_tagging(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                assumed_role_user_info,
                                tags,
                            )
                        else:
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                assumed_role_user_info,
                            )

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")
    # except ClientError as e:
    #     log.error(e)
    #     print("403 Forbidden, invalid rule in the policy")


if __name__ == "__main__":
    test_info = AddTestInfo("Starting STS test for assume-role operation")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
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
