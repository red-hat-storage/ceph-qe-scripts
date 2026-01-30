"""
test_sts_aswi.py - Test STS Assume role with web identity

Usage: test_sts_aswi.py -c <input_yaml>
<input_yaml>
    test_sts_aswi.yaml
    test_sts_aswi_azp_claim.yaml
    test_sts_aswi_sub_claim.yaml
    test_sts_aswi_aud_claim.yaml
    test_sts_aswi_aws_principal_tag_role_policy.yaml
    test_sts_aswi_aws_request_tag_trust_policy.yaml
    test_sts_aswi_aws_tagkeys_role_policy.yaml
    test_sts_aswi_aws_tagkeys_trust_policy.yaml
    test_sts_aswi_creds_expire_copy_in_progress.yaml
    test_sts_aswi_iam_resource_tag_trust_policy.yaml
    test_sts_aswi_s3_res_equals_aws_princ_tag_role_policy.yaml
    test_sts_aswi_s3_resource_tag_role_policy.yaml
    test_sts_aswi_verify_role_policy_allow_actions.yaml
    test_sts_aswi_verify_role_policy_deny_actions.yaml
    test_sts_aswi_isv.yaml
    test_sts_aswi_isv_verify_role_policy_allow_actions.yaml
    test_sts_aswi_isv_verify_role_policy_deny_actions.yaml

Operation:
    s1: Create 2 Users.
        user1 will be the owner and will give permission to create bucket to user2
    s2: keycloak deployment and administration
    s3: create openid connect provider
    s4: add caps to user1 for create role and oidc-provider - use radosgw-admin
    s5: create iam_client object using user1 credentials
    s6: gen a policy_doc added with user2 uid added in it.
    s7: create role
    s8: put role
    s9: get sts client object
    s10: assume role with web identity, this will return credentials and token
    s11: with above credentials create s3 object and start the io
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
from datetime import datetime

import boto3
import v2.lib.resource_op as s3lib
import v2.tests.s3_swift.reusables.bucket_policy_ops as bucket_policy_ops
import v2.tests.s3_swift.reusables.sts as stsaswi
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables.sts import Keycloak
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
    local_ip_addr = utils.get_localhost_ip_address()

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
    if config.test_ops.get("verify_policy"):
        ceph_config_set.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_enable_static_website,
            True,
            ssh_con,
        )

    if config.test_ops.get("test_copy_in_progress_sts_creds_expire"):
        ceph_config_set.set_to_ceph_conf(
            "global", ConfigOpts.debug_rgw, str(config.debug_rgw), ssh_con
        )
        ceph_config_set.set_to_ceph_conf("global", "log_to_file", "true", ssh_con)

    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    auth = Auth(user1, ssh_con, ssl=config.ssl)
    iam_client = auth.do_auth_iam_client()
    user1_client = auth.do_auth_using_client()
    rgw_conn_user1 = auth.do_auth()

    auth2 = Auth(user2, ssh_con, ssl=config.ssl)
    iam_client2 = auth2.do_auth_iam_client()
    sts_client = auth2.do_auth_sts_client()
    log.info(f"sts client: {sts_client}")

    policy_document = json.dumps(config.sts["policy_document"]).replace(" ", "")
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

    # configure identity_provider, get web token and create open_id_connect_provider
    stsaswi.delete_open_id_connect_provider(iam_client)
    identity_provider = config.test_ops.get("identity_provider", "Keycloak")
    if identity_provider == "Keycloak":
        keycloak = Keycloak(
            client_id="sts_client",
            client_secret="client_secret1",
            ip_addr=local_ip_addr,
            attributes=config.test_ops.get("session_tags"),
        )

        web_token = keycloak.get_web_access_token()
        jwt = keycloak.introspect_token(web_token)
        policy_document = policy_document.replace("ip_addr", local_ip_addr)
        policy_document = policy_document.replace("azp_claim", jwt["azp"])
        policy_document = policy_document.replace("sub_claim", jwt["sub"])
        stsaswi.create_open_id_connect_provider(iam_client, identity_provider, keycloak)
    elif identity_provider == "IBM_Security_Verify":
        utils.exec_shell_cmd(
            "cp /home/cephuser/configs/rgw/ibm_isv/get_isv_web_token.sh /home/cephuser/get_isv_web_token.sh"
        )
        utils.exec_shell_cmd("chmod +rwx /home/cephuser/get_isv_web_token.sh")
        out = json.loads(utils.exec_shell_cmd("sh /home/cephuser/get_isv_web_token.sh"))
        log.info(f"web token output: {out}")
        web_token = out["id_token"]
        out = utils.exec_shell_cmd("cat /home/cephuser/configs/rgw/ibm_isv/oidc_url")
        url = out.strip()
        idp_url_for_arn = url.replace("https://", "")
        policy_document = policy_document.replace("idp_url", idp_url_for_arn)
        stsaswi.create_open_id_connect_provider(iam_client, identity_provider)
    stsaswi.list_open_id_connect_provider(iam_client)

    log.info(f"assume-role-policy-doc: {policy_document}")
    log.info(f"role policy: {role_policy}")
    log.info(f"web token: {web_token}")

    role_name = f"S3RoleOf.{user1['user_id']}"
    log.info(f"role_name: {role_name}")
    log.info("creating role")
    create_role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document, Path="/", RoleName=role_name
    )
    log.info(f"create_role_response: {create_role_response}")

    if config.test_ops.get("iam_resource_tags"):
        print("Adding tags to role\n")
        tag_role_response = iam_client.tag_role(
            RoleName=role_name, Tags=config.test_ops.get("iam_resource_tags")
        )
        log.info(f"tag_role_response: {tag_role_response}")

    policy_name = f"policy.{user1['user_id']}"
    log.info(f"policy_name: {policy_name}")

    log.info("putting role policy")
    put_policy_response = iam_client.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
    )
    log.info("put_policy_response")
    log.info(put_policy_response)

    sts_creds_created_time = time.time()
    sts_creds_validity_seconds = config.test_ops.get("sts_creds_validity_seconds", 3600)
    assume_role_response = sts_client.assume_role_with_web_identity(
        RoleArn=create_role_response["Role"]["Arn"],
        RoleSessionName=user1["user_id"],
        DurationSeconds=sts_creds_validity_seconds,
        WebIdentityToken=web_token,
    )
    log.info(f"assume role with web identity response: {assume_role_response}")

    assumed_role_user_info = {
        "access_key": assume_role_response["Credentials"]["AccessKeyId"],
        "secret_key": assume_role_response["Credentials"]["SecretAccessKey"],
        "session_token": assume_role_response["Credentials"]["SessionToken"],
        "user_id": user2["user_id"],
    }
    s3_auth = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
    rgw_conn_using_sts_creds = s3_auth.do_auth()
    rgw_client_using_sts_creds = s3_auth.do_auth_using_client()
    sts_user_sns_client = s3_auth.do_auth_sns_client()

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
    if config.test_ops.get("verify_policy"):
        verify_policy = config.test_ops.get("verify_policy", "session_policy")
        bucket_name = f"{assumed_role_user_info['user_id']}-bkt1"
        bucket_policy_ops.CreateBucket(rgw_client=user1_client, bucket_name=bucket_name)
        for i in range(1, 10):
            bucket_policy_ops.PutObject(
                rgw_client=user1_client, bucket_name=bucket_name, object_name=f"obj{i}"
            )
        s3_object_name = f"Key_{bucket_name}"
        bucket_policy_ops.verify_policy(
            config=config,
            bucket_owner_rgw_client=user1_client,
            rgw_client=rgw_client_using_sts_creds,
            bucket_name=bucket_name,
            object_name=s3_object_name,
            rgw_s3_resource=rgw_conn_using_sts_creds,
            sns_client=sts_user_sns_client,
            policy_document=config.sts.get(verify_policy),
        )
    else:
        if config.test_ops["create_bucket"]:
            log.info(f"Number of buckets to create {config.bucket_count}")
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    assumed_role_user_info["user_id"], rand_no=bc
                )
                log.info(f"creating bucket with name: {bucket_name_to_create}")
                if config.test_ops.get("s3_resource_tag"):
                    rgw_conn = rgw_conn_user1
                else:
                    rgw_conn = rgw_conn_using_sts_creds
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, assumed_role_user_info, ip_and_port
                )
                if config.test_ops.get("s3_resource_tag"):
                    bucket = s3lib.resource_op(
                        {
                            "obj": rgw_conn_using_sts_creds,
                            "resource": "Bucket",
                            "args": [bucket_name_to_create],
                        }
                    )
                if config.test_ops.get("bucket_tags"):
                    response = user1_client.put_bucket_tagging(
                        Bucket=bucket_name_to_create,
                        Tagging={
                            "TagSet": config.test_ops.get("bucket_tags"),
                        },
                    )
                    log.info(f"put bucket tagging response: {response}")
                if config.test_ops["create_object"]:
                    # uploading data
                    log.info(f"s3 objects to create: {config.objects_count}")
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
                        log.info(f"s3 object name: {s3_object_name}")
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info(f"s3 object path: {s3_object_path}")
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
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                assumed_role_user_info,
                            )

    # refer bz: https://bugzilla.redhat.com/show_bug.cgi?id=2214981
    if config.test_ops.get("test_copy_in_progress_sts_creds_expire"):
        sleep_time_for_copy = sts_creds_created_time + sts_creds_validity_seconds - 15
        log.info(
            f"sleeping till {datetime.fromtimestamp(sleep_time_for_copy)} for testing sts creds expire while copy object is in progress"
        )
        while time.time() < sleep_time_for_copy:
            time.sleep(5)
        copy_object_name = f"copy_of_{s3_object_name}"
        log.info(f"copying object {s3_object_name} to {copy_object_name}")
        copy_source = {"Bucket": bucket.name, "Key": s3_object_name}
        status_copy_object = s3lib.resource_op(
            {
                "obj": bucket,
                "resource": "copy",
                "args": [copy_source, copy_object_name],
            }
        )
        if status_copy_object is False:
            log.info(
                "Failed to copy object as expected because sts creds expired in the middle"
            )
        if status_copy_object is None:
            raise TestExecError(
                "copy object is successful even after sts creds expired, expected to fail"
            )

        search_string = "402 Notify failed on object"
        if utils.search_for_string_in_rgw_logs(search_string, ssh_con):
            raise TestExecError(f"'{search_string}' found in rgw log")
        else:
            log.info(f"'{search_string}' not found in rgw log")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "Starting STS test for assume-role with web identity operation"
    )
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 STS aswi automation")
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
