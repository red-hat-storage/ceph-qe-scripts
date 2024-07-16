"""
# test s3 bucket policy operations (create/modify/replace existing policy)

usage : test_bucket_policy_ops.py -c configs/<input-yaml>
where input-yaml test_bucket_policy_delete.yaml, test_bucket_policy_modify.yaml and test_bucket_policy_replace.yaml,
  test_bucket_policy_multiple_conflicting_statements.yaml, test_bucket_policy_multiple_statements.yaml,
  test_bucket_policy_condition.yaml, test_bucket_policy_condition_explicit_deny.yaml,
  test_bucket_policy_invalid_*.yaml, test_sse_kms_per_bucket_with_bucket_policy.yaml,
  test_bucket_policy_deny_actions.yaml

Operation:
- create bucket in tenant1 for user1
- generate bucket policy to user1 in tenant1, policy: list access to user1 in tenant2
- add the policy to user1 in bucket1
- testing
- modify bucket policy to replace the existing policy - TC 11215
- add policy to the existing policy - TC 11214


"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import botocore.exceptions as boto3exception
import v2.lib.resource_op as s3lib
import v2.lib.s3.bucket_policy as s3_bucket_policy
import v2.tests.s3_swift.reusables.bucket_policy_ops as bucket_policy_ops
import v2.utils.utils as utils
from botocore.handlers import validate_bucket_name
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()


TEST_DATA_PATH = None


# bucket policy examples: https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html
# Actions list: https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html
# test run: https://polarion.engineering.redhat.com/polarion/#/project/CEPH/testrun?id=3_0_RHEL_7_4_RGW_BucketPolicyCompatibilityWithS3&tab=records&result=passed
# ceph supported actions: http://docs.ceph.com/docs/master/radosgw/bucketpolicy/

# sample bucket policy dict, this will be used to construct bucket policy for the test.


def get_svc_time(ssh_con=None):
    cmd = "pidof radosgw"
    if ssh_con:
        _, pid, _ = ssh_con.exec_command(cmd)
        pid = pid.readline()
        log.info(pid)
    else:
        pid = utils.exec_shell_cmd(cmd)
    pid = pid.strip()
    cmd = "ps -p " + pid + " -o etimes"
    if ssh_con:
        _, srv_time, _ = ssh_con.exec_command(cmd)
        _ = srv_time.readline()
        srv_time = srv_time.readline()
        srv_time = srv_time.replace("\n", "")
        srv_time = srv_time.replace(" ", "")
        srv_time = int(srv_time)
    else:
        srv_time = utils.exec_shell_cmd(cmd)
        srv_time = srv_time.replace("\n", "")
        srv_time = srv_time.replace(" ", "")
        srv_time = int(srv_time[7:])
    return srv_time


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
    else:
        log.info("RGW service restarted")

    # create user
    config.user_count = 1
    tenant1 = "MountEverest"
    tenant2 = "Himalayas"
    tenant1_user_info = s3lib.create_tenant_users(
        tenant_name=tenant1, no_of_users_to_create=config.user_count
    )
    tenant1_user1_info = tenant1_user_info[0]
    for each_user in tenant1_user_info:
        tenant1_user1_information = each_user
    tenant2_user_info = s3lib.create_tenant_users(
        tenant_name=tenant2, no_of_users_to_create=config.user_count
    )
    tenant2_user1_info = tenant2_user_info[0]
    tenant1_user1_auth = Auth(tenant1_user1_info, ssh_con, ssl=config.ssl)
    tenant2_user1_auth = Auth(tenant2_user1_info, ssh_con, ssl=config.ssl)
    rgw_tenant1_user1 = tenant1_user1_auth.do_auth()
    rgw_tenant1_user1_c = tenant1_user1_auth.do_auth_using_client()
    rgw_tenant2_user1 = tenant2_user1_auth.do_auth()
    rgw_tenant2_user1_c = tenant2_user1_auth.do_auth_using_client()
    rgw_tenant2_user1_sns_client = tenant2_user1_auth.do_auth_sns_client()
    bucket_name1 = utils.gen_bucket_name_from_userid(
        tenant1_user1_info["user_id"], rand_no=1
    )
    t1_u1_bucket1 = reusable.create_bucket(
        bucket_name1,
        rgw_tenant1_user1,
        tenant1_user1_info,
    )

    if config.test_ops.get("sse_s3_per_bucket") is True:
        reusable.put_get_bucket_encryption(rgw_tenant1_user1_c, bucket_name1, config)

    bucket_name2 = utils.gen_bucket_name_from_userid(
        tenant1_user1_info["user_id"], rand_no=2
    )
    t1_u1_bucket2 = reusable.create_bucket(
        bucket_name2,
        rgw_tenant1_user1,
        tenant1_user1_info,
    )
    if not config.test_ops.get("policy_document", False):
        bucket_policy_generated = s3_bucket_policy.gen_bucket_policy(
            tenants_list=[tenant2],
            userids_list=[tenant2_user1_info["user_id"]],
            actions_list=["CreateBucket"],
            resources=[t1_u1_bucket1.name],
        )
        bucket_policy = json.dumps(bucket_policy_generated)
    else:
        bucket_policy_generated = config.test_ops["policy_document"]
        bucket_policy = json.dumps(bucket_policy_generated)
        bucket_policy = bucket_policy.replace("<tenant_name>", tenant2)
        bucket_policy = bucket_policy.replace("<bucket_name>", t1_u1_bucket1.name)
        bucket_policy = bucket_policy.replace(
            "<user_name>", tenant2_user1_info["user_id"]
        )
        bucket_policy_generated = json.loads(bucket_policy)
        config.test_ops["policy_document"] = bucket_policy_generated
    log.info("jsoned policy:%s\n" % bucket_policy)
    log.info("bucket_policy_generated:%s\n" % bucket_policy_generated)
    bucket_policy_obj = s3lib.resource_op(
        {
            "obj": rgw_tenant1_user1,
            "resource": "BucketPolicy",
            "args": [t1_u1_bucket1.name],
        }
    )
    put_policy = s3lib.resource_op(
        {
            "obj": bucket_policy_obj,
            "resource": "put",
            "kwargs": dict(ConfirmRemoveSelfBucketAccess=True, Policy=bucket_policy),
        }
    )
    log.info("put policy response:%s\n" % put_policy)
    if put_policy is False:
        if config.test_ops.get("invalid_policy", False):
            log.info("Invalid bucket policy creation failed as expected")
        else:
            raise TestExecError(
                "Resource execution failed: bucket policy creation faield"
            )
    else:
        if put_policy is not None:
            response = HttpResponseParser(put_policy)
            if response.status_code == 200 or response.status_code == 204:
                if config.test_ops.get("invalid_policy", False):
                    raise TestExecError("Invalid bucket policy creation passed")
                else:
                    log.info("bucket policy created")
            else:
                raise TestExecError("bucket policy creation failed")
        else:
            raise TestExecError("bucket policy creation failed")

        if config.test_ops.get("upload_type") == "multipart":
            # verifies bug 1960262 rgw: Crash on multipart upload to bucket with policy
            srv_time_pre_op = get_svc_time(ssh_con)
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(t1_u1_bucket1.name, oc)
                log.info("s3 objects to create: %s" % config.objects_count)
                reusable.upload_mutipart_object(
                    s3_object_name,
                    t1_u1_bucket1,
                    TEST_DATA_PATH,
                    config,
                    tenant1_user1_information,
                )
            srv_time_post_op = get_svc_time(ssh_con)
            log.info(srv_time_pre_op)
            log.info(srv_time_post_op)

            if srv_time_post_op > srv_time_pre_op:
                log.info("Service is running without crash")
            else:
                raise TestExecError("Service got crashed")
        elif config.test_ops.get("upload_type") == "normal":
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(t1_u1_bucket1.name, oc)
                log.info("s3 object name: %s" % s3_object_name)
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info("s3 object path: %s" % s3_object_path)
                log.info("upload type: normal")
                reusable.upload_object(
                    s3_object_name,
                    t1_u1_bucket1,
                    TEST_DATA_PATH,
                    config,
                    tenant1_user1_info,
                )

        # get policy
        get_policy = rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name)
        log.info("got bucket policy:%s\n" % get_policy["Policy"])

        if config.test_ops.get("verify_policy"):
            bucket_name_verify_policy = f"{tenant1}:{t1_u1_bucket1.name}"
            rgw_tenant2_user1_c.meta.events.unregister(
                "before-parameter-build.s3", validate_bucket_name
            )
            rgw_tenant1_user1_c.meta.events.unregister(
                "before-parameter-build.s3", validate_bucket_name
            )
            bucket_policy_ops.verify_policy(
                bucket_owner_rgw_client=rgw_tenant1_user1_c,
                config=config,
                rgw_client=rgw_tenant2_user1_c,
                bucket_name=bucket_name_verify_policy,
                object_name=f"{s3_object_name}-verify-policy",
                rgw_s3_resource=rgw_tenant2_user1,
                sns_client=rgw_tenant2_user1_sns_client,
            )

        # modifying bucket policy to take new policy
        if config.bucket_policy_op == "modify":
            # adding new action list: ListBucket to existing action: CreateBucket
            log.info("modifying buckey policy")
            actions_list = ["ListBucket", "CreateBucket"]
            actions = list(map(s3_bucket_policy.gen_action, actions_list))
            bucket_policy2_generated = s3_bucket_policy.gen_bucket_policy(
                tenants_list=[tenant1],
                userids_list=[tenant2_user1_info["user_id"]],
                actions_list=actions_list,
                resources=[t1_u1_bucket1.name],
            )
            bucket_policy2 = json.dumps(bucket_policy2_generated)
            put_policy = s3lib.resource_op(
                {
                    "obj": bucket_policy_obj,
                    "resource": "put",
                    "kwargs": dict(
                        ConfirmRemoveSelfBucketAccess=True, Policy=bucket_policy2
                    ),
                }
            )
            log.info("put policy response:%s\n" % put_policy)
            if put_policy is False:
                raise TestExecError("Resource execution failed: bucket creation faield")
            if put_policy is not None:
                response = HttpResponseParser(put_policy)
                if response.status_code == 200 or response.status_code == 204:
                    log.info("bucket policy created")
                else:
                    raise TestExecError("bucket policy creation failed")
            else:
                raise TestExecError("bucket policy creation failed")
            get_modified_policy = rgw_tenant1_user1_c.get_bucket_policy(
                Bucket=t1_u1_bucket1.name
            )
            modified_policy = json.loads(get_modified_policy["Policy"])
            log.info("got bucket policy:%s\n" % modified_policy)
            actions_list_from_modified_policy = modified_policy["Statement"][0][
                "Action"
            ]
            cleaned_actions_list_from_modified_policy = list(
                map(str, actions_list_from_modified_policy)
            )
            log.info(
                "cleaned_actions_list_from_modified_policy: %s"
                % cleaned_actions_list_from_modified_policy
            )
            log.info("actions list to be modified: %s" % actions)
            cmp_val = utils.cmp(actions, cleaned_actions_list_from_modified_policy)
            log.info("cmp_val: %s" % cmp_val)
            if cmp_val != 0:
                raise TestExecError("modification of bucket policy failed ")
        if config.bucket_policy_op == "replace":
            log.info("replacing new bucket policy")
            new_policy_generated = s3_bucket_policy.gen_bucket_policy(
                tenants_list=[tenant1],
                userids_list=[tenant2_user1_info["user_id"]],
                actions_list=["ListBucket"],
                resources=[t1_u1_bucket2.name],
            )
            new_policy = json.dumps(new_policy_generated)
            put_policy = s3lib.resource_op(
                {
                    "obj": bucket_policy_obj,
                    "resource": "put",
                    "kwargs": dict(
                        ConfirmRemoveSelfBucketAccess=True, Policy=new_policy
                    ),
                }
            )
            log.info("put policy response:%s\n" % put_policy)
            if put_policy is False:
                raise TestExecError("Resource execution failed: bucket creation faield")
            if put_policy is not None:
                response = HttpResponseParser(put_policy)
                if response.status_code == 200 or response.status_code == 204:
                    log.info("new bucket policy created")
                else:
                    raise TestExecError("bucket policy creation failed")
            else:
                raise TestExecError("bucket policy creation failed")
        if config.bucket_policy_op == "delete":
            log.info("in delete bucket policy")
            delete_policy = s3lib.resource_op(
                {"obj": bucket_policy_obj, "resource": "delete", "args": None}
            )
            if delete_policy is False:
                raise TestExecError("Resource execution failed: bucket creation faield")
            if delete_policy is not None:
                response = HttpResponseParser(delete_policy)
                if response.status_code == 200 or response.status_code == 204:
                    log.info("bucket policy deleted")
                else:
                    raise TestExecError("bucket policy deletion failed")
            else:
                raise TestExecError("bucket policy deletion failed")
            # confirming once again by calling get_bucket_policy
            try:
                rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name)
                raise TestExecError("bucket policy did not get deleted")
            except boto3exception.ClientError as e:
                log.info(e.response)
                response = HttpResponseParser(e.response)
                if response.error["Code"] == "NoSuchBucketPolicy":
                    log.info("bucket policy deleted")
                else:
                    raise TestExecError("bucket policy did not get deleted")
            # log.info('get_policy after deletion: %s' % get_policy)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket policy")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
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
