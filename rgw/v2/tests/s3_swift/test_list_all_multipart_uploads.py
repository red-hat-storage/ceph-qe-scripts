"""
# test list bucket multipart uploads

usage : test_list_all_multipart_uploads.py -c configs/test_list_all_multipart_uploads.yaml

Operation:
- Create two users in the same tenant, user1 and user2
- Create two buckets(bucket1, bucket2) and upload multipart object with user1.
- Using user1 credentials, set bucket policy for user2 to list the multipart objects of
  bucket1 created with user1
- Verify user2 can list the object multiparts of bucket1
- Verify permission denied for user2 to list objects in bucket2


"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import string
import traceback

import v2.lib.resource_op as s3lib
import v2.lib.s3.bucket_policy as s3_bucket_policy
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser

log = logging.getLogger()


TEST_DATA_PATH = None


def get_svc_time():

    cmd = "pidof radosgw"
    pid = utils.exec_shell_cmd(cmd)
    pid = pid.strip()
    cmd = "ps -p " + pid + " -o etimes"
    srv_time = utils.exec_shell_cmd(cmd)
    srv_time = srv_time.replace("\n", "")
    srv_time = srv_time.replace(" ", "")
    srv_time = int(srv_time[7:])
    return srv_time


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    if config.test_ops.get("upload_type") == "multipart":
        srv_time_pre_op = get_svc_time()

    # create user
    tenant1 = "tenant_" + random.choice(string.ascii_letters)
    tenant1_user_info = s3lib.create_tenant_users(
        tenant_name=tenant1, no_of_users_to_create=2
    )
    tenant1_user1_info = tenant1_user_info[0]
    tenant1_user2_info = tenant1_user_info[1]

    tenant1_user1_auth = Auth(tenant1_user1_info, ssl=config.ssl)
    tenant1_user2_auth = Auth(tenant1_user2_info, ssl=config.ssl)

    rgw_tenant1_user1 = tenant1_user1_auth.do_auth()
    rgw_tenant1_user1_c = tenant1_user1_auth.do_auth_using_client()
    rgw_tenant1_user2 = tenant1_user2_auth.do_auth()
    rgw_tenant1_user2_c = tenant1_user2_auth.do_auth_using_client()

    bucket_name1 = utils.gen_bucket_name_from_userid(
        tenant1_user1_info["user_id"], rand_no=1
    )
    t1_u1_bucket1 = reusable.create_bucket(
        bucket_name1,
        rgw_tenant1_user1,
        tenant1_user1_info,
    )
    bucket_name2 = utils.gen_bucket_name_from_userid(
        tenant1_user1_info["user_id"], rand_no=2
    )
    t1_u1_bucket2 = reusable.create_bucket(
        bucket_name2,
        rgw_tenant1_user1,
        tenant1_user1_info,
    )
    bucket_policy_generated = s3_bucket_policy.gen_bucket_policy(
        tenants_list=[tenant1],
        userids_list=[tenant1_user2_info["user_id"]],
        actions_list=["ListBucketMultiPartUploads"],
        resources=[t1_u1_bucket1.name],
    )
    bucket_policy = json.dumps(bucket_policy_generated)
    log.info("jsoned policy:%s\n" % bucket_policy)
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
        raise TestExecError("Resource execution failed: bucket creation faield")
    if put_policy is not None:
        response = HttpResponseParser(put_policy)
        if response.status_code == 200 or response.status_code == 204:
            log.info("bucket policy created")
        else:
            raise TestExecError("bucket policy creation failed")
    else:
        raise TestExecError("bucket policy creation failed")

    if config.test_ops.get("upload_type") == "multipart":
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            for bucket in [t1_u1_bucket1, t1_u1_bucket2]:
                s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                log.info("s3 objects to create: %s" % config.objects_count)
                reusable.upload_mutipart_object(
                    s3_object_name,
                    bucket,
                    TEST_DATA_PATH,
                    config,
                    tenant1_user1_info,
                )
        srv_time_post_op = get_svc_time()
        log.info(srv_time_pre_op)
        log.info(srv_time_post_op)

        if srv_time_post_op > srv_time_pre_op:
            log.info("Service is running without crash")
        else:
            raise TestExecError("Service got crashed")

    # get policy
    get_policy = rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name)
    log.info("got bucket policy:%s\n" % get_policy["Policy"])

    # List multipart uploads with tenant1_user2 user with bucket t1_u1_bucket1
    multipart_object1 = rgw_tenant1_user2_c.list_multipart_uploads(
        Bucket=t1_u1_bucket1.name
    )
    log.info("Multipart object %s" % multipart_object1)

    # Verify tenant1_user2 not having permission for listing multipart uploads in t1_u1_bucket2
    try:
        multipart_object2 = rgw_tenant1_user2_c.list_multipart_uploads(
            Bucket=t1_u1_bucket2.name
        )
        raise Exception(
            "%s user should not list multipart uploads in bucket: %s"
            % (tenant1_user2_info["user_id"], t1_u1_bucket2.name)
        )
    except ClientError as err:
        log.error("Listing failed as expected with exception: %s" % err)

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
        args = parser.parse_args()
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read()
        if config.test_ops.get("upload_type") == "multipart":
            if config.mapped_sizes is None:
                config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
