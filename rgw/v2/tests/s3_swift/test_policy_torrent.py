"""
# test s3 bucket policies for object torrent from different users under same tenant

usage : test_policy_torrent.py -c configs/<input-yaml>
where input-yaml test_policy_torrent.yaml
Polarion : CEPH-11209

Operation:
- create bucket user1
- Using policy s3:GetObjectTorrent, users under same and different tenants,should be able to torrent for the file

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
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
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


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # create user
    config.user_count = 2
    tenant1 = "Everest"
    tenant2 = "Himalaya"
    tenant1_user_info = s3lib.create_tenant_users(
        tenant_name=tenant1, no_of_users_to_create=config.user_count
    )
    tenant1_user1_info = tenant1_user_info[0]
    tenant1_user2_info = tenant1_user_info[1]

    tenant2_user_info = s3lib.create_tenant_users(
        tenant_name=tenant2, no_of_users_to_create=config.user_count
    )
    tenant2_user1_info = tenant2_user_info[0]
    tenant2_user2_info = tenant2_user_info[1]

    tenant1_user1_auth = Auth(tenant1_user1_info, ssh_con, ssl=config.ssl)
    tenant1_user2_auth = Auth(tenant1_user2_info, ssh_con, ssl=config.ssl)
    rgw_tenant1_user1 = tenant1_user1_auth.do_auth()
    rgw_tenant1_user1_c = tenant1_user1_auth.do_auth_using_client()
    rgw_tenant1_user2 = tenant1_user2_auth.do_auth()
    rgw_tenant1_user2_c = tenant1_user2_auth.do_auth_using_client()

    tenant2_user1_auth = Auth(tenant2_user1_info, ssh_con, ssl=config.ssl)
    tenant2_user2_auth = Auth(tenant2_user2_info, ssh_con, ssl=config.ssl)
    rgw_tenant2_user1 = tenant2_user1_auth.do_auth()
    rgw_tenant2_user1_c = tenant2_user1_auth.do_auth_using_client()
    rgw_tenant2_user2 = tenant2_user2_auth.do_auth()
    rgw_tenant2_user2_c = tenant2_user2_auth.do_auth_using_client()

    bucket_name1 = utils.gen_bucket_name_from_userid(
        tenant1_user1_info["user_id"], rand_no=1
    )
    t1_u1_bucket1 = reusable.create_bucket(
        bucket_name1,
        rgw_tenant1_user1,
        tenant1_user1_info,
        ip_and_port,
    )
    rgw_service_name = utils.exec_shell_cmd("ceph orch ls | grep rgw").split(" ")[0]
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_torrent_flag true"
    )
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(20)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    log.info("RGW Torrent flag enabled and service restarted")

    if config.test_ops.get("upload_type") == "normal":
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(t1_u1_bucket1.name, oc)
            log.info(f"s3 object name: {s3_object_name}")
            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
            log.info(f"s3 object path: {s3_object_path}")
            log.info("upload type: normal")
            reusable.upload_object(
                s3_object_name,
                t1_u1_bucket1,
                TEST_DATA_PATH,
                config,
                tenant1_user1_info,
            )

    log.info("Create bucket policy for users under same tenant to get object torrent")
    bucket_policy_generated = config.test_ops["policy_document"]
    bucket_policy = json.dumps(bucket_policy_generated)
    bucket_policy = bucket_policy.replace("<tenant_name>", tenant1)
    bucket_policy = bucket_policy.replace("<user_name>", tenant1_user2_info["user_id"])
    bucket_policy_generated = json.loads(bucket_policy)
    config.test_ops["policy_document"] = bucket_policy_generated

    log.info(f"jsoned policy: {bucket_policy} \n")
    log.info(f"bucket_policy_generated: {bucket_policy_generated} \n")
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
    log.info(f"put policy response: {put_policy}")
    if put_policy is False:
        raise TestExecError("Resource execution failed: bucket policy creation failed")
    else:
        if put_policy is None:
            raise TestExecError("bucket policy creation failed")
        else:
            response = HttpResponseParser(put_policy)
            log.info("bucket policy created")

            log.info(tenant1_user1_info)
            log.info(tenant1_user2_info)
            log.info(rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name))

            log.info("Get object torrent from user2 (non owner) under tenant1")
            try:
                out = rgw_tenant1_user2_c.get_object_torrent(
                    Bucket=t1_u1_bucket1.name,
                    Key=s3_object_name,
                )
                if not out:
                    raise TestExecError("Torrent creation failed")
                log.info(f"Torrent is {out}")
            except Exception as e:
                log.info(f"Fails as expected with {e}")

            log.info("Get object torrent from bucket owner")
            try:
                out1 = rgw_tenant1_user1_c.get_object_torrent(
                    Bucket=t1_u1_bucket1.name,
                    Key=s3_object_name,
                )
                if not out1:
                    raise TestExecError("Torrent creation failed")
                log.info(f"Torrent is {out1}")
            except Exception as e:
                log.info(f"Fails as expected with {e}")

    log.info("Create bucket policy for cross tenant user object torrent access")
    bucket_policy_generated1 = config.test_ops["policy_document1"]
    bucket_policy1 = json.dumps(bucket_policy_generated1)
    bucket_policy1 = bucket_policy1.replace("<tenant_name>", tenant2)
    bucket_policy1 = bucket_policy1.replace(
        "<user_name>", tenant2_user1_info["user_id"]
    )
    bucket_policy_generated1 = json.loads(bucket_policy1)
    config.test_ops["policy_document1"] = bucket_policy_generated1

    log.info(f"jsoned policy: {bucket_policy1} \n")
    log.info(f"bucket_policy_generated: {bucket_policy_generated1} \n")
    bucket_policy_obj1 = s3lib.resource_op(
        {
            "obj": rgw_tenant1_user1,
            "resource": "BucketPolicy",
            "args": [t1_u1_bucket1.name],
        }
    )
    put_policy1 = s3lib.resource_op(
        {
            "obj": bucket_policy_obj1,
            "resource": "put",
            "kwargs": dict(ConfirmRemoveSelfBucketAccess=True, Policy=bucket_policy1),
        }
    )
    log.info(f"put policy response: {put_policy1}")
    if put_policy1 is False:
        raise TestExecError("Resource execution failed: bucket policy creation failed")
    else:
        if put_policy1 is None:
            raise TestExecError("bucket policy creation failed")
        else:
            response = HttpResponseParser(put_policy1)
            log.info("bucket policy created")
            log.info("Get object torrent from user1 under tenant2")
            rgw_tenant2_user1_c.meta.events.unregister(
                "before-parameter-build.s3", validate_bucket_name
            )
            try:
                out = rgw_tenant2_user1_c.get_object_torrent(
                    Bucket=f"{tenant1}:{t1_u1_bucket1.name}",
                    Key=s3_object_name,
                )
                if not out:
                    raise TestExecError("Torrent creation failed")
                log.info(f"Torrent is {out}")
            except Exception as e:
                log.info(f"Fails as expected with {e}")

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
