"""
test_server_access_logging - Test Server Access Logging feature
Usage: test_server_access_logging.py -c <input_yaml>
<input_yaml>
    Note: any one of these yamls can be used
    test_bucket_logging_journal_mode.yaml
    test_bucket_logging_journal_mode_multipart.yaml
    test_bucket_logging_standard_mode.yaml
    test_bucket_logging_standard_mode_multipart.yaml
Operation:
    create user (tenant/non-tenant)
    Create src and dest buckets
    put-bucket-policy on the target bucket to allow logging_service_principal send log objects to it from src bucket
    put-bucket-logging on the src-bucket
    perform operations on the src-bucket
    flush out the log records as log object to target bucket
    verify the log records for correctness and completeness
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import json
import logging
import random
import time
import traceback
import uuid

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import EventRecordDataError, RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_accounts as accounts
from v2.tests.s3_swift.reusables import server_access_logging as bkt_logging
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # add service2 sdk extras so that bucket logging api's and respective fields are supported
    utils.add_service2_sdk_extras(
        sdk_file_location="https://github.com/ceph/ceph/blob/main/examples/rgw/boto3/service-2.sdk-extras.json?raw=true"
    )

    if config.enable_resharding and config.sharding_type == "dynamic":
        reusable.set_dynamic_reshard_ceph_conf(config, ssh_con)
        log.info("trying to restart services")
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")

    if config.user_type is None:
        config.user_type = "non-tenanted"

    # create user
    if config.test_ops.get("test_via_rgw_accounts", False) is True:
        # create rgw account, account root user, iam user and return iam user details
        tenant_name = config.test_ops.get("tenant_name")
        region = config.test_ops.get("region")
        all_users_info = accounts.create_rgw_account_with_iam_user(
            config,
            tenant_name,
            region,
        )

    # create user
    elif config.user_type == "non-tenanted":
        all_users_info = s3lib.create_users(config.user_count)
    else:
        umgmt = UserMgmt()
        all_users_info = []
        for i in range(config.user_count):
            user_name = "user" + str(uuid.uuid4().hex[:16])
            tenant_name = "tenant" + str(i)
            tenant_user = umgmt.create_tenant_user(
                tenant_name=tenant_name, user_id=user_name, displayname=user_name
            )
            all_users_info.append(tenant_user)

    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()

        # authenticate with s3 client
        rgw_s3_client = auth.do_auth_using_client()

        objects_created_list = []
        if config.test_ops.get("create_bucket", False):
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                src_bucket_name = f"src-bkt{bc}-{each_user['user_id']}"
                dest_bucket_name = f"dest-bkt{bc}-{each_user['user_id']}"
                src_bucket = reusable.create_bucket(
                    src_bucket_name, rgw_conn, each_user
                )
                dest_bucket = reusable.create_bucket(
                    dest_bucket_name, rgw_conn, each_user
                )
                if config.test_ops.get("enable_version", False):
                    log.info("enable bucket version")
                    reusable.enable_versioning(
                        src_bucket, rgw_conn, each_user, write_bucket_io_info
                    )

                # put bucket policy on dest bucket to allow logging service for src bucket
                bucket_policy_generated = config.test_ops["policy_document"]
                bucket_policy = json.dumps(bucket_policy_generated)
                bucket_policy = bucket_policy.replace(
                    "<dest_bucket_name>", dest_bucket_name
                )
                bucket_policy = bucket_policy.replace(
                    "<source_bucket_name>", src_bucket_name
                )
                bucket_policy = bucket_policy.replace(
                    "<source_user_name>", each_user["user_id"]
                )
                bucket_policy_generated = json.loads(bucket_policy)
                config.test_ops["policy_document"] = bucket_policy_generated
                log.info(f"jsoned policy: {bucket_policy}")
                log.info(f"bucket_policy_generated: {bucket_policy_generated}")
                bucket_policy_obj = s3lib.resource_op(
                    {
                        "obj": rgw_conn,
                        "resource": "BucketPolicy",
                        "args": [dest_bucket_name],
                    }
                )
                put_policy = s3lib.resource_op(
                    {
                        "obj": bucket_policy_obj,
                        "resource": "put",
                        "kwargs": dict(
                            ConfirmRemoveSelfBucketAccess=True, Policy=bucket_policy
                        ),
                    }
                )
                log.info(f"put policy response on {dest_bucket_name}: {put_policy}")
                if put_policy is False:
                    raise TestExecError(
                        "Resource execution failed: put bucket policy failed"
                    )
                else:
                    if put_policy is not None:
                        response = HttpResponseParser(put_policy)
                        if response.status_code == 200 or response.status_code == 204:
                            log.info("put bucket policy successful")
                        else:
                            raise TestExecError("put bucket policy failed")
                    else:
                        raise TestExecError("put bucket policy failed")

                # put bucket logging
                bkt_logging.put_bucket_logging(
                    rgw_s3_client, src_bucket_name, dest_bucket_name, config
                )

                # get bucket logging
                bkt_logging.get_bucket_logging(rgw_s3_client, src_bucket_name)

                # get bucket logging with radosgw-admin command
                log.info(
                    f"radosgw-admin bucket logging info on source bucket: {src_bucket_name}"
                )
                out = bkt_logging.rgw_admin_logging_info(src_bucket_name)
                if not out:
                    raise Exception(
                        "radosgw-admin bucket logging info on source bucket failed"
                    )

                log.info(
                    f"radosgw-admin bucket logging info on target bucket: {dest_bucket_name}"
                )
                out = bkt_logging.rgw_admin_logging_info(dest_bucket_name)
                if not out:
                    raise Exception(
                        "radosgw-admin bucket logging info on target bucket failed"
                    )

                # create objects
                if config.test_ops.get("create_object", False):
                    # uploading data
                    log.info("s3 objects to create: %s" % config.objects_count)
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(src_bucket_name, oc)
                        obj_name_temp = s3_object_name
                        log.info("s3 object name: %s" % s3_object_name)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info("s3 object path: %s" % s3_object_path)
                        if config.test_ops.get("upload_type") == "multipart":
                            log.info("upload type: multipart")
                            reusable.upload_mutipart_object(
                                s3_object_name,
                                src_bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                            )
                        if config.test_ops.get("upload_type") == "normal":
                            log.info("upload type: normal")
                            reusable.upload_object(
                                s3_object_name,
                                src_bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                            )

                        objects_created_list.append((s3_object_name, s3_object_path))

                        # copy objects
                        if config.test_ops.get("copy_object", False):
                            obj_name = "copy_of_object" + obj_name_temp
                            log.info(f"copy object {s3_object_name} to {obj_name}")
                            status = rgw_s3_client.copy_object(
                                Bucket=src_bucket_name,
                                Key=obj_name,
                                CopySource={
                                    "Bucket": src_bucket_name,
                                    "Key": s3_object_name,
                                },
                            )
                            if status is None:
                                raise TestExecError("copy object failed")
                            objects_created_list.append((obj_name, s3_object_path))

                # verify resharding
                if config.enable_resharding:
                    if config.sharding_type == "manual":
                        reusable.bucket_reshard_manual(src_bucket, config)
                        reusable.bucket_reshard_manual(dest_bucket, config)
                    if config.sharding_type == "dynamic":
                        reusable.bucket_reshard_dynamic(src_bucket, config)
                        reusable.bucket_reshard_dynamic(dest_bucket, config)

                # download objects
                if config.test_ops.get("download_object", False):
                    for name, path in objects_created_list:
                        reusable.download_object(
                            name,
                            src_bucket,
                            TEST_DATA_PATH,
                            path,
                            config,
                        )

                # delete objects
                if config.test_ops.get("delete_bucket_object", False):
                    if config.test_ops.get("enable_version", False):
                        for name, path in objects_created_list:
                            reusable.delete_version_object(
                                src_bucket, name, path, rgw_conn, each_user
                            )
                    else:
                        reusable.delete_objects(src_bucket)

                bkt_logging.verify_log_records(
                    rgw_s3_client,
                    each_user["user_id"],
                    src_bucket_name,
                    dest_bucket_name,
                    config,
                )

                # delete src-bucket and verify if associated logging conf on the dest-bucket is also deleted
                if config.test_ops.get("delete_bucket_object", False):
                    reusable.delete_bucket(src_bucket)

                    log.info(
                        f"test radosgw-admin bucket logging info on target bucket is empty after source bucket deletion"
                    )
                    out = bkt_logging.rgw_admin_logging_info(dest_bucket_name)
                    if out:
                        raise Exception(
                            "radosgw-admin bucket logging info on target bucket is not empty after source bucket deletion"
                        )

                    reusable.delete_objects(dest_bucket)
                    reusable.delete_bucket(dest_bucket)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    if config.user_remove:
        for i in all_users_info:
            if config.user_type == "non-tenanted":
                reusable.remove_user(i)
            else:
                reusable.remove_user(i, tenant=i["tenant"])


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket logging")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
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
        ceph_conf = CephConfOp(ssh_con)
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
