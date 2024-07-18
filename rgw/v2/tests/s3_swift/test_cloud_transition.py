"""
Test for cloud transition workflow
test_cloud_transitions.py - Test for cloud transition workflow

Usage: test_cloud_transitions.py -c <input_yaml>

<input_yaml>:
    configs/test_cloud_transitions.yaml
    configs/test_cloud_transition_encrypted.yaml
    configs/test_cloud_transition_headobject_false.yaml
    configs/test_cloud_transition_headobject_true.yaml
    configs/test_cloud_transition_multipart.yaml
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
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import lc_policy
from v2.tests.s3_swift.reusables import server_side_encryption_s3 as sse_s3
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    user_info = s3lib.create_users(config.user_count)[0]
    # authenticate
    auth = Auth(user_info, ssh_con, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    s3_client1 = auth.do_auth_using_client()

    log.info("Create buckets and objects in source cluster")
    if config.test_ops["create_bucket"] is True:
        log.info("no of buckets to create: %s" % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=bc
            )
            log.info(f"creating bucket with name: {bucket_name_to_create}")
            bucket = reusable.create_bucket(bucket_name_to_create, rgw_conn, user_info)

            if config.test_ops["enable_encryption"]:
                # enable per bucket encryption on the bucket
                log.info(
                    f"Encryption type is per-bucket, enable it on bucket : {bucket_name_to_create}"
                )
                encryption_method = config.encryption_keys
                sse_s3.put_bucket_encryption(
                    s3_client1, bucket_name_to_create, encryption_method
                )
                # get bucket encryption
                log.info(f"get bucket encryption for bucket : {bucket_name_to_create}")
                sse_s3.get_bucket_encryption(s3_client1, bucket_name_to_create)

            if config.test_ops["create_object"] is True:
                # uploading data
                log.info(f"s3 objects to create: {config.objects_count}")
                config.mapped_sizes = utils.make_mapped_sizes(config)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                    log.info("s3 object name: %s" % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info("s3 object path: %s" % s3_object_path)
                    if config.test_ops.get("upload_type") == "multipart":
                        log.info("upload type: multipart")
                        reusable.upload_mutipart_object(
                            s3_object_name, bucket, TEST_DATA_PATH, config, user_info
                        )
                    else:
                        log.info("upload type: normal")
                        reusable.upload_object(
                            s3_object_name, bucket, TEST_DATA_PATH, config, user_info
                        )
    s3_client_local = reusable.get_s3_client(
        user_info["access_key"], user_info["secret_key"], auth.endpoint_url
    )
    # If Etag verification is enabled get local bucket Etag
    if config.etag_verification is True:
        local_dict = reusable.get_object_list_etag(
            bucket_name_to_create, s3_client_local
        )

    log.info("Create bucket in remote cluster if not exists")
    remote_creds = reusable.get_zg_endpoint_creds()
    s3_client_remote = reusable.get_s3_client(
        remote_creds["access_key"], remote_creds["secret_key"], remote_creds["endpoint"]
    )
    remote_bucket = remote_creds["bucket_name"]
    if not reusable.is_bucket_exists(remote_bucket, s3_client_remote):
        s3_client_remote.create_bucket(Bucket=remote_bucket)

    log.info("restart the rgw daemons")
    restart_service = rgw_service.restart(ssh_con)
    if restart_service is False:
        raise TestExecError("RGW service restart failed")
    log.info("sleep for 20 seconds after RGW service restart")
    time.sleep(20)

    log.info("Applying LC policy to source cluster bucket %s" % (bucket.name))
    bucket_life_cycle = s3lib.resource_op(
        {
            "obj": rgw_conn,
            "resource": "BucketLifecycleConfiguration",
            "args": [bucket.name],
        }
    )
    life_cycle = lc_policy.create_transition_lc_config(
        prefix="key", id=config.test_ops["lc_id"], days=2
    )
    put_bucket_life_cycle = s3lib.resource_op(
        {
            "obj": bucket_life_cycle,
            "resource": "put",
            "kwargs": dict(LifecycleConfiguration=life_cycle),
        }
    )
    log.info("put bucket life cycle:\n%s" % put_bucket_life_cycle)
    log.info("waiting for 180sec to complete transition...")
    time.sleep(180)

    log.info("Verifying objects are transitioned")
    object_list = reusable.get_object_list(
        remote_bucket, s3_client_remote, prefix=user_info["user_id"]
    )
    log.info("Object list: %s" % object_list)
    message = "Expected: %s, Actual: %s" % (config.objects_count, len(object_list))
    assert len(object_list) == config.objects_count, message

    # check retain_head_object behaviour
    object_list = reusable.get_object_list(bucket.name, s3_client_local)
    if config.test_ops["retain_head_object"] is True:
        if object_list:
            log.info("Head objects retained post transition as expected")
        else:
            raise TestExecError("Bucket is empty, head objects not retained")

    if config.test_ops["retain_head_object"] is False:
        if len(object_list) == 0:
            log.info("Head objects not retained post transition as expected")
        else:
            raise TestExecError("Bucket is not empty, head objects retained")

    if config.etag_verification is True:
        log.info("Verifying ETags before and after transition")
        cloud_dict = reusable.get_object_list_etag(remote_bucket, s3_client_remote)
        if not local_dict or not cloud_dict:
            raise TestExecError("ETags not obtained")
        for key in local_dict:
            local_etag = local_dict[key]
            remote_key = bucket_name_to_create + "/" + key
            cloud_etag = cloud_dict[remote_key]
            if local_etag != cloud_etag:
                raise AssertionError(f"mismatch found in the eTAG from aws and radosgw")

    # verify tier-type cannot be changed from cloud-s3 CEPH-83575280
    log.info("Try to modify the tier-type of the Cloud Storage Class")
    cmd = "radosgw-admin zonegroup placement modify --storage-class CLOUDTIER --tier-type new1 --placement-id default-placement"
    op = utils.exec_shell_cmd(cmd)
    op = json.loads(op)
    if op[0]["val"]["tier_targets"][0]["val"]["tier_type"] != "cloud-s3":
        raise TestExecError("Tier target has been modified")

    # check sync status if a multisite cluster
    reusable.check_sync_status()


if __name__ == "__main__":
    test_info = AddTestInfo("Test for cloud transition workflow")
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
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
