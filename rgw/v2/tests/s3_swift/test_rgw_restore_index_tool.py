"""
test_rgw_restore_index_tool - Test resharding operations on bucket

Usage: test_rgw_restore_index_tool.py -c <input_yaml>

<input_yaml>
    Note: any one of these yamls can be used
    test_rgw_restore_index_multipart_uploads.yaml(to be added in future.)
    test_rgw_restore_index_versioned_buckets.yaml

Operation:
    Create user and a bucket and enable bucket versioning
    Upload 200 objects to the bucket (with 2 versions of each object)
    Clear the bucket instance objects for that bucket via `rados clearomap ...`
    Run `rgw-restore-bucket-index ...` on the bucket.
    Verify bucket objects and metadata are restored.
"""

# test RGW-restore-index tool
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
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()

TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    log.info("starting IO")
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = Auth(user_info, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
    rgw_conn = auth.do_auth()
    objects_created_list = []
    bucket_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=1)
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info)
    if config.test_ops.get("enable_version", False):
        log.info("enable bucket version")
        reusable.enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info)
        # create objects
    if config.test_ops.get("create_object", False):
        # uploading data
        log.info(f"s3 objects to create: {config.objects_count}")
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
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
                    user_info,
                )
            else:
                if config.test_ops.get("enable_version", False):
                    reusable.upload_version_object(
                        config,
                        user_info,
                        rgw_conn,
                        s3_object_name,
                        config.obj_size,
                        bucket,
                        TEST_DATA_PATH,
                    )
                else:
                    log.info("upload type: normal")
                    reusable.upload_object(
                        s3_object_name,
                        bucket,
                        TEST_DATA_PATH,
                        config,
                        user_info,
                    )
            objects_created_list.append((s3_object_name, s3_object_path))
    if config.test_ops.get("verify_bucket_gen", False) is True:
        time.sleep(600)
        zone_name = config.local_zone
        bucket_gen = reusable.fetch_bucket_gen(bucket.name)
        log.info(f"Bucket generation value is {bucket_gen}")

        bkt_stat_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
        num_shard = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))["num_shards"]
        num_objects = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))["usage"][
            "rgw.main"
        ]["num_objects"]
        bucket_id = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))["id"]

        log.info(
            f"the shards and number of objects before rados clearomap are {num_shard} shards and {num_objects} objects"
        )
        for shard in range(num_shard):
            cmd_rados_clear_omap = f"rados clearomap -p {zone_name}.rgw.buckets.index  .dir.{bucket_id}.{bucket_gen}.{shard}"
            utils.exec_shell_cmd(cmd_rados_clear_omap)

        log.info(
            f"bucket stats after clearing the bucket instance objects: {utils.exec_shell_cmd(bkt_stat_cmd)}"
        )
        log.info(
            f"run the rgw-restore-bucket-index tool at custom location bug-2267715"
        )
        restore_index_cmd = (
            f"rgw-restore-bucket-index -b {bucket.name} -t /home/cephuser -y"
        )
        utils.exec_shell_cmd(restore_index_cmd)
        time.sleep(60)
        log.info(
            "the number of objects after the restore-index tool should be same as before."
        )

        restored_num_objects = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))["usage"][
            "rgw.main"
        ]["num_objects"]

        if restored_num_objects == num_objects:
            log.info("restore bucket index is successful!")
        else:
            raise AssertionError("restore bucket index is not successful!")
        reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW bucket index restore test")
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
