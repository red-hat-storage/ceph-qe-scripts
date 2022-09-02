"""
Test bucket lifecycle for multipart object expiration: CEPH-83574797
Usage: test_bucket_lc_object_exp_multipart.py -c configs/<input-yaml>
where : <input-yaml> are test_bucket_lc_object_exp_multipart.yaml
Operation:
-Update rgw daemon with conf(rgw_lc_debug_interval = 1, rgw_lifecycle_work_time = 00:00-23:59)
-Restart the daemon
-Create a user and a bucket and setlifecycle to it and verify
-Upload 1K objects using multipart of size more than 15m (object uploaded are 16m)
-Wait Once all objects uploaded and lc reaches completed state
-Check bucket stats for num_objects and check for entries created in data pool for that objects which should be 0
-If data pool contains object but bucket stats doesn't, then try downloading ...
-Remove the user at successful completion
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
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize, KeyIoInfo
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_key_io_info = KeyIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    log.info("making changes to ceph.conf")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_lc_debug_interval,
        str(config.rgw_lc_debug_interval),
        ssh_con,
    )
    ceph_conf.set_to_ceph_conf(
        "global", ConfigOpts.rgw_lifecycle_work_time, "00:00-23:59"
    )
    log.info("trying to restart services")
    srv_restarted = rgw_service.restart(ssh_con)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    rgw_service.status(ssh_con)
    # create user
    user_info = s3lib.create_users(config.user_count)
    for each_user in user_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        if config.test_ops["create_bucket"]:
            log.info("no of buckets to create: %s" % config.bucket_count)
            # create bucket
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=1
                )
                bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
                life_cycle_rule = {"Rules": config.lifecycle_conf}
                reusable.put_bucket_lifecycle(
                    bucket, rgw_conn, rgw_conn2, life_cycle_rule
                )
                if config.test_ops["create_object"]:
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        log.info(f"s3 objects to create of size {config.obj_size}")
                        s3_object_name = config.lifecycle_conf[0]["Filter"][
                            "Prefix"
                        ] + str(oc)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info(
                            f"s3 object path: {s3_object_path}, name: {s3_object_name}"
                        )
                        reusable.upload_mutipart_object(
                            s3_object_name, bucket, TEST_DATA_PATH, config, each_user
                        )
                time.sleep(config.rgw_lc_debug_interval)

                for _ in range(1, 10):
                    time.sleep(60)
                    bucket_details = json.loads(
                        utils.exec_shell_cmd(
                            f"radosgw-admin bucket stats --bucket={bucket.name}"
                        )
                    )
                    if bucket_details["usage"]["rgw.main"]["num_objects"] == 0:
                        break
                else:
                    raise TestExecError(
                        "Bucket object expiration taking longer than expected"
                    )

                gc_list_output = json.loads(
                    utils.exec_shell_cmd("radosgw-admin gc list --include-all")
                )
                if gc_list_output:
                    log.info("Removing shadow objects found")
                    utils.exec_shell_cmd("radosgw-admin gc process --include-all")

                bucket_id = (
                    bucket_details["id"]
                    + "_"
                    + config.lifecycle_conf[0]["Filter"]["Prefix"]
                )
                log.info(
                    f"check for all the entry {bucket_id} for the bucket in data pool"
                )
                obj_pool = utils.exec_shell_cmd(
                    f"rados ls -p default.rgw.buckets.data | grep {bucket_id}"
                )
                if obj_pool:
                    for obj in obj_pool:
                        object_name = obj.split("_")[-1]
                        log.info(f"s3 object name to download: {object_name}")
                        object_name_downloaded = object_name + "." + "download"
                        object_download_path = os.path.join(
                            TEST_DATA_PATH, object_name_downloaded
                        )
                        object_downloaded_status = s3lib.resource_op(
                            {
                                "obj": bucket,
                                "resource": "download_file",
                                "args": [object_name, object_download_path],
                            }
                        )
                        if object_downloaded_status is False:
                            log.info("As expected object is not Downloadable")
                        if object_downloaded_status is None:
                            raise TestExecError(
                                "Objects are not listed but can be downloadable"
                            )

                if config.local_file_delete:
                    log.info("deleting local file created after the upload")
                    utils.exec_shell_cmd(f"rm -rf {TEST_DATA_PATH}")

                write_key_io_info.set_keys_deleted_in_bucket_with_prefix(
                    each_user["access_key"],
                    bucket.name,
                    [config.lifecycle_conf[0]["Filter"]["Prefix"]],
                )
                reusable.delete_bucket(bucket)
        reusable.remove_user(each_user)

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("bucket life cycle: test object expiration")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW multipart object expiration through lc"
        )
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
