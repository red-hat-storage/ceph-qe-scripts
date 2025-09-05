"""
test_data_omap_offload - Test data omap offload
Usage: test_data_omap_offload.py -c <input_yaml>
<input_yaml>
    Note: any one of these yamls can be used
        test_data_omap_offload.yaml
        test_data_omap_offload_change_datatype_to_omap.yaml
        test_data_omap_offload_change_datatype_to_fifo.yaml
        test_data_omap_offload_multipart.yaml
        test_data_omap_offload_versioned_bucket.yaml
Operation:
    with default datalog_backing verify
        change the default datalog_backing and verify [applicable to nautilus]
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
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
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # check the default data log backing
    default_data_log = reusable.get_default_datalog_type()
    log.info(f"{default_data_log} is the default data log backing")

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        objects_created_list = []

        # change the default datalog backing to FIFO
        if config.test_ops.get("change_datalog_backing", False):
            logtype = config.test_ops["change_datalog_backing"]
            log.info(f"change default datalog backing to {logtype}")
            cmd = f"radosgw-admin datalog type --log-type={logtype}"
            change_datalog_type = utils.exec_shell_cmd(cmd)
            if change_datalog_type is False:
                raise TestExecError("Failed to change the datalog type to fifo")
            log.info(
                "restart the rgw daemons and sleep of 30secs for rgw daemon to be up "
            )
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")

        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info("creating bucket with name: %s" % bucket_name_to_create)
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user, ip_and_port
                )
                if config.test_ops.get("enable_version", False):
                    log.info("enable bucket version")
                    reusable.enable_versioning(
                        bucket, rgw_conn, each_user, write_bucket_io_info
                    )
                if config.test_ops["create_object"] is True:
                    # uploading data
                    log.info(
                        "top level s3 objects to create: %s" % config.objects_count
                    )
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
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
                                each_user,
                            )
                        else:
                            log.info("upload type: normal")
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                            )
                        objects_created_list.append((s3_object_name, s3_object_path))
                        # deleting the local file created after upload
                        if config.local_file_delete is True:
                            log.info("deleting local file created after the upload")
                            utils.exec_shell_cmd("rm -rf %s" % s3_object_path)

        # delete  object and bucket
        if config.test_ops.get("delete_bucket_object", False):
            if config.test_ops.get("enable_version", False):
                for name, path in objects_created_list:
                    reusable.delete_version_object(
                        bucket, name, path, rgw_conn, each_user
                    )
            else:
                reusable.delete_objects(bucket)
                time.sleep(30)
                reusable.delete_bucket(bucket)

    # check for any ERRORs in datalog list. ref- https://bugzilla.redhat.com/show_bug.cgi?id=1917687
    error_in_data_log_list = reusable.check_datalog_list()
    if error_in_data_log_list:
        raise TestExecError("Error in datalog list")

    # check for data log markers. ref: https://bugzilla.redhat.com/show_bug.cgi?id=1831798#c22
    data_log_marker = reusable.check_datalog_marker()
    log.info(f"The data_log_marker is: {data_log_marker}")

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()


if __name__ == "__main__":

    test_info = AddTestInfo("Test data omap offload")
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
