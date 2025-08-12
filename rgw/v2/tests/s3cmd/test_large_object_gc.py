"""
test_s3cmd - Test large object download with gc using s3cmd

Usage: test_large_object_gc.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_large_object_gc.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload large file to bucket
    Set rgw_gc_obj_min_wait as 5
    Download uploaded object
    Verify download is succeeded
    Delete uploaded object
    Delete bucket
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    rgw_service = RGWService()
    # preparing data
    user_name = resource_op.create_users(no_of_users_to_create=1)[0]["user_id"]
    tenant = "tenant"
    tenant_user_info = umgmt.create_tenant_user(
        tenant_name=tenant, user_id=user_name, displayname=user_name
    )
    umgmt.create_subuser(tenant_name=tenant, user_id=user_name)

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    s3_auth.do_auth(tenant_user_info, ip_and_port)

    bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)

    # Create a bucket
    s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
    log.info(f"Bucket {bucket_name} created")

    # Upload a 2GB file to bucket
    uploaded_file_info = s3cmd_reusable.upload_file(
        bucket_name, file_size=2147483648, test_data_path=TEST_DATA_PATH
    )
    uploaded_file = uploaded_file_info["name"]
    uploaded_file_md5 = uploaded_file_info["md5"]
    log.info(f"Uploaded file {uploaded_file} to bucket {bucket_name}")

    if config.gc_verification is True:
        log.info("making changes to ceph.conf")
        config.rgw_gc_obj_min_wait = 5
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_gc_obj_min_wait,
            str(config.rgw_gc_obj_min_wait),
        )
        log.info("trying to restart services")
        srv_restarted = rgw_service.restart()
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")
        log.info("download large object again to make gc list with shadow entries")

        downloaded_file1 = s3cmd_reusable.download_file(
            bucket_name,
            uploaded_file,
            local_file_name="download1.img",
            test_data_path=TEST_DATA_PATH,
        )
        time.sleep(5)
        downloaded_file1_md5 = utils.get_md5(downloaded_file1)
        assert uploaded_file_md5 == downloaded_file1_md5
        gc_list_output = json.loads(
            utils.exec_shell_cmd("radosgw-admin gc list --include-all")
        )

        log.info(gc_list_output)

        if gc_list_output:
            log.info("Shadow obj found after setting rgw_gc_obj_min_wait to 5 sec")
            utils.exec_shell_cmd("radosgw-admin gc process --include-all")
            log.info("Object download should not error out in 404 NoSuchKey error")
            downloaded_file2 = s3cmd_reusable.download_file(
                bucket_name,
                uploaded_file,
                local_file_name="download2.img",
                test_data_path=TEST_DATA_PATH,
            )
            downloaded_file2_md5 = utils.get_md5(downloaded_file2)
            assert uploaded_file_md5 == downloaded_file2_md5

    # Delete file from bucket
    s3cmd_reusable.delete_file(bucket_name, uploaded_file)
    log.info(f"Deleted file {uploaded_file} from bucket {bucket_name}")

    # Delete bucket
    s3cmd_reusable.delete_bucket(bucket_name)
    log.info(f"Bucket {bucket_name} deleted")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test swift user key gen")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW S3 Large Object download using s3cmd"
        )
        parser.add_argument("-c", dest="config", help="RGW S3 Large Object using s3cmd")
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
        config = resource_op.Config(yaml_file)
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
