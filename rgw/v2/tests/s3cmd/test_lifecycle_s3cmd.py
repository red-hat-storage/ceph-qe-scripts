"""
test_s3cmd - Test s3cmd operations on cluster

Usage: test_lifecycle_s3cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd_lifecycle_archive_current_expiration.yaml
    test_s3cmd_lifecycle_archive_noncurrent_expiration.yaml
    test_s3cmd_lifecycle_archive_newer_noncurrent_expiration.yaml
    test_s3cmd_lifecycle_archive_object_size.yaml
    test_s3cmd_lifecycle_archive_transition.yaml

Operation:
    Create a user
    Create a bucket with user credentials
    Upload a files to bucket
    Apply LC rule to the bucket(from the primary site.)
    Test the LC rule at the archive site.
"""
import argparse
import logging
import os
import socket
import sys
import traceback
import xml.etree.ElementTree as xml

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3 import lifecycle_validation as lc_validate
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_bucket_io_info = BucketIoInfo()
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    if config.haproxy:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = 5000
        ip_and_port = f"{ip}:{port}"

    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    s3_auth.do_auth(user_info[0], ip_and_port)
    auth = Auth(user_info[0], ssh_con, ssl=config.ssl, haproxy=config.haproxy)
    rgw_conn = auth.do_auth()
    for bc in range(config.bucket_count):
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info[0]["user_id"], rand_no=bc
        )
        if config.version_enable:
            s3cmd_reusable.create_versioned_bucket(
                user_info[0], bucket_name, ip_and_port, ssl=None
            )
        else:
            s3cmd_reusable.create_bucket(bucket_name)
        log.info(f"Bucket {bucket_name} created")
        log.info(f"Now Upload the objects to the bucket {bucket_name}")
        s3cmd_reusable.upload_objects_via_s3cmd(bucket_name, config)
        log.info("Generate a LC rule xml file")
        s3cmd_reusable.Generate_LC_xml(
            "/home/cephuser/rgw-ms-tests/ceph-qe-scripts/rgw/lifecycle_rule.xml", config
        )
        s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
        log.info(f"Apply the LC rule via the xml file on bucket {bucket_name}")
        lc_s3cmd = f"{s3cmd_path} setlifecycle /home/cephuser/rgw-ms-tests/ceph-qe-scripts/rgw/lifecycle_rule.xml s3://{bucket_name}"
        utils.exec_shell_cmd(lc_s3cmd)
        lc_s3cmd = f"{s3cmd_path} getlifecycle s3://{bucket_name}"
        utils.exec_shell_cmd(lc_s3cmd)
        s3cmd_reusable.lc_validation_at_archive_zone(bucket_name, config)

    log.info("Remove downloaded objects from cluster")
    utils.exec_shell_cmd("rm -rf *-obj-*")  # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("rgw test bucket lifecycle using s3cmd")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW s3cmd Automation")
        parser.add_argument("-c", dest="config", help="RGW Test using s3cmd tool")
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
