import os
import logging
import socket
import argparse
from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import TestExecError
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()


def test_s3cmd_get_on_tertiary_cluster(config, ssh_con):
    """
    Test s3cmd GET operation on the tertiary cluster.
    Args:
        config (object): Test configuration
        ssh_con (object): SSH connection object
    """
    log.info("Testing s3cmd GET operation on the tertiary cluster")
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

    # Create user and bucket on the tertiary cluster
    user_info = resource_op.create_users(no_of_users_to_create=1)
    s3_auth.do_auth(user_info[0], ip_and_port)
    auth = Auth(user_info[0], ssh_con, ssl=config.ssl, haproxy=config.haproxy)
    rgw_conn = auth.do_auth()

    bucket_name = utils.gen_bucket_name_from_userid(user_info[0]["user_id"], rand_no=0)
    s3cmd_reusable.create_bucket(bucket_name)
    log.info(f"Bucket {bucket_name} created on the tertiary cluster")

    # Upload a file to the bucket
    uploaded_file_info = s3cmd_reusable.upload_file(bucket_name, "test_object", test_data_path=TEST_DATA_PATH)
    log.info(f"Uploaded file {uploaded_file_info['name']} to bucket {bucket_name}")

    # Perform s3cmd GET operation to fetch and download the object
    s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
    local_file_path = f"/tmp/{uploaded_file_info['name']}"
    cmd = f"{s3cmd_path} get s3://{bucket_name}/{uploaded_file_info['name']} {local_file_path}"
    rc = utils.exec_shell_cmd(cmd)
    if rc is False:
        raise AssertionError(f"Failed to download object {uploaded_file_info['name']} from bucket {bucket_name}")

    log.info(f"Successfully downloaded object {uploaded_file_info['name']} from bucket {bucket_name}")

    # Verify that the object was downloaded correctly
    if not os.path.exists(local_file_path):
        raise AssertionError(f"Downloaded file {local_file_path} does not exist")

    log.info(f"Verified that the object {uploaded_file_info['name']} was downloaded successfully")

    # Clean up
    s3cmd_reusable.delete_file(bucket_name, uploaded_file_info["name"])
    s3cmd_reusable.delete_bucket(bucket_name)
    log.info(f"Deleted file and bucket {bucket_name} from the tertiary cluster")

    # Check for crashes
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("s3cmd GET test on tertiary cluster")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW s3cmd GET test on tertiary cluster")
        parser.add_argument("-c", dest="config", help="Test configuration YAML file")
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
        test_s3cmd_get_on_tertiary_cluster(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (TestExecError, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
