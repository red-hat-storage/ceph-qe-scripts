"""
test_s3cmd - Test s3cmd operation on cluster

Usage: test_s3cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload a file to bucket
    Delete uploaded object
    Delete bucket
"""


import argparse
import logging
import os
import socket
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()


def test_exec(config):
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
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)

    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    port = utils.get_radosgw_port_no()

    ip_and_port = f"{ip}:{port}"
    s3_auth.do_auth(tenant_user_info, ip_and_port)

    bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)

    # Create a bucket
    s3cmd_reusable.create_bucket(bucket_name)
    log.info(f"Bucket {bucket_name} created")

    # Upload file to bucket
    uploaded_file_info = s3cmd_reusable.upload_file(
        bucket_name, test_data_path=TEST_DATA_PATH
    )
    uploaded_file = uploaded_file_info["name"]
    log.info(f"Uploaded file {uploaded_file} to bucket {bucket_name}")

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
        parser = argparse.ArgumentParser(description="RGW Swift Automation")
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
        config = resource_op.Config(yaml_file)
        config.read()
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
