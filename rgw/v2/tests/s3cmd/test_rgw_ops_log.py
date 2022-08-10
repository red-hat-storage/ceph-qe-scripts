"""
Test_rgw_ops_log are sent to a file. The test will be performed by doing 
some rgw ops via s3cmd. For example, list_buckets, create buckets, put objects etc.

Usage: test_rgw_ops_log.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_rgw_ops_log.yaml

Operation:
    1. Enable ops logging [set rgw_enable_ops_log true, rgw_log_http_headers and rgw_ops_log_socket_path ]
    2. Make sure that they're set
    3. Params rgw_log_http_headers and rgw_ops_log_socket_path require a rgw service restart to reflect.
    4. Install nmap-ncat on the host node
    5. Create a user
    6. Create a bucket with user credentials
    7. Upload a file to the bucket
    8. We should observe the above operations logged in a file
 
"""


import argparse
import json
import logging
import os
import subprocess
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


def test_exec(config):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)[0]
    user_name = user_info["user_id"]
    rgw_service = RGWService()

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port()
    s3_auth.do_auth(user_info, ip_and_port)

    if config.rgw_ops_log:
        log.info("Testing rgw ops log are saved in a file")
        ceph_version_id, _ = utils.get_ceph_version()
        if float(ceph_version_id[1]) >= 6 and float(ceph_version_id[5]) >= 8:
            cmd = " ceph orch ps | grep rgw"
            out = utils.exec_shell_cmd(cmd)
            rgw_process_name = out.split()[0]
            utils.exec_shell_cmd(
                f"ceph config set client.{rgw_process_name} rgw_enable_ops_log true"
            )
            utils.exec_shell_cmd(
                f"ceph config set client.{rgw_process_name} rgw_log_http_headers http_x_forwarded_for,http_expect,http_content_md5"
            )
            utils.exec_shell_cmd(
                f"ceph config set client.{rgw_process_name} rgw_ops_log_socket_path /var/run/ceph/opslog"
            )
            srv_restarted = rgw_service.restart()

            # opslog path
            log.info(f"The opslog file created is /var/run/ceph/*/opslog ")

            # s3:operation - list all buckets
            log.info("list all buckets operation")
            utils.exec_shell_cmd("s3cmd ls")
            opslog_out = subprocess.getoutput(
                "timeout 1 nc -U --recv-only /var/run/ceph/*/opslog"
            )
            print(f"print opslog for list_buckets {opslog_out}")
            # Currently opslog is an incomplete dictionary

            # s3:operation - create bucket operation
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)
            s3cmd_reusable.create_bucket(bucket_name)
            log.info(f"Bucket {bucket_name} created")
            log.info("Check the operation 'create_bucket'")
            opslog_out = subprocess.getoutput(
                "timeout 1 nc -U --recv-only /var/run/ceph/*/opslog"
            )
            print(f"print opslog for bucket create {opslog_out}")

            # s3:op - put object in a bucket
            log.info("Upload a file")
            uploaded_file_info = s3cmd_reusable.upload_file(
                bucket_name, file_size=2056, test_data_path=TEST_DATA_PATH
            )
            uploaded_file = uploaded_file_info["name"]
            log.info(f"Uploaded file {uploaded_file} to bucket {bucket_name}")
            opslog_out = subprocess.getoutput(
                "timeout 1 nc -U --recv-only /var/run/ceph/*/opslog"
            )
            print(f"print opslog for put object {opslog_out}")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test rgw opslog")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="test rgw opslog via s3cmd")
        parser.add_argument("-c", dest="config", help="test rgw opslog via s3cmd")
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
        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.info(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
