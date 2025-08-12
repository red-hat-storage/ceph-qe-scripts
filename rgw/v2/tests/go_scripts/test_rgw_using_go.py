"""
Usage: test_rgw_using_go.py -c <input_yaml>
polarion: CEPH-83591699
<input_yaml>
    Note: Following yaml can be used
    rgw/v2/tests/go_scripts/configs/test_checksum_using_go.yaml
Operation:
the workflow is to test all permutations of:

1. with supported 5 checksum algorithms: sha1, sha256, crc32, crc32c, crc64nvme
2. with small and medium sized objects
3. with upload types - normal, chunked and multipart
4. with operations - copy, download, get-object-attributes, delete
"""


import argparse
import json
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.go import auth as go_auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con, config_yaml_path):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    go_auth.install_go()
    if config.test_ops.get("use_ssl"):
        config.ssl = True
    endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
    all_users_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    # create local objects
    utils.exec_shell_cmd("fallocate -l 9KB /home/cephuser/obj9KB")
    utils.exec_shell_cmd("fallocate -l 10MB /home/cephuser/obj10MB")
    utils.exec_shell_cmd("mkdir -p /home/cephuser/obj10MB.parts/")
    utils.exec_shell_cmd(
        "split -b 5m /home/cephuser/obj10MB /home/cephuser/obj10MB.parts/"
    )

    # go module initialization and add missing dependencies
    utils.exec_shell_cmd(
        "cd /home/cephuser/rgw-tests/ceph-qe-scripts/rgw/v2/tests/go_scripts/aws_sdk_go_v2 ; go mod init rgw-tests/ceph-qe-scripts/rgw/v2/tests/go_scripts/aws_sdk_go_v2"
    )
    utils.exec_shell_cmd(
        "cd /home/cephuser/rgw-tests/ceph-qe-scripts/rgw/v2/tests/go_scripts/aws_sdk_go_v2/ ; go mod tidy"
    )

    for each_user in all_users_info:
        out = utils.exec_long_running_shell_cmd(
            f"cd /home/cephuser/rgw-tests/ceph-qe-scripts/rgw/v2/tests/go_scripts/aws_sdk_go_v2/ ; sudo go run test_checksum.go -username {each_user['user_id']} -access {each_user['access_key']} -secret {each_user['secret_key']} -endpoint '{endpoint}'"
        )
        if out is False:
            raise Exception("go script failed")

        if config.user_remove:
            s3_reusable.remove_user(each_user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test rgw with go scripts")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="Test rgw with go scripts")
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
        config = resource_op.Config(yaml_file)
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con, yaml_file)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
