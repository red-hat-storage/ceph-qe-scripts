"""
test_s3cmd_malformed_url - test whether rgw daemon crash occurs while using malformed url in s3cmd command

Usage: test_s3cmd_malformed_url.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd_malformed_url_cp.yaml
    test_s3cmd_malformed_url_del.yaml
    test_s3cmd_malformed_url_get.yaml
    test_s3cmd_malformed_url_ls.yaml
    test_s3cmd_malformed_url_multipart.yaml
    test_s3cmd_malformed_url_mv.yaml
    test_s3cmd_malformed_url_put.yaml
    test_s3cmd_malformed_url_sync.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    test s3cmd malformed url with different permutations of special characters
"""


import argparse
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.manage_data as manage_data
from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.lib.s3cmd.resource_op import S3CMD
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.tests.s3cmd.reusables.malformed_url import execute_command_with_permutations
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

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
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)[0]
    user_name = user_info["user_id"]

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    s3_auth.do_auth(user_info, ip_and_port)

    object_name = "hello_world.txt"
    data_info = manage_data.io_generator(object_name, 1)
    if data_info is False:
        TestExecError("data creation failed")

    for bc in range(config.bucket_count):
        bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
        s3cmd_reusable.create_bucket(bucket_name)
        log.info(f"Bucket {bucket_name} created")
        cmd = f"/home/cephuser/venv/bin/s3cmd put {object_name} s3://{bucket_name}"
        utils.exec_shell_cmd(cmd)

        operation = config.test_ops["operation"]
        options = config.test_ops.get("options")
        params = config.test_ops.get("params")
        s3cmd_class = S3CMD(operation=operation, options=options)
        cmd = s3cmd_class.command(params=params)
        cmd = cmd.replace("{bucket_name}", bucket_name)
        cmd = cmd.replace("{object_name}", object_name)
        execute_command_with_permutations(cmd, config)


if __name__ == "__main__":

    test_info = AddTestInfo("test s3cmd malformed url")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 bucket stats using s3cmd")
        parser.add_argument("-c", dest="config", help="RGW S3 bucket stats using s3cmd")
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
