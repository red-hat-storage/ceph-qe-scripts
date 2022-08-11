"""
test_s3cmd - Test bucket stats consistency in number of objects using s3cmd

Usage: test_bucket_stats.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_bucket_stats.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Performs multipart upload with object name consist of whitespace
    checks for bucket stats consistency among number of objects
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
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

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

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port()
    s3_auth.do_auth(user_info, ip_and_port)

    if config.bucket_stats:
        bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)
        s3cmd_reusable.create_bucket(bucket_name)
        log.info(f"Bucket {bucket_name} created")
        utils.exec_shell_cmd(f"fallocate -l 25m obj25m")
        object_name = f"s3://{bucket_name}/encyclopedia/space & universe/.bkp/journal$i"
        range_val = f"1..{config.objects_count}"
        cmd = (
            "for i in {"
            + range_val
            + "}; do /home/cephuser/venv/bin/s3cmd put obj25m "
            + object_name
            + ";done;"
        )

        rc = utils.exec_shell_cmd(cmd)

        if rc:
            raise AssertionError("expected scenario is not achieved!!!")

        bucket_stats = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket {bucket_name}"
        )
        log.info(f" bucket stats are :{bucket_stats}")

        data = json.loads(bucket_stats)

        num_objects = data["usage"]["rgw.main"]["num_objects"]
        log.info(f"num objects :{num_objects}")

        object_count = utils.exec_shell_cmd(
            f"/home/cephuser/venv/bin/s3cmd ls s3://{bucket_name} --recursive | wc -l"
        )
        log.info(f"object_count :{object_count}")

        if int(num_objects) != int(object_count):
            raise AssertionError("Inconsistency found in number of objects")

        if "rgw.none" in data["usage"].keys():
            raise AssertionError("inconsistency issue observed")


if __name__ == "__main__":

    test_info = AddTestInfo("test bucket stats consistency")

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
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
