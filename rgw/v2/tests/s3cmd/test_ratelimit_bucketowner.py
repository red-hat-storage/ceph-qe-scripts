"""
test_ratelimit_bucketowner - Test bucket changes owner with ratelimit configured using s3cmd

Usage: test_ratelimit_bucketowner.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_ratelimit_bucketowner.yaml

Polarion Tests:
CEPH-83574920

Operation:
    Create an user
    Create a bucket with user credentials
    Enable the limits max-read-ops, max-read-bytes, max-write-ops, max-write-bytes on a Bucket scope
    Verify the rate limits using s3cmd
    Change the bucket owner to user2
    Bucket limits should not change
"""

import argparse
import json
import logging
import math
import os
import subprocess
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from time import sleep

from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, S3CommandExecError, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3cmd import reusable as s3cmd_reusable
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
    # Create user and required number of buckets
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    uname1 = user_info[0]["user_id"]
    uname2 = user_info[1]["user_id"]

    for i in uname1, uname2:
        caps_add = utils.exec_shell_cmd(
            f"radosgw-admin caps add --uid {i} "
            + "--caps='users=*;buckets=*;ratelimit=*'"
        )
        data = json.loads(caps_add)
        caps = data["caps"]
        log.info(f" User Caps are :{caps}")

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    s3_auth.do_auth(user_info[0], ip_and_port)

    max_read_bytes = config.bucket_max_read_bytes
    max_read_ops = config.bucket_max_read_ops
    max_write_bytes = config.bucket_max_write_bytes
    max_write_ops = config.bucket_max_write_ops

    max_read_bytes_kb = math.ceil(float(max_read_bytes) / 1024)
    max_write_bytes_kb = math.ceil(float(max_write_bytes) / 1024)
    bucket_name = utils.gen_bucket_name_from_userid(user_info[0]["user_id"], rand_no=0)
    ssl = config.ssl
    s3cmd_reusable.create_bucket(bucket_name, ip_and_port, ssl)

    log.info(f"Bucket {bucket_name} created")
    limset = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit set --ratelimit-scope=bucket "
        + f"--bucket={bucket_name} --max-read-ops={max_read_ops} "
        + f"--max-read-bytes={max_read_bytes} --max-write-bytes={max_write_bytes} "
        + f"--max-write-ops={max_write_ops}"
    )
    log.info(f"Rate limits set on bucket {bucket_name}")
    limenable = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit enable --ratelimit-scope=bucket "
        + f"--bucket={bucket_name}"
    )
    limget = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit get --ratelimit-scope=bucket "
        + f"--bucket={bucket_name}"
    )
    log.info(f"Rate limits enabled on bucket : {limget} ")
    # Test the ratelimits on the bucket under user1
    log.info(f"Test the read ops limits")
    s3cmd_reusable.rate_limit_read(bucket_name, max_read_ops, ssl)
    sleep(61)

    log.info(f"Set rate limits on user {uname1}")
    # Set the rate limits for the user and enable them
    max_read_bytes = config.user_max_read_bytes
    max_read_ops = config.user_max_read_ops
    max_write_bytes = config.user_max_write_bytes
    max_write_ops = config.user_max_write_ops

    limset = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit set --ratelimit-scope=user --uid={uname1}"
        + f" --max-read-ops={max_read_ops} --max-read-bytes={max_read_bytes}"
        + f" --max-write-bytes={max_write_bytes} --max-write-ops={max_write_ops}"
    )
    log.info(f"Rate limits set on user {uname1}")
    limenable = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit enable --ratelimit-scope=user --uid={uname1}"
    )
    limget = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit get --ratelimit-scope=user --uid={uname1}"
    )
    log.info(f"Rate limits enabled on bucket : {limget} ")

    # Change bucket owner to user2
    s3_auth.do_auth(user_info[1], ip_and_port)
    rc = utils.exec_shell_cmd(
        f"radosgw-admin bucket unlink --bucket {bucket_name} --uid {uname1}"
    )
    log.info(f"Bucket unlinked from user {uname1}")

    rc = utils.exec_shell_cmd(
        f"radosgw-admin bucket link --bucket {bucket_name} --uid {uname2}"
    )
    log.info(f"Bucket linked to user {uname2}")
    rc = utils.exec_shell_cmd(
        f"radosgw-admin bucket chown --bucket {bucket_name} --uid {uname2}"
    )

    s3_auth.do_auth(user_info[1], ip_and_port)
    # Test the bucket ratelimit is still valid
    log.info(f"Test the read ops limits")
    s3cmd_reusable.rate_limit_read(bucket_name, max_read_ops, ssl)

    log.info("Rate limit still active post bucket link and unlink")


if __name__ == "__main__":
    test_info = AddTestInfo("Test ratelimit on bucket owner change")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Test ratelimit on bucket owner change"
        )
        parser.add_argument(
            "-c", dest="config", help="Test ratelimit on bucket owner change"
        )
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
