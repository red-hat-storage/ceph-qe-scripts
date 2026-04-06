"""
test_list_delete_ratelimit_multiuser - Test LIST and DELETE rate limits for multiple users using s3cmd

Usage: test_list_delete_ratelimit_multiuser.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_list_delete_ratelimit_multiuser.yaml - Tests user-level LIST/DELETE rate limits for 5 users

Operation:
    Create 5 users
    Add ratelimit caps to each user
    For each user:
        Create a bucket with user credentials
        Enable max-list-ops and max-delete-ops rate limits on user scope
        Create objects in the bucket after applying ratelimit
        Attempt to list objects using s3cmd ls for (max_list_ops + 1) times;
        the (max_list_ops+1)th call exceeds the limit and returns 503
        Attempt to delete objects for (max_delete_ops + 1) times;
        the (max_delete_ops+1)th call exceeds the limit and returns 503
    Verify all 5 users hit 503 rate limit errors
"""

import argparse
import json
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from time import sleep

from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None

S3CMD_PATH = "/home/cephuser/venv/bin/s3cmd"


def create_objects_after_ratelimit(bucket_name, object_count):
    """
    Create objects in the bucket after rate limit is applied, before asserting
    for 503. Ensures the bucket has content so LIST/DELETE rate limit tests
    run against real objects.
    """
    s3cmd_reusable.create_local_file("1k", "ratelimit_test_file")
    for i in range(1, object_count + 1):
        cmd = (
            f"{S3CMD_PATH} put ratelimit_test_file " f"s3://{bucket_name}/delete_obj{i}"
        )
        utils.exec_shell_cmd(cmd)
    log.info(f"Created {object_count} objects in bucket {bucket_name} after ratelimit")


def attempt_list_ops_and_assert_503(bucket_name, max_list_ops):
    """
    max_list_ops is the maximum number of LIST operations allowed on the bucket
    per interval. Attempt to list objects using s3cmd ls (max_list_ops + 1)
    times; the first max_list_ops calls are within limit, the (max_list_ops+1)th
    exceeds the limit and must return 503.
    """
    bucket_for_s3cmd = bucket_name.split("/")[1] if "/" in bucket_name else bucket_name
    range_val = f"1..{max_list_ops + 1}"
    cmd = (
        f"for i in {{{range_val}}}; do {S3CMD_PATH} ls "
        f"s3://{bucket_for_s3cmd}/; done;"
    )
    stdout, stderr = s3cmd_reusable.run_subprocess(cmd)
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Create all users
    all_users_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    log.info(f"Created {config.user_count} users for multiuser ratelimit test")

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)

    max_list_ops = config.user_max_list_ops
    max_delete_ops = config.user_max_delete_ops

    for idx, user_info in enumerate(all_users_info):
        user_name = user_info["user_id"]
        log.info(
            f"--- User {idx + 1}/{config.user_count} ({user_name}): "
            f"Starting ratelimit test ---"
        )

        # Add ratelimit capability to user
        caps_add = utils.exec_shell_cmd(
            f"radosgw-admin caps add --uid {user_name} "
            + "--caps='users=*;buckets=*;ratelimit=*'"
        )
        data = json.loads(caps_add)
        caps = data["caps"]
        log.info(f"User Caps are: {caps}")

        # Authenticate s3cmd for this user
        s3_auth.do_auth(user_info, ip_and_port)

        # Create bucket for this user
        bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)
        bucket_name = bucket_name.replace("'", "")

        if config.version_enable:
            s3cmd_reusable.create_versioned_bucket(user_info, bucket_name, ip_and_port)
        else:
            s3cmd_reusable.create_bucket(bucket_name, ip_and_port)

        log.info(f"Bucket {bucket_name} created for user {user_name}")

        # Set user-level rate limits
        utils.exec_shell_cmd(
            f'radosgw-admin ratelimit set --ratelimit-scope=user --uid="{user_name}" '
            f"--max-list-ops={max_list_ops} --max-delete-ops={max_delete_ops}"
        )
        log.info(f"Rate limits set on user {user_name}")

        # Enable user-level rate limits
        utils.exec_shell_cmd(
            f'radosgw-admin ratelimit enable --ratelimit-scope=user --uid="{user_name}"'
        )

        # Verify rate limits
        limget = utils.exec_shell_cmd(
            f'radosgw-admin ratelimit get --ratelimit-scope=user --uid="{user_name}"'
        )
        log.info(f"Rate limits enabled on user {user_name}: {limget}")

        # Create objects after applying ratelimit, before asserting 503
        obj_count = max_list_ops + max_delete_ops + 2
        create_objects_after_ratelimit(bucket_name, obj_count)

        # Test LIST operations rate limit
        log.info(
            "Attempting to list objects using s3cmd ls for max_list_ops+1 times "
            "(max_list_ops=%s is the limit) for user %s",
            max_list_ops,
            user_name,
        )
        attempt_list_ops_and_assert_503(bucket_name, max_list_ops)
        log.info(f"User {user_name}: LIST rate limit 503 verified")

        log.info("Sleeping for 61 seconds to reset limits")
        sleep(61)

        # Test DELETE operations rate limit
        log.info(f"Testing DELETE operations rate limit for user {user_name}")
        s3cmd_reusable.rate_limit_delete(bucket_name, max_delete_ops)
        log.info(f"User {user_name}: DELETE rate limit 503 verified")

        log.info("Sleeping for 61 seconds to reset limits")
        sleep(61)

        log.info(
            f"--- User {idx + 1}/{config.user_count} ({user_name}): "
            f"LIST and DELETE rate limit verified ---"
        )

    log.info(f"All {config.user_count} users passed LIST and DELETE rate limit tests")


if __name__ == "__main__":
    test_info = AddTestInfo("test LIST and DELETE rate limits for multiple users")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW S3 LIST and DELETE rate limits for multiple users"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW S3 LIST and DELETE rate limits multiuser"
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
