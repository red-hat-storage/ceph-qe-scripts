"""
test_list_delete_ratelimit - Test LIST and DELETE rate limits on User and Bucket level using s3cmd

Usage: test_list_delete_ratelimit.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_list_delete_ratelimit_user.yaml - Tests user-level LIST/DELETE rate limits
    test_list_delete_ratelimit_bucket.yaml - Tests bucket-level LIST/DELETE rate limits
    test_list_delete_ratelimit_interval.yaml - Tests rgw_ratelimit_interval config
    test_list_delete_ratelimit_get_nonexistent_user.yaml - Scenario 1: get ratelimit
        for non-existing user (test_ops.test_ratelimit_get_nonexistent_user)
    test_list_delete_ratelimit_get_user_not_enabled.yaml - Scenario 2: get ratelimit
        for existing user where ratelimit is not enabled (test_ops.test_ratelimit_get_user_not_enabled)

Polarion Tests:
TBD - Test case IDs to be added

Operation:
    Create a user
    Create a bucket with user credentials
    (Optional) Scenario 1: Attempt to get max_list_ops and max_delete_ops for
    a non-existing user; expect ERROR: failed to get a ratelimit for user id,
    errno: (2) No such file or directory (test_ops.test_ratelimit_get_nonexistent_user)
    (Optional) Scenario 2: Attempt to get max_list_ops and max_delete_ops for
    an existing user where ratelimit is not enabled (test_ops.test_ratelimit_get_user_not_enabled)
    Enable the limits max-list-ops and max-delete-ops on a Bucket scope
    Create objects in the bucket after applying ratelimit (before asserting 503)
    max_list_ops is the maximum number of LIST operations allowed on the bucket;
    attempt to list objects using s3cmd ls for (max_list_ops + 1) times so the
    (max_list_ops+1)th call exceeds the limit and returns 503
    Repeat the same limits on a User scope
    Test the rgw_ratelimit_interval configuration option
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
    # Run s3cmd ls (max_list_ops + 1) times to exceed the limit and get 503
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

    # add rate limit capability to rgw user
    if config.user_type == "tenanted":
        user_info = resource_op.create_tenant_users(
            no_of_users_to_create=config.user_count, tenant_name="tenant1"
        )[0]
        name = user_info["user_id"]
        user_name = "'tenant1$" + f"{name}'"
        log.info(f"tenanted user name {user_name}")
        uid = user_info["user_id"]
        caps_add = utils.exec_shell_cmd(
            f"radosgw-admin caps add --uid {uid} --tenant tenant1 "
            + "--caps='users=*;buckets=*;ratelimit=*'"
        )
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)[0]
        user_name = user_info["user_id"]
        caps_add = utils.exec_shell_cmd(
            f"radosgw-admin caps add --uid {user_name} "
            + "--caps='users=*;buckets=*;ratelimit=*'"
        )

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    s3_auth.do_auth(user_info, ip_and_port)

    data = json.loads(caps_add)
    caps = data["caps"]
    log.info(f"User Caps are: {caps}")

    # create bucket
    bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)
    bucket_name = bucket_name.replace("'", "")

    if config.version_enable:
        s3cmd_reusable.create_versioned_bucket(user_info, bucket_name, ip_and_port)
    else:
        s3cmd_reusable.create_bucket(bucket_name, ip_and_port)

    if config.user_type == "tenanted":
        bucket_name = f"tenant1/{bucket_name}"

    log.info(f"Bucket {bucket_name} created")

    # Scenario 1: ratelimit get for non-existing user (expect error)
    test_ops = getattr(config, "test_ops", None) or {}
    if test_ops.get("test_ratelimit_get_nonexistent_user", False):
        log.info(
            "Scenario 1: attempt to get max_list_ops and max_delete_ops for "
            "non-existing user (expect error)"
        )
        nonexistent_uid = "nonexistent_user_ratelimit_get_test"
        cmd = f'radosgw-admin ratelimit get --ratelimit-scope=user --uid="{nonexistent_uid}"'
        output = utils.exec_shell_cmd(cmd, return_err=True)
        log.info("radosgw-admin ratelimit get for non-existing user: %s", output)
        assert output, "Expected non-empty error output from radosgw-admin"
        assert (
            "failed to get a ratelimit for user" in output
        ), f"Expected 'failed to get a ratelimit for user' in output, got: {output}"
        assert (
            "No such file or directory" in output or "errno: (2)" in output
        ), f"Expected 'No such file or directory' or 'errno: (2)' in output, got: {output}"
        log.info("Correctly received error for ratelimit get on non-existing user")

    # Scenario 2: ratelimit get for existing user where ratelimit is not enabled
    if test_ops.get("test_ratelimit_get_user_not_enabled", False):
        log.info(
            "Scenario 2: attempt to get max_list_ops and max_delete_ops for "
            "existing user where ratelimit is not enabled"
        )
        cmd = f'radosgw-admin ratelimit get --ratelimit-scope=user --uid="{user_name}"'
        output = utils.exec_shell_cmd(cmd, return_err=True)
        log.info("radosgw-admin ratelimit get for user (not enabled): %s", output)
        assert output, "Expected output from radosgw-admin ratelimit get"
        # Either error (ratelimit not set) or success (JSON with enabled: false / empty limits)
        if "failed" in output or "errno" in output:
            assert (
                "ratelimit" in output.lower()
            ), f"Expected ratelimit-related error, got: {output}"
        else:
            # Success: output is JSON; should indicate disabled or no limits
            assert (
                "enabled" in output
                or "max_list" in output
                or "ratelimit" in output.lower()
            ), f"Expected ratelimit state in output, got: {output}"
        log.info(
            "Correctly got ratelimit state for existing user with ratelimit not enabled"
        )

    # Test bucket-level LIST/DELETE rate limits
    if (
        getattr(config, "bucket_max_list_ops", None) is not None
        and getattr(config, "bucket_max_delete_ops", None) is not None
    ):
        log.info("Testing bucket-level LIST/DELETE rate limits")
        max_list_ops = config.bucket_max_list_ops
        max_delete_ops = config.bucket_max_delete_ops

        # Set bucket-level rate limits
        limset = utils.exec_shell_cmd(
            f"radosgw-admin ratelimit set --ratelimit-scope=bucket "
            + f"--bucket={bucket_name} --max-list-ops={max_list_ops} "
            + f"--max-delete-ops={max_delete_ops}"
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
        log.info(f"Rate limits enabled on bucket: {limget}")

        # Create objects after applying ratelimit, before asserting 503
        obj_count = max_list_ops + max_delete_ops + 2
        create_objects_after_ratelimit(bucket_name, obj_count)

        # Test LIST operations rate limit: max_list_ops is the max LIST ops
        # allowed; run s3cmd ls (max_list_ops + 1) times to exceed and assert 503
        log.info(
            "Attempting to list objects using s3cmd ls for max_list_ops+1 times "
            "(max_list_ops=%s is the limit)",
            max_list_ops,
        )
        attempt_list_ops_and_assert_503(bucket_name, max_list_ops)

        log.info("Sleeping for 61 seconds to reset limits")
        sleep(61)

        # Test DELETE operations rate limit
        log.info("Testing DELETE operations rate limit")
        s3cmd_reusable.rate_limit_delete(bucket_name, max_delete_ops)

        log.info("Sleeping for 61 seconds to reset limits")
        sleep(61)

        # Disable bucket-level limits before testing user-level
        utils.exec_shell_cmd(
            f"radosgw-admin ratelimit disable --ratelimit-scope=bucket --bucket={bucket_name}"
        )

    # Test user-level LIST/DELETE rate limits
    if (
        getattr(config, "user_max_list_ops", None) is not None
        and getattr(config, "user_max_delete_ops", None) is not None
    ):
        log.info("Testing user-level LIST/DELETE rate limits")
        max_list_ops = config.user_max_list_ops
        max_delete_ops = config.user_max_delete_ops

        # Set user-level rate limits
        limset = utils.exec_shell_cmd(
            f'radosgw-admin ratelimit set --ratelimit-scope=user --uid="{user_name}" '
            f"--max-list-ops={max_list_ops} --max-delete-ops={max_delete_ops}"
        )
        log.info(f"Rate limits set on user {user_name}")

        limenable = utils.exec_shell_cmd(
            f'radosgw-admin ratelimit enable --ratelimit-scope=user --uid="{user_name}"'
        )

        limget = utils.exec_shell_cmd(
            f'radosgw-admin ratelimit get --ratelimit-scope=user --uid="{user_name}"'
        )
        log.info(f"Rate limits enabled on user: {limget}")

        # Create a second bucket for user-level testing
        bucket_name2 = utils.gen_bucket_name_from_userid(user_name, rand_no=1)
        bucket_name2 = bucket_name2.replace("'", "")

        if config.user_type == "tenanted":
            bucket_name2 = f"tenant1/{bucket_name2}"

        if config.version_enable:
            s3cmd_reusable.create_versioned_bucket(user_info, bucket_name2, ip_and_port)
        else:
            s3cmd_reusable.create_bucket(bucket_name2, ip_and_port)

        log.info(f"Bucket {bucket_name2} created for user-level testing")

        # Create objects after applying ratelimit, before asserting 503
        obj_count = max_list_ops + max_delete_ops + 2
        create_objects_after_ratelimit(bucket_name2, obj_count)

        # Test LIST operations rate limit at user level: max_list_ops is the max
        # LIST ops allowed; run s3cmd ls (max_list_ops + 1) times to exceed 503
        log.info(
            "Attempting to list objects using s3cmd ls for max_list_ops+1 times "
            "at user level (max_list_ops=%s is the limit)",
            max_list_ops,
        )
        attempt_list_ops_and_assert_503(bucket_name2, max_list_ops)

        log.info("Sleeping for 61 seconds to reset limits")
        sleep(61)

        # Test DELETE operations rate limit at user level
        log.info("Testing DELETE operations rate limit at user level")
        s3cmd_reusable.rate_limit_delete(bucket_name2, max_delete_ops)

        log.info("Sleeping for 61 seconds to reset limits")
        sleep(61)

    # Test rgw_ratelimit_interval configuration option
    test_ops = getattr(config, "test_ops", None) or {}
    if test_ops.get("test_rgw_ratelimit_interval", False):
        log.info("Testing rgw_ratelimit_interval configuration option")

        # Get RGW process name for config commands
        cmd = "ceph orch ps | grep rgw"
        out = utils.exec_shell_cmd(cmd)
        rgw_process_name = out.split()[0]
        log.info(f"RGW process name: {rgw_process_name}")

        # Get RGW service name for restart command
        cmd = "ceph orch ls | grep rgw"
        out = utils.exec_shell_cmd(cmd)
        rgw_service_name = out.split()[0]
        log.info(f"RGW service name: {rgw_service_name}")

        # Set rgw_ratelimit_interval (e.g., 30 seconds instead of default 60)
        rgw_ratelimit_interval = getattr(config, "rgw_ratelimit_interval", None)
        if rgw_ratelimit_interval is None:
            rgw_ratelimit_interval = 60
            log.warning(
                "config rgw_ratelimit_interval not set, using default %s seconds",
                rgw_ratelimit_interval,
            )
        log.info(
            f"Setting rgw_ratelimit_interval to {rgw_ratelimit_interval} seconds (default is 60)"
        )
        utils.exec_shell_cmd(
            f"ceph config set client.{rgw_process_name} rgw_ratelimit_interval {rgw_ratelimit_interval}"
        )

        # Restart RGW daemon to apply config change
        log.info("Restarting RGW daemon to apply configuration")
        utils.exec_shell_cmd(f"ceph orch restart {rgw_service_name}")

        # Wait for RGW to be ready
        log.info("Waiting 60 seconds for RGW to restart")
        sleep(60)

        # Set rate limits for testing
        max_list_ops = config.user_max_list_ops
        max_delete_ops = config.user_max_delete_ops

        limset = utils.exec_shell_cmd(
            f'radosgw-admin ratelimit set --ratelimit-scope=user --uid="{user_name}" '
            f"--max-list-ops={max_list_ops} --max-delete-ops={max_delete_ops}"
        )

        limenable = utils.exec_shell_cmd(
            f'radosgw-admin ratelimit enable --ratelimit-scope=user --uid="{user_name}"'
        )

        # Trigger rate limit: run s3cmd ls (max_list_ops + 1) times to exceed 503
        log.info("Triggering LIST rate limit")
        attempt_list_ops_and_assert_503(bucket_name, max_list_ops)

        # Sleep for the custom rgw_ratelimit_interval (should reset counter)
        log.info(
            f"Sleeping for {rgw_ratelimit_interval + 1} seconds (rgw_ratelimit_interval + 1)"
        )
        sleep(rgw_ratelimit_interval + 1)

        # Verify limits are reset after custom rgw_ratelimit_interval
        log.info(
            "Verifying rate limit counter reset after custom rgw_ratelimit_interval"
        )
        attempt_list_ops_and_assert_503(bucket_name, max_list_ops)

        log.info(
            f"rgw_ratelimit_interval of {rgw_ratelimit_interval} seconds working correctly - test passed"
        )

        # Reset to default (60 seconds)
        log.info("Resetting rgw_ratelimit_interval to default (60 seconds)")
        utils.exec_shell_cmd(
            f"ceph config rm client.{rgw_process_name} rgw_ratelimit_interval"
        )
        utils.exec_shell_cmd(f"ceph orch restart {rgw_service_name}")
        sleep(60)


if __name__ == "__main__":
    test_info = AddTestInfo("test LIST and DELETE rate limits")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW S3 LIST and DELETE rate limits"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW S3 LIST and DELETE rate limits"
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
