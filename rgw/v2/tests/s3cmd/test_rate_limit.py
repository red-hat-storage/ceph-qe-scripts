"""
test_rate_limit - Test rate limit on a User and Bucket level using s3cmd

Usage: test_rate_limit.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_rate_limit.yaml
    test_ratelimit_split.yaml
    test_ratelimit_debt.yaml
    test_bucket_link_with_ratelimit.yaml
    test_user_link_with_ratelimit.yaml

Polarion Tests:
CEPH-83574910
CEPH-83574913
CEPH-83574917

Operation:
    Create an user
    Create a bucket with user credentials
    Enable the limits max-read-ops, max-read-bytes, max-write-ops, max-write-bytes on a Bucket scope
    Verify the rate limits using s3cmd
    Repeat the same limits on a User scope

    Test Bucket link ops: on bucket where rate limit config enabled
    1. Bucket rename
    2. Bucket owner change
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
    log.info(f" User Caps are :{caps}")

    max_read_bytes = config.bucket_max_read_bytes
    max_read_ops = config.bucket_max_read_ops
    max_write_bytes = config.bucket_max_write_bytes
    max_write_ops = config.bucket_max_write_ops

    max_read_bytes_kb = math.ceil(float(max_read_bytes) / 1024)
    max_write_bytes_kb = math.ceil(float(max_write_bytes) / 1024)

    # create bucket and set limits
    bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)
    bucket_name = bucket_name.replace("'", "")

    if config.version_enable:
        ssl = config.ssl
        s3cmd_reusable.create_versioned_bucket(user_info, bucket_name, ip_and_port, ssl)
    else:
        ssl = config.ssl
        s3cmd_reusable.create_bucket(bucket_name, ip_and_port, ssl)

    if config.user_type == "tenanted":
        bucket_name = f"tenant1/{bucket_name}"

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

    if config.test_ops.get("test_bucket_link_with_ratelimit", False):
        log.info("Testing bucket link ops with ratelimit set")
        log.info(
            "Perform bucket rename operation using radosgw-admin bucket link command"
        )
        bucket_name_new = f"{bucket_name}-new"
        cmd = f"radosgw-admin bucket link --bucket={bucket_name} --bucket-new-name={bucket_name_new} --uid={user_name}"
        output = utils.exec_shell_cmd(cmd, return_err=True)
        log.info(f"output is {output}")
        if (
            "(22) Invalid argument: While crossing the Anavros you have displeased the goddess Hera"
            in output
        ):
            raise AssertionError(
                f"Bucket rename with bucket link command failed for ratelimit enabled bucket {bucket_name}"
            )
        out = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket {bucket_name_new}"
        )

    elif config.test_ops.get("test_user_link_with_ratelimit", False):
        log.info("Testing user link ops with ratelimit set")
        existing_user_name = user_name
        new_user_name = f"{existing_user_name}-new"
        utils.exec_shell_cmd(
            f"radosgw-admin user create --uid {new_user_name} --display-name {new_user_name}"
        )
        log.info(f"unlink bucket {bucket_name} from existing user {existing_user_name}")
        utils.exec_shell_cmd(
            f"radosgw-admin bucket unlink --bucket {bucket_name} --uid {existing_user_name}"
        )
        log.info(f"Perform new user:{new_user_name} link to the bucket {bucket_name}")
        cmd = f"radosgw-admin bucket link --bucket={bucket_name} --uid={new_user_name}"
        output = utils.exec_shell_cmd(cmd, return_err=True)
        log.info(f"output is {output}")
        if (
            "(22) Invalid argument: While crossing the Anavros you have displeased the goddess Hera"
            in output
        ):
            raise AssertionError(
                f"Bucket link to new user failed for ratelimit enabled bucket {bucket_name}"
            )
        out = json.loads(
            utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket_name}")
        )
        if out["owner"] != new_user_name:
            raise AssertionError("Bucket owner change failed!")
    else:
        # test the read and write ops limit
        log.info(f"Test the read and write ops limits")
        s3cmd_reusable.rate_limit_read(bucket_name, max_read_ops, ssl)

        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)

        s3cmd_reusable.rate_limit_write(bucket_name, max_write_ops, ssl)

        # sleep a minute to reset the ops limit
        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)

        # test the read and write data limit
        log.info(f"Test the read and write data limits")
        s3cmd_reusable.rate_limit_read(bucket_name, max_read_bytes_kb, ssl)

        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)
        s3cmd_reusable.rate_limit_write(bucket_name, max_write_bytes_kb, ssl)

        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)

        # Set the rate limits for the user and enable them
        max_read_bytes = config.user_max_read_bytes
        max_read_ops = config.user_max_read_ops
        max_write_bytes = config.user_max_write_bytes
        max_write_ops = config.user_max_write_ops

        max_read_bytes_kb = math.ceil(float(max_read_bytes) / 1024)
        max_write_bytes_kb = math.ceil(float(max_write_bytes) / 1024)

        utils.exec_shell_cmd(
            f"radosgw-admin ratelimit disable --ratelimit-scope=bucket --bucket={bucket_name}"
        )

        limset = utils.exec_shell_cmd(
            f"radosgw-admin ratelimit set --ratelimit-scope=user --uid={user_name}"
            + f" --max-read-ops={max_read_ops} --max-read-bytes={max_read_bytes}"
            + f" --max-write-bytes={max_write_bytes} --max-write-ops={max_write_ops}"
        )
        log.info(f"Rate limits set on user {user_name}")
        limenable = utils.exec_shell_cmd(
            f"radosgw-admin ratelimit enable --ratelimit-scope=user --uid={user_name}"
        )
        limget = utils.exec_shell_cmd(
            f"radosgw-admin ratelimit get --ratelimit-scope=user --uid={user_name}"
        )
        log.info(f"Rate limits enabled on bucket : {limget} ")

        bucket_name2 = utils.gen_bucket_name_from_userid(user_name, rand_no=1)
        bucket_name2 = bucket_name2.replace("'", "")
        if config.version_enable:
            s3cmd_reusable.create_versioned_bucket(
                user_info, bucket_name2, ip_and_port, ssl
            )
        else:
            s3cmd_reusable.create_bucket(bucket_name2, ip_and_port, ssl)

        # test the read and write ops limit
        log.info(f"Test the read and write ops limits")
        s3cmd_reusable.rate_limit_read(bucket_name2, max_read_ops, ssl)

        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)

        s3cmd_reusable.rate_limit_write(bucket_name2, max_write_ops, ssl)

        # sleep a minute to reset the ops limit
        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)

        # test the read and write data limit
        log.info(f"Test the read and write data limits")
        s3cmd_reusable.rate_limit_read(bucket_name2, max_read_bytes_kb, ssl)

        log.info(f"Sleeping for a minute to reset limits")
        sleep(61)
        s3cmd_reusable.rate_limit_write(bucket_name2, max_write_bytes_kb, ssl)

        if config.test_ops.get("daemon_add", False):
            log.info("Add a RGW daemon to the existing configuration")
            s3cmd_reusable.rgw_daemon_add(ssh_con)
            log.info("Verify that the ratelimits should now be halved for each daemon")
            max_read_ops = math.ceil(max_read_ops / 2)
            max_write_ops = math.ceil(max_write_ops / 2)
            # test the read and write ops limit
            sleep(60)
            log.info(f"Test the read and write ops limits")
            s3cmd_reusable.rate_limit_read(bucket_name2, max_read_ops, ssl)

            log.info(f"Sleeping for a minute to reset limits")
            sleep(61)
            s3cmd_reusable.rate_limit_write(bucket_name2, max_write_ops, ssl)

        if config.test_ops.get("test_debt", False):
            log.info("Test the rate limit debt feature ")
            log.info("Write more than double the max write bytes")
            log.info("Sleep for a minute to reset limits")
            sleep(61)
            debt_limit = 2 * int(max_write_bytes_kb)
            s3cmd_reusable.debt_ratelimit(bucket_name2, debt_limit, ssl)

            # post a write above the set limit , debt is in effect
            # further writes will fail until 2 minutes
            s3cmd_reusable.rate_limit_write(bucket_name2, max_write_bytes_kb, ssl)
            log.info("Sleep for 120 seconds for the debt to conclude")
            sleep(121)
            s3cmd_reusable.rate_limit_write(bucket_name2, max_write_bytes_kb, ssl)


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket and user rate limits")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW S3 bucket and user rate limits"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW S3 bucket and user rate limits"
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
