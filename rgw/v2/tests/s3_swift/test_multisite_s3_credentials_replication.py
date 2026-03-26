"""
test_multisite_s3_credentials_replication - Test S3 credentials replication in multisite setup

Usage: test_multisite_s3_credentials_replication.py -c <input_yaml>

<input_yaml>
        test_multisite_s3_credentials_replication.yaml

Operation:
    This test validates that S3 credentials created at secondary site are not erased
    when new credentials are created at primary site in a multisite RGW setup.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import os
import random
import string
import sys
import time
import traceback

import names
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import admin_api
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """Main test execution function"""
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Get endpoints
    primary_ip = utils.get_rgw_ip_zone("primary")
    primary_port = utils.get_radosgw_port_no(ssh_con)
    primary_endpoint = f"http://{primary_ip}:{primary_port}"

    secondary_ip = utils.get_rgw_ip_zone("secondary")
    secondary_port = utils.get_radosgw_port_no(ssh_con)
    secondary_endpoint = f"http://{secondary_ip}:{secondary_port}"

    log.info(f"Primary: {primary_endpoint}, Secondary: {secondary_endpoint}")

    # Get admin credentials
    repuser_info = admin_api.parse_json_response(
        utils.exec_shell_cmd("radosgw-admin user info --uid=repuser"), "repuser"
    )
    admin_access_key = repuser_info["keys"][0]["access_key"]
    admin_secret_key = repuser_info["keys"][0]["secret_key"]

    sync_wait_time = config.sync_wait_time if hasattr(config, "sync_wait_time") else 10
    all_users = []

    try:
        # Users created on Primary site
        for user_num in range(config.user_count):
            uid = (
                names.get_first_name().lower()
                + random.choice(string.ascii_lowercase)
                + "."
                + str(random.randint(1, 1000))
            )
            display_name = names.get_full_name().lower()

            log.info("=" * 80)
            log.info("Create User on Primary site")
            log.info("=" * 80)

            user = admin_api.create_user(
                primary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
                display_name,
                "Primary",
            )
            initial_key = user["keys"][0]["access_key"]
            all_users.append(uid)

            log.info(f"Waiting {sync_wait_time} seconds for multisite sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_key_replication(
                initial_key,
                "Primary",
                "Secondary",
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info("-" * 80)
            log.info("Step 1: Creating key on Primary site")
            key_p1 = admin_api.create_key(
                primary_endpoint, admin_access_key, admin_secret_key, uid, "Primary"
            )["access_key"]
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_key_replication(
                key_p1,
                "Primary",
                "Secondary",
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info("-" * 80)
            log.info("Step 2: Creating key on Secondary site")
            key_s1 = admin_api.create_key(
                secondary_endpoint, admin_access_key, admin_secret_key, uid, "Secondary"
            )["access_key"]
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_key_replication(
                key_s1,
                "Secondary",
                "Primary",
                primary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info("-" * 80)
            log.info("Step 3: Creating another key on Primary site")
            key_p2 = admin_api.create_key(
                primary_endpoint, admin_access_key, admin_secret_key, uid, "Primary"
            )["access_key"]
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_all_keys(
                [initial_key, key_p1, key_s1, key_p2],
                primary_endpoint,
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info("-" * 80)
            log.info("Step 4: Creating another key on Secondary site")
            key_s2 = admin_api.create_key(
                secondary_endpoint, admin_access_key, admin_secret_key, uid, "Secondary"
            )["access_key"]
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_all_keys(
                [initial_key, key_p1, key_s1, key_p2, key_s2],
                primary_endpoint,
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info(f"All keys replicated correctly for user '{uid}'")

        # Users created on Secondary site
        for user_num in range(config.user_count):
            uid = (
                names.get_first_name().lower()
                + random.choice(string.ascii_lowercase)
                + "."
                + str(random.randint(1, 1000))
            )
            display_name = names.get_full_name().lower()

            log.info("=" * 80)
            log.info("Create User on Secondary site")
            log.info("=" * 80)

            user = admin_api.create_user(
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
                display_name,
                "Secondary",
            )
            initial_key = user["keys"][0]["access_key"]
            all_users.append(uid)

            log.info(f"Waiting {sync_wait_time} seconds for multisite sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_key_replication(
                initial_key,
                "Secondary",
                "Primary",
                primary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info("-" * 80)
            log.info("Step 1: Creating key on Secondary site")
            key_s1 = admin_api.create_key(
                secondary_endpoint, admin_access_key, admin_secret_key, uid, "Secondary"
            )["access_key"]
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_key_replication(
                key_s1,
                "Secondary",
                "Primary",
                primary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info("-" * 80)
            log.info("Step 2: Creating key on Primary site")
            key_p1 = admin_api.create_key(
                primary_endpoint, admin_access_key, admin_secret_key, uid, "Primary"
            )["access_key"]
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)
            admin_api.verify_all_keys(
                [initial_key, key_s1, key_p1],
                primary_endpoint,
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                uid,
            )

            log.info(f"All keys replicated correctly for user '{uid}'")

        log.info("ALL TESTS PASSED SUCCESSFULLY")

    except Exception as e:
        log.error(f"Test failed: {str(e)}")
        raise
    finally:
        # Cleanup
        for uid in all_users:
            admin_api.delete_user(uid)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test multisite S3 credentials replication")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="RGW Multisite S3 Credentials Replication Test"
        )
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            default="info",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", default="127.0.0.1", help="RGW Node"
        )
        args = parser.parse_args()

        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)

        configure_logging(
            f_name=os.path.basename(os.path.splitext(args.config)[0]),
            set_level=args.log_level.upper(),
        )
        config = Config(args.config)
        config.read(ssh_con)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
