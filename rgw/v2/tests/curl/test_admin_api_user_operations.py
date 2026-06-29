"""
test_admin_api_user_operations - Test user/subuser modify and delete operations in multisite

Usage: test_admin_api_user_operations.py -c <input_yaml>

<input_yaml>
        test_admin_api_user_operations.yaml

Operation:
    This test validates user modifications, deletions, and subuser operations
    are properly synced between primary and secondary sites in a multisite RGW setup.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import random
import string
import time
import traceback

import names
import v2.utils.utils as utils
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.curl import admin_api
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

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

    user_count = config.user_count if hasattr(config, "user_count") else 1
    sync_wait_time = config.sync_wait_time if hasattr(config, "sync_wait_time") else 10

    all_users = []

    try:
        for user_num in range(user_count):
            # Generate UIDs for both sites
            primary_uid = (
                names.get_first_name().lower()
                + random.choice(string.ascii_lowercase)
                + "."
                + str(random.randint(1, 1000))
            )
            secondary_uid = (
                names.get_first_name().lower()
                + random.choice(string.ascii_lowercase)
                + "."
                + str(random.randint(1, 1000))
            )
            primary_display_name = names.get_full_name().lower()
            secondary_display_name = names.get_full_name().lower()
            subuser = "subuser1"

            # Create User on both sites
            log.info("-" * 80)
            log.info(f"Create User on Primary site")
            admin_api.create_user(
                primary_endpoint,
                admin_access_key,
                admin_secret_key,
                primary_uid,
                primary_display_name,
                "Primary",
            )
            all_users.append(primary_uid)
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)

            log.info("-" * 80)
            log.info(f"Create User on Secondary site")
            admin_api.create_user(
                secondary_endpoint,
                admin_access_key,
                admin_secret_key,
                secondary_uid,
                secondary_display_name,
                "Secondary",
            )
            all_users.append(secondary_uid)
            log.info(f"Waiting {sync_wait_time} seconds for sync...")
            time.sleep(sync_wait_time)

            # Modify User on both sites
            if config.test_ops.get("modify_user", False):
                log.info("-" * 80)
                log.info(f"Modify User on Primary site")
                primary_new_display_name = "Updated_from_Primary"
                admin_api.modify_user(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    primary_new_display_name,
                    "Primary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "user_modification",
                    "Primary",
                    "Secondary",
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=primary_uid,
                    expected_display_name=primary_new_display_name,
                )

                log.info("-" * 80)
                log.info(f"Modify User on Secondary site")
                secondary_new_display_name = "Updated_from_Secondary"
                admin_api.modify_user(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    secondary_new_display_name,
                    "Secondary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "user_modification",
                    "Secondary",
                    "Primary",
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=secondary_uid,
                    expected_display_name=secondary_new_display_name,
                )

            # Create Subuser on both sites
            if config.test_ops.get("create_subuser", False):
                log.info("-" * 80)
                log.info(f"Create Subuser on Primary site")
                admin_api.create_subuser(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    subuser,
                    "Primary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "subuser",
                    "Primary",
                    "Secondary",
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=primary_uid,
                    subuser=subuser,
                )

                log.info("-" * 80)
                log.info(f"Create Subuser on Secondary site")
                admin_api.create_subuser(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    subuser,
                    "Secondary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "subuser",
                    "Secondary",
                    "Primary",
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=secondary_uid,
                    subuser=subuser,
                )

            # Modify Subuser on both sites
            if config.test_ops.get("modify_subuser", False):
                log.info("-" * 80)
                log.info(f"Modify Subuser on Primary site")
                admin_api.modify_subuser(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    subuser,
                    "Primary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "subuser_modification",
                    "Primary",
                    "Secondary",
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=primary_uid,
                    subuser=subuser,
                )

                log.info("-" * 80)
                log.info(f"Modify Subuser on Secondary site")
                admin_api.modify_subuser(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    subuser,
                    "Secondary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "subuser_modification",
                    "Secondary",
                    "Primary",
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=secondary_uid,
                    subuser=subuser,
                )

            # Delete Subuser on both sites
            if config.test_ops.get("delete_subuser", False):
                log.info("-" * 80)
                log.info(f"Delete Subuser on Primary site")
                admin_api.delete_subuser(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    subuser,
                    "Primary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "subuser_deletion",
                    "Primary",
                    "Secondary",
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=primary_uid,
                    subuser=subuser,
                )

                log.info("-" * 80)
                log.info(f"Delete Subuser on Secondary site")
                admin_api.delete_subuser(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    subuser,
                    "Secondary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "subuser_deletion",
                    "Secondary",
                    "Primary",
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=secondary_uid,
                    subuser=subuser,
                )

            # Add Capabilities
            if config.test_ops.get("add_capabilities", False):
                cap_type = "usage"
                cap_perm = "*"
                caps = f"{cap_type}={cap_perm}"
                expected_caps = [{"type": cap_type, "perm": cap_perm}]

                log.info("-" * 80)
                log.info(f"Add Capabilities on Primary site")
                admin_api.add_user_capabilities(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    caps,
                    "Primary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_user_capabilities(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    expected_caps,
                    should_exist=True,
                )
                log.info(
                    f"Verifying capabilities replication from Primary to Secondary"
                )
                admin_api.verify_user_capabilities(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    expected_caps,
                    should_exist=True,
                )

                log.info("-" * 80)
                log.info(f"Add Capabilities on Secondary site")
                admin_api.add_user_capabilities(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    caps,
                    "Secondary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_user_capabilities(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    expected_caps,
                    should_exist=True,
                )
                log.info(
                    f"Verifying capabilities replication from Secondary to Primary"
                )
                admin_api.verify_user_capabilities(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    expected_caps,
                    should_exist=True,
                )

            # Remove Capabilities
            if config.test_ops.get("remove_capabilities", False):
                cap_type = "usage"
                cap_perm = "*"
                caps = f"{cap_type}={cap_perm}"

                log.info("-" * 80)
                log.info(f"Remove Capabilities on Primary site")
                admin_api.remove_user_capabilities(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    caps,
                    "Primary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_user_capabilities(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    should_exist=False,
                )
                log.info(
                    f"Verifying capabilities removal replication from Primary to Secondary"
                )
                admin_api.verify_user_capabilities(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    should_exist=False,
                )

                log.info("-" * 80)
                log.info(f"Remove Capabilities on Secondary site")
                admin_api.remove_user_capabilities(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    caps,
                    "Secondary",
                )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_user_capabilities(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    should_exist=False,
                )
                log.info(
                    f"Verifying capabilities removal replication from Secondary to Primary"
                )
                admin_api.verify_user_capabilities(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    should_exist=False,
                )

            # Bucket Operations - Setup
            # Get user credentials for bucket operations
            primary_info = admin_api.get_user_info(
                primary_endpoint, admin_access_key, admin_secret_key, primary_uid
            )
            primary_user = {
                "user_id": primary_info["user_id"],
                "display_name": primary_info["display_name"],
                "access_key": primary_info["keys"][0]["access_key"],
                "secret_key": primary_info["keys"][0]["secret_key"],
            }

            secondary_info = admin_api.get_user_info(
                secondary_endpoint, admin_access_key, admin_secret_key, secondary_uid
            )
            secondary_user = {
                "user_id": secondary_info["user_id"],
                "display_name": secondary_info["display_name"],
                "access_key": secondary_info["keys"][0]["access_key"],
                "secret_key": secondary_info["keys"][0]["secret_key"],
            }

            # Setup AWS CLI and create AWS clients
            log.info("Setting up AWS CLI...")
            primary_aws = AWS(ssl=config.ssl if hasattr(config, "ssl") else False)
            secondary_aws = AWS(ssl=config.ssl if hasattr(config, "ssl") else False)

            # Lists to store created bucket names
            primary_buckets_list = []
            secondary_buckets_list = []

            # Create buckets
            if config.test_ops.get("create_bucket", False):
                log.info("-" * 80)
                log.info(f"Create Bucket on Primary site")
                aws_auth.do_auth_aws(primary_user)
                for bc in range(config.bucket_count):
                    bucket_name = utils.gen_bucket_name_from_userid(
                        primary_user["user_id"], rand_no=bc
                    )
                    aws_reusable.create_bucket(
                        primary_aws, bucket_name, primary_endpoint
                    )
                    log.info(f"Bucket {bucket_name} created")
                    primary_buckets_list.append(bucket_name)
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)

                log.info("-" * 80)
                log.info(f"Create Bucket on Secondary site")
                aws_auth.do_auth_aws(secondary_user)
                for bc in range(config.bucket_count):
                    bucket_name = utils.gen_bucket_name_from_userid(
                        secondary_user["user_id"], rand_no=bc
                    )
                    aws_reusable.create_bucket(
                        secondary_aws, bucket_name, secondary_endpoint
                    )
                    log.info(f"Bucket {bucket_name} created")
                    secondary_buckets_list.append(bucket_name)
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)

            # Verify buckets
            if config.test_ops.get("create_bucket", False) and config.test_ops.get(
                "verify_bucket", False
            ):
                log.info("-" * 80)
                log.info("Verifying buckets on Primary site")
                aws_auth.do_auth_aws(primary_user)
                all_primary_buckets = aws_reusable.list_buckets(
                    primary_aws, primary_endpoint
                )
                for bucket_name in primary_buckets_list:
                    if bucket_name not in all_primary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} not found on Primary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' exists on Primary"
                    )

                log.info(f"Verifying bucket replication from Primary to Secondary")
                all_secondary_buckets = aws_reusable.list_buckets(
                    primary_aws, secondary_endpoint
                )
                for bucket_name in primary_buckets_list:
                    if bucket_name not in all_secondary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} not replicated to Secondary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' replicated to Secondary"
                    )

                log.info("-" * 80)
                log.info("Verifying buckets on Secondary site")
                aws_auth.do_auth_aws(secondary_user)
                all_secondary_buckets = aws_reusable.list_buckets(
                    secondary_aws, secondary_endpoint
                )
                for bucket_name in secondary_buckets_list:
                    if bucket_name not in all_secondary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} not found on Secondary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' exists on Secondary"
                    )

                log.info(f"Verifying bucket replication from Secondary to Primary")
                all_primary_buckets = aws_reusable.list_buckets(
                    secondary_aws, primary_endpoint
                )
                for bucket_name in secondary_buckets_list:
                    if bucket_name not in all_primary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} not replicated to Primary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' replicated to Primary"
                    )

            # Delete buckets
            if config.test_ops.get("create_bucket", False) and config.test_ops.get(
                "delete_bucket", False
            ):
                log.info("-" * 80)
                log.info(f"Delete Buckets from Primary site")
                for bucket_name in primary_buckets_list:
                    admin_api.delete_bucket_admin_api(
                        primary_endpoint,
                        admin_access_key,
                        admin_secret_key,
                        bucket_name,
                        "Primary",
                    )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)

                log.info("-" * 80)
                log.info(f"Delete Buckets from Secondary site")
                for bucket_name in secondary_buckets_list:
                    admin_api.delete_bucket_admin_api(
                        secondary_endpoint,
                        admin_access_key,
                        admin_secret_key,
                        bucket_name,
                        "Secondary",
                    )
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)

            # Verify bucket deletion
            if config.test_ops.get("delete_bucket", False) and config.test_ops.get(
                "verify_bucket", False
            ):
                log.info("-" * 80)
                log.info("Verifying bucket deletion on Primary site")
                aws_auth.do_auth_aws(primary_user)
                all_primary_buckets = aws_reusable.list_buckets(
                    primary_aws, primary_endpoint
                )
                for bucket_name in primary_buckets_list:
                    if bucket_name in all_primary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} still exists on Primary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' deleted from Primary"
                    )

                log.info(
                    f"Verifying bucket deletion replication from Primary to Secondary"
                )
                all_secondary_buckets = aws_reusable.list_buckets(
                    primary_aws, secondary_endpoint
                )
                for bucket_name in primary_buckets_list:
                    if bucket_name in all_secondary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} deletion not replicated to Secondary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' deletion replicated to Secondary"
                    )

                log.info("-" * 80)
                log.info("Verifying bucket deletion on Secondary site")
                aws_auth.do_auth_aws(secondary_user)
                all_secondary_buckets = aws_reusable.list_buckets(
                    secondary_aws, secondary_endpoint
                )
                for bucket_name in secondary_buckets_list:
                    if bucket_name in all_secondary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} still exists on Secondary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' deleted from Secondary"
                    )

                log.info(
                    f"Verifying bucket deletion replication from Secondary to Primary"
                )
                all_primary_buckets = aws_reusable.list_buckets(
                    secondary_aws, primary_endpoint
                )
                for bucket_name in secondary_buckets_list:
                    if bucket_name in all_primary_buckets:
                        raise TestExecError(
                            f"Bucket {bucket_name} deletion not replicated to Primary"
                        )
                    log.info(
                        f"VERIFICATION PASSED: Bucket '{bucket_name}' deletion replicated to Primary"
                    )

            # Delete User on both sites
            if config.test_ops.get("delete_user", False):
                log.info("-" * 80)
                log.info(f"Delete User on Primary site")
                admin_api.delete_user_api(
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    primary_uid,
                    "Primary",
                )
                all_users.remove(primary_uid)
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "user_deletion",
                    "Primary",
                    "Secondary",
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=primary_uid,
                )

                log.info("-" * 80)
                log.info(f"Delete User on Secondary site")
                admin_api.delete_user_api(
                    secondary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    secondary_uid,
                    "Secondary",
                )
                all_users.remove(secondary_uid)
                log.info(f"Waiting {sync_wait_time} seconds for sync...")
                time.sleep(sync_wait_time)
                admin_api.verify_replication(
                    "user_deletion",
                    "Secondary",
                    "Primary",
                    primary_endpoint,
                    admin_access_key,
                    admin_secret_key,
                    uid=secondary_uid,
                )

        log.info("ALL TESTS PASSED SUCCESSFULLY")

    except Exception as e:
        log.error(f"Test failed: {str(e)}")
        raise
    finally:
        # Cleanup
        if config.test_ops.get("user_remove", False):
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
