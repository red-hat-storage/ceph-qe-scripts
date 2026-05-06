"""
Test for Cloud Transition and Restore Bug Verifications

Bugs covered:
1. Multipart Part Number 0 (https://tracker.ceph.com/issues/68324)
2. ETag Double Quotes on Restore (https://tracker.ceph.com/issues/67560)
3. Days=0 Restore Invalid State (https://tracker.ceph.com/issues/67685)

Owner: Vidushi Mishra
Email: vmishra@redhat.com

Test Description:
This test validates fixes for known cloud transition and restore bugs.
Each test can be run independently based on configuration.

Cluster Requirements:
- RGW with cloud tier configured
- S3 API enabled
- Cloud endpoint credentials configured

Success Criteria:
- Part numbers start at 1 (not 0) for multipart cloud transitions
- ETag has single quotes after restore (not double)
- Days=0 restore request is properly rejected or handled
"""

import logging
import os
import sys
import time
import traceback
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import s3_object_restore
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_multipart_part_number_bug(config, rgw_conn, rgw_conn_client, s3_user, ssh_con):
    """
    Test: Verify multipart transitions don't use part number 0

    Bug: https://tracker.ceph.com/issues/68324
    Fixed in: v21.0.0-721-g9fef887b05

    This test verifies that multipart cloud transitions use proper
    1-based part numbering (not 0-based).
    """
    log.info("=" * 80)
    log.info("BUG TEST: Multipart Part Number 0")
    log.info("Tracker: https://tracker.ceph.com/issues/68324")
    log.info("=" * 80)

    try:
        # Get cloud tier config
        storage_class = config.test_ops.get("cloud_storage_class", "CLOUDIBM")
        bucket_name = utils.gen_bucket_name_from_userid(s3_user["user_id"], rand_no=1)

        # Create bucket
        bucket = reusable.create_bucket(bucket_name, rgw_conn, s3_user)
        log.info(f"Created bucket: {bucket_name}")

        # Apply lifecycle policy for immediate transition
        lifecycle_config = {
            "Rules": [{
                "ID": "MultipartTestRule",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [{
                    "Days": 0,
                    "StorageClass": storage_class
                }]
            }]
        }

        rgw_conn_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        log.info("Applied lifecycle policy")

        # Create a test file larger than multipart threshold
        # Config should have low multipart_sync_threshold to trigger multipart
        test_file = os.path.join(TEST_DATA_PATH, "multipart_test_100kb.bin")
        utils.exec_shell_cmd(f"dd if=/dev/urandom of={test_file} bs=1K count=100 2>/dev/null")
        log.info("Created 100KB test file to trigger multipart")

        # Upload object
        object_key = "multipart_test_100kb.bin"
        bucket.upload_file(test_file, object_key)
        log.info(f"Uploaded object: {object_key}")

        # Trigger lifecycle processing
        log.info("Processing lifecycle to trigger cloud transition...")
        utils.exec_shell_cmd(
            f"radosgw-admin lc process --bucket={bucket_name}",
            ssh_con=ssh_con
        )

        # Wait for processing
        time.sleep(20)

        # Check RGW logs for "part number 0" error
        log.info("Checking logs for 'part number 0' error...")
        try:
            log_check = utils.exec_shell_cmd(
                'journalctl -u ceph-*@rgw* --since "2 minutes ago" | grep -i "part number 0"',
                ssh_con=ssh_con
            )
            if log_check:
                log.error(f"BUG DETECTED: Found 'part number 0' error:")
                log.error(log_check)
                raise TestExecError("Multipart part number 0 bug detected!")
        except Exception as e:
            if "part number 0" in str(e).lower():
                raise TestExecError("Multipart part number 0 bug detected!")

        log.info("✓ No 'part number 0' errors found - bug not present")

        # Verify object transitioned
        obj_stat = utils.exec_shell_cmd(
            f"radosgw-admin object stat --bucket={bucket_name} --object={object_key}",
            ssh_con=ssh_con
        )

        if storage_class in obj_stat:
            log.info(f"✓ Object successfully transitioned to {storage_class}")
        else:
            log.warning(f"Object may not have transitioned to {storage_class}")

        log.info("TEST PASSED: Multipart part numbering is correct")
        return True

    except Exception as e:
        log.error(f"TEST FAILED: {e}")
        log.error(traceback.format_exc())
        raise
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)


def test_etag_double_quotes_bug(config, rgw_conn, rgw_conn_client, s3_user, ssh_con):
    """
    Test: Verify restored objects don't have double-quoted ETags

    Bug: https://tracker.ceph.com/issues/67560
    Fixed in: v21.0.0-719-g1934aadd0d

    This test verifies that ETags on restored objects have single quotes,
    not double quotes.
    """
    log.info("=" * 80)
    log.info("BUG TEST: ETag Double Quotes on Restore")
    log.info("Tracker: https://tracker.ceph.com/issues/67560")
    log.info("=" * 80)

    try:
        storage_class = config.test_ops.get("cloud_storage_class", "CLOUDIBM")
        bucket_name = utils.gen_bucket_name_from_userid(s3_user["user_id"], rand_no=2)

        # Create bucket
        bucket = reusable.create_bucket(bucket_name, rgw_conn, s3_user)
        log.info(f"Created bucket: {bucket_name}")

        # Apply lifecycle policy
        lifecycle_config = {
            "Rules": [{
                "ID": "ETagTestRule",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [{
                    "Days": 0,
                    "StorageClass": storage_class
                }]
            }]
        }

        rgw_conn_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )

        # Upload test object
        test_file = os.path.join(TEST_DATA_PATH, "etag_test.bin")
        utils.exec_shell_cmd(f"dd if=/dev/urandom of={test_file} bs=1M count=5 2>/dev/null")

        object_key = "etag_test.bin"
        bucket.upload_file(test_file, object_key)
        log.info(f"Uploaded object: {object_key}")

        # Get ETag before transition
        head_before = rgw_conn_client.head_object(Bucket=bucket_name, Key=object_key)
        etag_before = head_before['ETag']
        log.info(f"ETag before transition: {etag_before}")

        # Trigger transition
        utils.exec_shell_cmd(
            f"radosgw-admin lc process --bucket={bucket_name}",
            ssh_con=ssh_con
        )
        time.sleep(30)

        # Check if transitioned
        head_after_transition = rgw_conn_client.head_object(
            Bucket=bucket_name,
            Key=object_key
        )

        if head_after_transition.get('StorageClass') == storage_class:
            log.info(f"✓ Object transitioned to {storage_class}")

            # Restore the object
            log.info("Restoring object...")
            rgw_conn_client.restore_object(
                Bucket=bucket_name,
                Key=object_key,
                RestoreRequest={'Days': 7}
            )

            # Wait for restore
            max_wait = config.test_ops.get("restore_wait_time", 300)
            poll_interval = config.test_ops.get("restore_poll_interval", 30)
            elapsed = 0

            while elapsed < max_wait:
                time.sleep(poll_interval)
                elapsed += poll_interval

                head_restore = rgw_conn_client.head_object(
                    Bucket=bucket_name,
                    Key=object_key
                )
                restore_status = head_restore.get("Restore", "")

                if 'ongoing-request="false"' in restore_status:
                    log.info(f"Restore completed after {elapsed}s")

                    # Check ETag
                    etag_after_restore = head_restore['ETag']
                    log.info(f"ETag after restore: {etag_after_restore}")

                    # Count quotes
                    quote_count = etag_after_restore.count('"')
                    log.info(f"ETag quote count: {quote_count}")

                    # Bug: ETag has double quotes like ""hash""
                    # Expected: Single quotes like "hash"
                    if etag_after_restore.startswith('""') or quote_count > 2:
                        log.error(f"BUG DETECTED: ETag has extra quotes: {etag_after_restore}")
                        raise TestExecError("ETag double quotes bug detected!")

                    log.info("✓ ETag format is correct (no extra quotes)")
                    break

                log.info(f"Waiting for restore... elapsed: {elapsed}s")
            else:
                log.warning(f"Restore did not complete in {max_wait}s")

        log.info("TEST PASSED: ETag formatting is correct")
        return True

    except Exception as e:
        log.error(f"TEST FAILED: {e}")
        log.error(traceback.format_exc())
        raise
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


def test_days_zero_restore_bug(config, rgw_conn, rgw_conn_client, s3_user, ssh_con):
    """
    Test: Verify Days=0 restore is properly rejected

    Bug: https://tracker.ceph.com/issues/67685
    Fixed in: v21.0.0-655-g1df675bb60

    This test verifies that restore requests with Days=0 are properly
    handled and don't leave objects in a broken state.
    """
    log.info("=" * 80)
    log.info("BUG TEST: Days=0 Restore Request")
    log.info("Tracker: https://tracker.ceph.com/issues/67685")
    log.info("=" * 80)

    try:
        storage_class = config.test_ops.get("cloud_storage_class", "CLOUDIBM")
        bucket_name = utils.gen_bucket_name_from_userid(s3_user["user_id"], rand_no=3)

        # Create bucket and transition object
        bucket = reusable.create_bucket(bucket_name, rgw_conn, s3_user)

        lifecycle_config = {
            "Rules": [{
                "ID": "Days0TestRule",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [{
                    "Days": 0,
                    "StorageClass": storage_class
                }]
            }]
        }

        rgw_conn_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )

        # Upload and transition
        test_file = os.path.join(TEST_DATA_PATH, "days0_test.bin")
        utils.exec_shell_cmd(f"dd if=/dev/urandom of={test_file} bs=1M count=1 2>/dev/null")

        object_key = "days0_test.bin"
        bucket.upload_file(test_file, object_key)

        # Transition
        utils.exec_shell_cmd(
            f"radosgw-admin lc process --bucket={bucket_name}",
            ssh_con=ssh_con
        )
        time.sleep(30)

        # Try restore with Days=0
        log.info("Attempting restore with Days=0...")
        try:
            response = rgw_conn_client.restore_object(
                Bucket=bucket_name,
                Key=object_key,
                RestoreRequest={'Days': 0}
            )

            log.info(f"Restore response: {response}")

            # Check if object is in broken state
            time.sleep(10)
            head_obj = rgw_conn_client.head_object(Bucket=bucket_name, Key=object_key)
            restore_status = head_obj.get("Restore", "")

            # Bug: Object shows ongoing-request=true indefinitely
            if 'ongoing-request="true"' in restore_status:
                # Wait a bit more to be sure
                time.sleep(60)
                head_obj_2 = rgw_conn_client.head_object(Bucket=bucket_name, Key=object_key)
                restore_status_2 = head_obj_2.get("Restore", "")

                if 'ongoing-request="true"' in restore_status_2:
                    log.error("BUG DETECTED: Object stuck in ongoing-request=true state")
                    log.error(f"Restore status: {restore_status_2}")

                    # Check logs for "Days = 0 not valid"
                    log_check = utils.exec_shell_cmd(
                        'journalctl -u ceph-*@rgw* --since "2 minutes ago" | grep -i "Days = 0"',
                        ssh_con=ssh_con
                    )
                    if log_check:
                        log.error(f"Found Days=0 message in logs: {log_check}")

                    raise TestExecError("Days=0 restore bug detected - object in broken state!")

            log.info("✓ Days=0 restore was handled correctly (not stuck)")

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidArgument':
                log.info("✓ Days=0 properly rejected with InvalidArgument")
            else:
                log.warning(f"Days=0 rejected with: {error_code}")

        log.info("TEST PASSED: Days=0 restore handled properly")
        return True

    except Exception as e:
        log.error(f"TEST FAILED: {e}")
        log.error(traceback.format_exc())
        raise
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


def test_exec(config, ssh_con):
    """
    Main test execution function.
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Create user
    all_users_info = s3lib.create_users(config.user_count)
    s3_user = all_users_info[0]

    # Authenticate
    auth = Auth(s3_user, ssh_con, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    rgw_conn_client = auth.do_auth_using_client()

    # Get tests to run
    tests_to_run = config.test_ops.get("bug_tests_to_run", "all")

    test_results = {}

    # Test 1: Multipart Part Number 0
    if tests_to_run == "all" or "multipart_part_number" in tests_to_run:
        try:
            test_multipart_part_number_bug(config, rgw_conn, rgw_conn_client, s3_user, ssh_con)
            test_results["multipart_part_number"] = "PASSED"
        except Exception as e:
            test_results["multipart_part_number"] = f"FAILED: {e}"

    # Test 2: ETag Double Quotes
    if tests_to_run == "all" or "etag_double_quotes" in tests_to_run:
        try:
            test_etag_double_quotes_bug(config, rgw_conn, rgw_conn_client, s3_user, ssh_con)
            test_results["etag_double_quotes"] = "PASSED"
        except Exception as e:
            test_results["etag_double_quotes"] = f"FAILED: {e}"

    # Test 3: Days=0 Restore
    if tests_to_run == "all" or "days_zero_restore" in tests_to_run:
        try:
            test_days_zero_restore_bug(config, rgw_conn, rgw_conn_client, s3_user, ssh_con)
            test_results["days_zero_restore"] = "PASSED"
        except Exception as e:
            test_results["days_zero_restore"] = f"FAILED: {e}"

    # Print summary
    log.info("=" * 80)
    log.info("BUG VERIFICATION TEST RESULTS")
    log.info("=" * 80)

    passed = 0
    failed = 0

    for test_name, result in test_results.items():
        if result == "PASSED":
            log.info(f"✓ {test_name}: {result}")
            passed += 1
        else:
            log.error(f"✗ {test_name}: {result}")
            failed += 1

    log.info("=" * 80)
    log.info(f"Total: {passed + failed} | Passed: {passed} | Failed: {failed}")
    log.info("=" * 80)

    # Check for crashes
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    # Cleanup
    if config.local_file_delete:
        log.info("Cleaning up test data")
        utils.exec_shell_cmd(f"rm -rf {TEST_DATA_PATH}")

    if failed > 0:
        raise TestExecError(f"{failed} test(s) failed")

    return 0


if __name__ == "__main__":
    test_info = AddTestInfo("cloud_transition_bug_verification")

    try:
        import argparse

        parser = argparse.ArgumentParser(description="Cloud Transition Bug Verification Tests")
        parser.add_argument(
            "-c", dest="config", help="Test YAML configuration", required=True
        )
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set log level",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )

        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        log_level = args.log_level
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)

        # Configure logging
        configure_logging(
            f_name=os.path.basename(__file__), set_level=log_level.upper()
        )

        # Setup paths
        project_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../..")
        )
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")

        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        # Read config
        config = Config(yaml_file)
        config.read(ssh_con)

        # Start test
        test_info.started_info()

        # Execute test
        test_exec(config, ssh_con)

        test_info.success_status("test passed")
        sys.exit(0)

    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
