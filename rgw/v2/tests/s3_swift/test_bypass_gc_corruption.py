"""
Test for bypass-gc corruption fix (Issues #73138 & #73348)

Owner: Vidushi Mishra
Email: vmishra@redhat.com

Test Description:
This test validates the fix for cls_refcount_put corruption when using
--bypass-gc flag with server-side copy operations. It ensures that when
destination buckets with copied objects are deleted using bypass-gc,
the source objects remain accessible and intact.

This version focuses on two critical scenarios:
1. Multipart uploads with bypass-gc deletion
2. Versioned buckets with bypass-gc deletion

Cluster Requirements:
- Single node or multi-node cluster
- RGW daemon running
- S3 API enabled

Test Flow:
1. Multipart uploads with bypass-gc deletion
2. Versioned buckets with bypass-gc deletion

Success Criteria:
- Source objects remain accessible after bypass-gc deletion of copies
- No data corruption (MD5 checksums match)
- No shadow object corruption
- Versioned objects maintain all versions correctly
"""

import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bypass_gc_ops
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_multipart_upload(config, rgw_conn, s3_user, ssh_con):
    """
    Test: Multipart upload with server-side copy and bypass-gc deletion.

    Tests that multipart uploaded objects work correctly with bypass-gc.
    """
    log.info("=" * 80)
    log.info("TEST: Multipart Upload with Server-Side Copy and Bypass-GC")
    log.info("=" * 80)

    try:
        # Create source and destination buckets
        src_bucket_name = utils.gen_bucket_name_from_userid(
            s3_user["user_id"], rand_no=1
        )
        dst_bucket_name = utils.gen_bucket_name_from_userid(
            s3_user["user_id"], rand_no=2
        )

        src_bucket = reusable.create_bucket(src_bucket_name, rgw_conn, s3_user)
        dst_bucket = reusable.create_bucket(dst_bucket_name, rgw_conn, s3_user)

        # Upload multipart object
        object_name = utils.gen_s3_object_name(src_bucket_name, 1)
        log.info(f"Uploading multipart object: {object_name}")

        # Get multipart config from test config or use defaults
        obj_size = config.test_ops.get("multipart_obj_size", 30)
        part_size = config.test_ops.get("multipart_part_size", 10)

        # Create multipart config object
        class MultipartConfig:
            pass

        mp_config = MultipartConfig()
        mp_config.obj_size = obj_size
        mp_config.split_size = part_size
        mp_config.local_file_delete = config.local_file_delete

        log.info(f"Multipart config: {obj_size}MB object, {part_size}MB parts")

        reusable.upload_multipart_with_break(
            object_name,
            src_bucket,
            TEST_DATA_PATH,
            mp_config,
            s3_user,
            break_at_part_no=0,  # 0 means complete the upload
        )

        # Get original MD5
        original_path = os.path.join(TEST_DATA_PATH, object_name)
        original_md5 = utils.get_md5(original_path)
        log.info(f"Original multipart object MD5: {original_md5}")

        # Verify source object is accessible
        bypass_gc_ops.verify_object_integrity(
            src_bucket, object_name, original_md5, TEST_DATA_PATH
        )

        # Server-side copy
        bypass_gc_ops.perform_server_side_copy(src_bucket, dst_bucket, object_name)

        # Verify both copies are accessible
        bypass_gc_ops.verify_object_integrity(
            src_bucket, object_name, original_md5, TEST_DATA_PATH
        )
        bypass_gc_ops.verify_object_integrity(
            dst_bucket, object_name, original_md5, TEST_DATA_PATH
        )

        # Delete destination with bypass-gc
        bypass_gc_ops.delete_bucket_with_bypass_gc(dst_bucket_name)

        # Verify source multipart object remains accessible
        log.info("Verifying source multipart object after bypass-gc deletion")
        bypass_gc_ops.verify_object_integrity(
            src_bucket, object_name, original_md5, TEST_DATA_PATH
        )

        log.info("TEST PASSED: Multipart upload test successful")
        return True

    except Exception as e:
        log.error(f"TEST FAILED: {e}")
        log.error(traceback.format_exc())
        raise


def test_versioned_buckets(config, rgw_conn, s3_user, ssh_con):
    """
    Test: Versioned buckets with server-side copy and bypass-gc deletion.

    Tests server-side copy of versioned objects with bypass-gc deletion.
    """
    log.info("=" * 80)
    log.info("TEST: Versioned Buckets with Server-Side Copy and Bypass-GC")
    log.info("=" * 80)

    try:
        # Create source and destination buckets
        src_bucket_name = utils.gen_bucket_name_from_userid(
            s3_user["user_id"], rand_no=10
        )
        dst_bucket_name = utils.gen_bucket_name_from_userid(
            s3_user["user_id"], rand_no=11
        )

        src_bucket = reusable.create_bucket(src_bucket_name, rgw_conn, s3_user)
        dst_bucket = reusable.create_bucket(dst_bucket_name, rgw_conn, s3_user)

        # Enable versioning on source bucket
        bypass_gc_ops.enable_versioning(rgw_conn, src_bucket_name)

        # Upload multiple versions
        object_name = utils.gen_s3_object_name(src_bucket_name, 1)
        version_count = config.test_ops.get("version_count", 2)
        version_md5s = {}

        log.info(f"Creating {version_count} versions of object {object_name}")

        for version_num in range(1, version_count + 1):
            log.info(f"Uploading version {version_num}")
            config.obj_size = config.test_ops.get("object_size", 10)
            reusable.upload_object(
                object_name, src_bucket, TEST_DATA_PATH, config, s3_user
            )

            # Get version ID
            versions = bypass_gc_ops.get_object_versions(src_bucket, object_name)
            latest_version = versions[0]
            version_id = latest_version.version_id

            log.info(f"Version {version_num} ID: {version_id}")

            # Store MD5 for this version
            version_path = os.path.join(TEST_DATA_PATH, object_name)
            version_md5s[version_id] = utils.get_md5(version_path)

            # Remove file to create new version in next iteration
            if os.path.exists(version_path):
                os.remove(version_path)

        # Get all versions for verification
        all_versions = bypass_gc_ops.get_object_versions(src_bucket, object_name)

        # Copy a specific version to destination
        version_to_copy = all_versions[-1].version_id
        log.info(f"Copying version {version_to_copy} to destination")

        bypass_gc_ops.perform_server_side_copy(
            src_bucket, dst_bucket, object_name, version_id=version_to_copy
        )

        # Verify copied object in destination
        bypass_gc_ops.verify_object_integrity(
            dst_bucket,
            object_name,
            version_md5s[version_to_copy],
            TEST_DATA_PATH,
        )

        # Delete destination with bypass-gc
        bypass_gc_ops.delete_bucket_with_bypass_gc(dst_bucket_name)

        # Verify all versions in source still work
        log.info("Verifying all versions in source bucket after bypass-gc deletion")
        for version in all_versions:
            version_id = version.version_id
            log.info(f"Verifying version {version_id}")

            download_name = f"{object_name}.v{version_id}.download"
            download_path = os.path.join(TEST_DATA_PATH, download_name)

            try:
                s3lib.resource_op(
                    {
                        "obj": src_bucket,
                        "resource": "download_file",
                        "args": [
                            object_name,
                            download_path,
                            {"VersionId": version_id},
                        ],
                    }
                )

                downloaded_md5 = utils.get_md5(download_path)
                expected_md5 = version_md5s.get(version_id)

                if expected_md5 and str(downloaded_md5) != str(expected_md5):
                    raise TestExecError(
                        f"MD5 mismatch for version {version_id}: expected {expected_md5}, got {downloaded_md5}"
                    )

                log.info(f"✓ Version {version_id} verified successfully")

            finally:
                if os.path.exists(download_path):
                    os.remove(download_path)

        log.info("TEST PASSED: Versioned buckets test successful")
        return True

    except Exception as e:
        log.error(f"TEST FAILED: {e}")
        log.error(traceback.format_exc())
        raise


def test_exec(config, ssh_con):
    """
    Main test execution function.

    Args:
        config: Parsed YAML configuration
        ssh_con: SSH connection object to cluster

    Returns:
        int: 0 for success, 1 for failure
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

    # Run tests based on config
    tests_to_run = config.test_ops.get("tests_to_run", "all")

    test_results = {}

    # Test 1: Multipart Upload
    if tests_to_run == "all" or "multipart_upload" in tests_to_run:
        try:
            test_multipart_upload(config, rgw_conn, s3_user, ssh_con)
            test_results["multipart_upload"] = "PASSED"
        except Exception as e:
            test_results["multipart_upload"] = f"FAILED: {e}"

    # Test 2: Versioned Buckets
    if tests_to_run == "all" or "versioned_buckets" in tests_to_run:
        try:
            test_versioned_buckets(config, rgw_conn, s3_user, ssh_con)
            test_results["versioned_buckets"] = "PASSED"
        except Exception as e:
            test_results["versioned_buckets"] = f"FAILED: {e}"

    # Print summary
    log.info("=" * 80)
    log.info("TEST RESULTS SUMMARY")
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
    test_info = AddTestInfo("test_bypass_gc_corruption")

    try:
        # Parse arguments first
        import argparse

        parser = argparse.ArgumentParser(description="RGW Bypass-GC Corruption Test")
        parser.add_argument(
            "-c", dest="config", help="RGW Test yaml configuration", required=True
        )
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set log level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )

        args = parser.parse_args()
        yaml_file = args.config
        ssh_con = None
        rgw_node = args.rgw_node
        log_level = args.log_level

        # Configure logging before using log
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
            log.info("test data dir not exists, creating...")
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
