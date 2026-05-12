"""
Reusable functions for Cloud Transition Bug Verification

This module contains functions to verify fixes for known cloud transition
and restore bugs:

1. Multipart Part Number 0 (https://tracker.ceph.com/issues/68324)
2. ETag Double Quotes on Restore (https://tracker.ceph.com/issues/67560)
3. Days=0 Restore Invalid State (https://tracker.ceph.com/issues/67685)

Owner: Vidushi Mishra
Email: vmishra@redhat.com
"""

import logging
import time
from botocore.exceptions import ClientError
import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError

log = logging.getLogger()


def check_multipart_part_number_bug(ssh_con, bucket_name, object_key, storage_class):
    """
    Check for multipart part number 0 bug.

    Bug: https://tracker.ceph.com/issues/68324
    Fixed in: v21.0.0-721-g9fef887b05

    This function checks RGW logs for "part number 0" errors during
    cloud transition, which indicates the bug is present.

    Args:
        ssh_con: SSH connection to RGW node
        bucket_name: Name of the bucket
        object_key: Object key that was transitioned
        storage_class: Expected storage class after transition

    Raises:
        TestExecError: If "part number 0" error is found in logs

    Returns:
        bool: True if bug is NOT present (test passed)
    """
    log.info("=" * 80)
    log.info("BUG CHECK: Multipart Part Number 0")
    log.info("Tracker: https://tracker.ceph.com/issues/68324")
    log.info("=" * 80)

    # Check RGW logs for "part number 0" error
    log.info("Checking RGW logs for 'part number 0' error...")
    try:
        log_check = utils.exec_shell_cmd(
            'journalctl -u ceph-*@rgw* --since "2 minutes ago" | grep -i "part number 0"',
            ssh_con=ssh_con
        )
        if log_check:
            log.error(f"BUG DETECTED: Found 'part number 0' error in logs:")
            log.error(log_check)
            raise TestExecError(
                "Multipart part number 0 bug detected! "
                "Part numbering should start at 1, not 0. "
                "Bug: https://tracker.ceph.com/issues/68324"
            )
    except Exception as e:
        if "part number 0" in str(e).lower():
            raise TestExecError(
                "Multipart part number 0 bug detected! "
                "Bug: https://tracker.ceph.com/issues/68324"
            )

    log.info("✓ No 'part number 0' errors found - bug not present")

    # Verify object transitioned successfully
    try:
        obj_stat = utils.exec_shell_cmd(
            f"radosgw-admin object stat --bucket={bucket_name} --object={object_key}",
            ssh_con=ssh_con
        )

        if storage_class in obj_stat:
            log.info(f"✓ Object successfully transitioned to {storage_class}")
        else:
            log.warning(f"Object may not have transitioned to {storage_class}")
    except Exception as e:
        log.warning(f"Could not verify object stat: {e}")

    log.info("BUG CHECK PASSED: Multipart part numbering is correct")
    return True


def check_etag_double_quotes_bug(s3_client, bucket_name, object_key, version_id=None):
    """
    Check for ETag double quotes bug on restored objects.

    Bug: https://tracker.ceph.com/issues/67560
    Fixed in: v21.0.0-719-g1934aadd0d

    This function verifies that ETags on restored objects have single quotes,
    not double quotes (e.g., "hash" not ""hash"").

    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the bucket
        object_key: Object key
        version_id: Optional version ID

    Raises:
        TestExecError: If ETag has double quotes (bug present)

    Returns:
        bool: True if bug is NOT present (test passed)
    """
    log.info("=" * 80)
    log.info("BUG CHECK: ETag Double Quotes on Restore")
    log.info("Tracker: https://tracker.ceph.com/issues/67560")
    log.info("=" * 80)

    try:
        # Get object head after restore
        if version_id:
            head_response = s3_client.head_object(
                Bucket=bucket_name,
                Key=object_key,
                VersionId=version_id
            )
        else:
            head_response = s3_client.head_object(
                Bucket=bucket_name,
                Key=object_key
            )

        etag = head_response.get('ETag', '')
        log.info(f"ETag after restore: {etag}")

        # Count quotes
        quote_count = etag.count('"')
        log.info(f"ETag quote count: {quote_count}")

        # Bug: ETag has double quotes like ""hash"" or ""hash-parts""
        # Expected: Single quotes like "hash" or "hash-parts"
        # A normal ETag has 2 quotes (surrounding the hash)
        # Bug adds extra quotes, so quote_count > 2
        if etag.startswith('""') or quote_count > 2:
            log.error(f"BUG DETECTED: ETag has extra quotes: {etag}")
            log.error(f"Expected format: \"hash\" but got: {etag}")
            raise TestExecError(
                f"ETag double quotes bug detected! ETag: {etag}. "
                "Bug: https://tracker.ceph.com/issues/67560"
            )

        log.info("✓ ETag format is correct (no extra quotes)")
        log.info("BUG CHECK PASSED: ETag formatting is correct")
        return True

    except ClientError as e:
        log.error(f"Error checking object: {e}")
        raise
    except TestExecError:
        raise
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        raise


def check_days_zero_restore_bug(
    s3_client, bucket_name, object_key, wait_time=60, version_id=None
):
    """
    Check for Days=0 restore bug.

    Bug: https://tracker.ceph.com/issues/67685
    Fixed in: v21.0.0-655-g1df675bb60

    This function verifies that restore requests with Days=0 are properly
    handled and don't leave objects in a broken state (stuck in ongoing-request=true).

    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the bucket
        object_key: Object key
        wait_time: Time to wait to check if stuck in ongoing state (seconds)
        version_id: Optional version ID

    Raises:
        TestExecError: If object is stuck in ongoing-request=true state

    Returns:
        bool: True if bug is NOT present (test passed)
    """
    log.info("=" * 80)
    log.info("BUG CHECK: Days=0 Restore Request")
    log.info("Tracker: https://tracker.ceph.com/issues/67685")
    log.info("=" * 80)

    try:
        # Attempt restore with Days=0
        log.info("Attempting restore with Days=0...")
        restore_params = {
            'Bucket': bucket_name,
            'Key': object_key,
            'RestoreRequest': {'Days': 0}
        }
        if version_id:
            restore_params['VersionId'] = version_id

        try:
            response = s3_client.restore_object(**restore_params)
            log.info(f"Restore response: {response}")

            # Check if object is in broken state
            time.sleep(10)
            head_params = {'Bucket': bucket_name, 'Key': object_key}
            if version_id:
                head_params['VersionId'] = version_id

            head_obj = s3_client.head_object(**head_params)
            restore_status = head_obj.get("Restore", "")

            # Bug: Object shows ongoing-request=true indefinitely
            if 'ongoing-request="true"' in restore_status:
                log.warning(f"Object in ongoing-request state, waiting {wait_time}s to verify...")
                time.sleep(wait_time)

                head_obj_2 = s3_client.head_object(**head_params)
                restore_status_2 = head_obj_2.get("Restore", "")

                if 'ongoing-request="true"' in restore_status_2:
                    log.error("BUG DETECTED: Object stuck in ongoing-request=true state")
                    log.error(f"Restore status after {wait_time}s: {restore_status_2}")
                    raise TestExecError(
                        "Days=0 restore bug detected! Object stuck in ongoing-request=true. "
                        "Bug: https://tracker.ceph.com/issues/67685"
                    )

            log.info("✓ Days=0 restore was handled correctly (not stuck in ongoing state)")

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error'].get('Message', '')

            if error_code == 'InvalidArgument' or 'Days' in error_msg:
                log.info(f"✓ Days=0 properly rejected with: {error_code}")
                log.info("This is the expected behavior (proper fix)")
            else:
                log.warning(f"Days=0 rejected with different error: {error_code} - {error_msg}")
                # Still considered a pass as long as it doesn't leave object in broken state

        log.info("BUG CHECK PASSED: Days=0 restore handled properly")
        return True

    except TestExecError:
        raise
    except Exception as e:
        log.error(f"Unexpected error during Days=0 restore check: {e}")
        raise


def verify_cloud_transition_bugs(
    s3_client,
    ssh_con,
    bucket_name,
    object_key,
    storage_class,
    version_id=None,
    check_multipart=True,
    check_etag=True,
    check_days_zero=False
):
    """
    Convenience function to run all bug checks.

    Args:
        s3_client: Boto3 S3 client
        ssh_con: SSH connection to RGW node
        bucket_name: Name of the bucket
        object_key: Object key
        storage_class: Cloud storage class
        version_id: Optional version ID
        check_multipart: Check multipart part number 0 bug
        check_etag: Check ETag double quotes bug
        check_days_zero: Check Days=0 restore bug

    Returns:
        dict: Results of each check
    """
    results = {}

    if check_multipart:
        try:
            check_multipart_part_number_bug(
                ssh_con, bucket_name, object_key, storage_class
            )
            results['multipart_part_number'] = 'PASSED'
        except Exception as e:
            log.error(f"Multipart part number check failed: {e}")
            results['multipart_part_number'] = f'FAILED: {e}'

    if check_etag:
        try:
            check_etag_double_quotes_bug(
                s3_client, bucket_name, object_key, version_id
            )
            results['etag_double_quotes'] = 'PASSED'
        except Exception as e:
            log.error(f"ETag double quotes check failed: {e}")
            results['etag_double_quotes'] = f'FAILED: {e}'

    if check_days_zero:
        try:
            check_days_zero_restore_bug(
                s3_client, bucket_name, object_key, wait_time=60, version_id=version_id
            )
            results['days_zero_restore'] = 'PASSED'
        except Exception as e:
            log.error(f"Days=0 restore check failed: {e}")
            results['days_zero_restore'] = f'FAILED: {e}'

    return results
