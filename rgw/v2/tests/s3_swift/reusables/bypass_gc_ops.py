"""
Bypass GC Operations - Reusable Functions

This module provides reusable functions for bypass-gc related operations,
including server-side copy, bypass-gc deletion, and object integrity verification.

Owner: Vidushi Mishra
Email: vmishra@redhat.com
"""

import json
import logging
import os
import time

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.utils.utils import HttpResponseParser

log = logging.getLogger()


def verify_object_integrity(
    bucket, s3_object_name, original_md5, test_data_path, version_id=None
):
    """
    Verify object integrity by downloading and comparing MD5 checksums.

    Args:
        bucket: S3 bucket object
        s3_object_name: Name of the object
        original_md5: Original MD5 checksum
        test_data_path: Path to test data directory
        version_id: Optional version ID for versioned objects

    Returns:
        bool: True if integrity check passes, raises exception otherwise
    """
    log.info(f"Verifying object integrity: {s3_object_name}")
    download_name = f"{s3_object_name}.verify.download"
    download_path = os.path.join(test_data_path, download_name)

    try:
        # Download object
        download_args = [s3_object_name, download_path]
        if version_id:
            download_args.append({"VersionId": version_id})
            log.info(f"Downloading version: {version_id}")

        s3lib.resource_op(
            {"obj": bucket, "resource": "download_file", "args": download_args}
        )

        # download_file returns None on success, raises exception on failure
        if not os.path.exists(download_path):
            raise TestExecError(f"Failed to download object: {s3_object_name}")

        # Compare MD5
        downloaded_md5 = utils.get_md5(download_path)
        log.info(f"Original MD5:   {original_md5}")
        log.info(f"Downloaded MD5: {downloaded_md5}")

        if str(original_md5) != str(downloaded_md5):
            raise TestExecError(
                f"MD5 mismatch for {s3_object_name}: expected {original_md5}, got {downloaded_md5}"
            )

        log.info("MD5 verification passed")
        return True

    finally:
        # Cleanup downloaded file
        if os.path.exists(download_path):
            os.remove(download_path)


def perform_server_side_copy(src_bucket, dst_bucket, object_name, version_id=None):
    """
    Perform server-side copy from source to destination bucket.

    Args:
        src_bucket: Source bucket object
        dst_bucket: Destination bucket object
        object_name: Name of the object to copy
        version_id: Optional version ID to copy specific version

    Returns:
        dict: Copy response
    """
    copy_source = {"Bucket": src_bucket.name, "Key": object_name}

    if version_id:
        copy_source["VersionId"] = version_id
        log.info(
            f"Copying version {version_id} from {src_bucket.name} to {dst_bucket.name}"
        )
    else:
        log.info(f"Copying {object_name} from {src_bucket.name} to {dst_bucket.name}")

    dst_object = s3lib.resource_op(
        {"obj": dst_bucket, "resource": "Object", "args": [object_name]}
    )

    copy_response = dst_object.copy_from(CopySource=copy_source)

    response = HttpResponseParser(copy_response)
    if response.status_code == 200:
        log.info("Server-side copy successful")
    else:
        raise TestExecError(f"Server-side copy failed: {response.status_code}")

    return copy_response


def delete_bucket_with_bypass_gc(bucket_name):
    """
    Delete bucket using radosgw-admin with --bypass-gc flag.

    Args:
        bucket_name: Name of the bucket to delete

    Returns:
        bool: True if deletion successful
    """
    log.info(f"Deleting bucket with bypass-gc: {bucket_name}")
    cmd = f"radosgw-admin bucket rm --bucket={bucket_name} --bypass-gc --purge-objects"

    try:
        output = utils.exec_shell_cmd(cmd)
        log.info(f"Bypass-GC deletion output: {output}")

        # Verify bucket is deleted
        time.sleep(2)
        bucket_list_output = utils.exec_shell_cmd("radosgw-admin bucket list")
        bucket_list = json.loads(bucket_list_output)

        if bucket_name in bucket_list:
            raise TestExecError(
                f"Bucket {bucket_name} still exists after bypass-gc deletion"
            )

        log.info(f"Bucket {bucket_name} successfully deleted with bypass-gc")
        return True

    except Exception as e:
        log.error(f"Error during bypass-gc deletion: {e}")
        raise


def enable_versioning(rgw_conn, bucket_name):
    """
    Enable versioning on a bucket.

    Args:
        rgw_conn: RGW connection object
        bucket_name: Name of the bucket

    Returns:
        bool: True if versioning enabled successfully
    """
    log.info(f"Enabling versioning on bucket: {bucket_name}")
    bucket_versioning = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "BucketVersioning", "args": [bucket_name]}
    )
    version_enable_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "enable", "args": None}
    )

    response = HttpResponseParser(version_enable_status)
    if response.status_code != 200:
        raise TestExecError(f"Failed to enable versioning: {response.status_code}")

    log.info("Versioning enabled successfully")
    return True


def get_object_versions(bucket, object_name):
    """
    Get all versions of an object.

    Args:
        bucket: S3 bucket object
        object_name: Name of the object

    Returns:
        list: List of object versions
    """
    versions = list(bucket.object_versions.filter(Prefix=object_name))
    log.info(f"Found {len(versions)} versions for object {object_name}")
    for idx, version in enumerate(versions):
        log.info(f"  Version {idx + 1}: {version.version_id}")
    return versions
