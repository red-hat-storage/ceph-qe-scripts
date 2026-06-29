import hashlib
import json
import logging
import os
import random
import time
import timeit
from urllib import parse as urlparse

import boto3
import v2.lib.manage_data as manage_data
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import ConfigOpts

log = logging.getLogger()


def store_object_checksum(s3_client, bucket_name, object_key, version_id=None):
    """
    Store original object metadata, content length and MD5 checksum before transition.

    :param s3_client: boto3 S3 client
    :param bucket_name: Bucket name
    :param object_key: Object key
    :param version_id: Version ID (optional)
    :return: Dictionary with object metadata
    """
    try:
        # Download object and calculate MD5
        download_path = f"original-{object_key}"
        s3_client.download_file(
            Bucket=bucket_name,
            Key=object_key,
            Filename=download_path,
            ExtraArgs={"VersionId": version_id} if version_id else None,
        )

        # Calculate MD5 checksum
        md5_hash = hashlib.md5()
        with open(download_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
        md5_checksum = md5_hash.hexdigest()

        # Get content length from file
        content_length = os.path.getsize(download_path)

        # Clean up downloaded file
        os.remove(download_path)

        metadata = {
            "MD5": md5_checksum,
            "ContentLength": content_length,
            "VersionId": version_id,
        }

        log.info(
            f"Stored metadata for {object_key} (version: {version_id}): "
            f"MD5={metadata['MD5']}, Size={metadata['ContentLength']} bytes"
        )

        return metadata

    except ClientError as e:
        log.error(f"Failed to get object metadata for {object_key}: {e}")
        raise


def verify_object_checksum(
    s3_client, bucket_name, object_key, version_id, original_metadata, download_path
):
    """
    Verify restored object matches original using MD5 checksum and content length.

    :param s3_client: boto3 S3 client
    :param bucket_name: Bucket name
    :param object_key: Object key
    :param version_id: Version ID
    :param original_metadata: Dictionary with original metadata (from store_object_checksum)
    :param download_path: Path to the downloaded restored object
    :raises TestExecError: If checksums don't match
    """
    try:
        # Calculate MD5 checksum of restored object
        md5_hash = hashlib.md5()
        with open(download_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
        restored_md5 = md5_hash.hexdigest()

        # Get content length from file
        restored_size = os.path.getsize(download_path)

        # Compare MD5
        if original_metadata["MD5"] != restored_md5:
            raise TestExecError(
                f"MD5 checksum mismatch for {object_key} (version: {version_id})! "
                f"Original: {original_metadata['MD5']}, Restored: {restored_md5}"
            )

        # Compare ContentLength
        if original_metadata["ContentLength"] != restored_size:
            raise TestExecError(
                f"ContentLength mismatch for {object_key} (version: {version_id})! "
                f"Original: {original_metadata['ContentLength']}, Restored: {restored_size}"
            )

        log.info(
            f"✓ Checksum verification passed for {object_key} (version: {version_id}): "
            f"MD5={restored_md5}, Size={restored_size} bytes"
        )

    except ClientError as e:
        log.error(f"Failed to verify object checksum for {object_key}: {e}")
        raise


def restore_s3_object(
    s3_client,
    each_user,
    config,
    bucket_name,
    object_key,
    version_id=None,
    days=7,
    max_wait_time=600,
    poll_interval=30,
    original_metadata=None,
):
    """
    Restore an S3 object, verify restore attributes, download and verify checksum.

    :param bucket_name: Name of the S3 bucket.
    :param object_key: Key of the S3 object.
    :param version_id: Version ID of the object (optional).
    :param days: Number of days to keep the restored object.
    :param max_wait_time: Maximum time to wait for restore completion
                          (seconds). Default 600 (10 min).
    :param poll_interval: Time between restore status checks (seconds). Default 30.
    :param original_metadata: Original object metadata for checksum verification (optional).
    """
    try:
        # Initiate restore request
        restore_request = {
            "Days": days,
        }

        if version_id:
            response = s3_client.restore_object(
                Bucket=bucket_name,
                Key=object_key,
                VersionId=version_id,
                RestoreRequest=restore_request,
            )
        else:
            response = s3_client.restore_object(
                Bucket=bucket_name, Key=object_key, RestoreRequest=restore_request
            )

        log.info("Restore initiated: %s", response)

        # Validate restore attributes
        head_response = s3_client.head_object(
            Bucket=bucket_name, Key=object_key, VersionId=version_id
        )
        log.info(f" the head_object is  {head_response}")
        restore_status = head_response.get("Restore", "")
        if 'ongoing-request="false"' in restore_status:
            log.info("Object is already successfully restored.")
        else:
            log.info("Restore status: %s", restore_status)

            # Wait for restore to complete
            elapsed = 0
            log.info(f"Waiting for restore to complete (max {max_wait_time}s)...")
            while elapsed < max_wait_time:
                time.sleep(poll_interval)
                elapsed += poll_interval

                head_response = s3_client.head_object(
                    Bucket=bucket_name, Key=object_key, VersionId=version_id
                )
                restore_status = head_response.get("Restore", "")

                if 'ongoing-request="false"' in restore_status:
                    log.info(f"Object restore completed successfully after {elapsed}s.")
                    break

                log.info(
                    f"Restore still in progress... "
                    f"waiting {poll_interval}s (elapsed: {elapsed}s)"
                )
            else:
                log.warning(
                    f"Restore did not complete within {max_wait_time}s, "
                    f"attempting download anyway..."
                )

        # Download the restored object
        download_path = f"restored-{object_key}"
        s3_client.download_file(
            Bucket=bucket_name,
            Key=object_key,
            Filename=download_path,
            ExtraArgs={"VersionId": version_id} if version_id else None,
        )
        log.info(f"Restored object downloaded to {download_path}.")

        # Verify checksum if original metadata provided
        if original_metadata:
            log.info(f"Verifying checksum for restored object {object_key}...")
            verify_object_checksum(
                s3_client,
                bucket_name,
                object_key,
                version_id,
                original_metadata,
                download_path,
            )
            log.info(f"✓ Checksum verification completed successfully for {object_key}")

    except ClientError as e:
        log.error(f"Temporary restore failed for {object_key}: {e}")
        raise


def permanent_restore_s3_object(
    s3_client,
    bucket_name,
    object_key,
    version_id=None,
    target_storage_class="STANDARD",
    original_metadata=None,
    max_wait_time=600,
    poll_interval=30,
):
    """
    Permanently restore an S3 object using empty RestoreRequest (AWS permanent restore).

    :param s3_client: boto3 S3 client
    :param bucket_name: Bucket name
    :param object_key: Object key
    :param version_id: Version ID (optional)
    :param target_storage_class: Target storage class (default: STANDARD) - unused for permanent restore
    :param original_metadata: Original object metadata for checksum verification (optional)
    :param max_wait_time: Maximum time to wait for restore completion (seconds). Default 600 (10 min).
    :param poll_interval: Time between restore status checks (seconds). Default 30.
    """
    try:
        log.info(f"Starting permanent restore for {object_key} (version: {version_id})")

        # Step 1: Initiate permanent restore with empty RestoreRequest
        # AWS CLI equivalent: aws s3api restore-object --bucket <bucket> --key <key> --restore-request {}
        log.info(f"Issuing permanent restore request for {object_key}...")
        restore_request = {}  # Empty dict = permanent restore (no Days parameter)

        restore_params = {
            "Bucket": bucket_name,
            "Key": object_key,
            "RestoreRequest": restore_request,
        }
        if version_id:
            restore_params["VersionId"] = version_id

        restore_start_time = time.time()

        try:
            s3_client.restore_object(**restore_params)
            log.info(f"Permanent restore request initiated for {object_key}")
        except ClientError as e:
            # Object may already be restored
            if e.response["Error"]["Code"] == "RestoreAlreadyInProgress":
                log.info(f"Restore already in progress for {object_key}")
            else:
                raise

        # Step 2: Wait for restore to complete and measure time
        log.info(f"Waiting for permanent restore to complete (no time limit)...")
        elapsed = 0
        while True:
            head_params = {"Bucket": bucket_name, "Key": object_key}
            if version_id:
                head_params["VersionId"] = version_id

            head_response = s3_client.head_object(**head_params)
            restore_status = head_response.get("Restore", "")

            # For permanent restore, check if object is accessible (no ongoing-request)
            if restore_status and 'ongoing-request="false"' in restore_status:
                restore_time = time.time() - restore_start_time
                log.info(
                    f"✓ Permanent restore completed successfully after {restore_time:.2f} seconds"
                )
                break
            elif not restore_status:
                # No Restore header means object is already in STANDARD storage
                restore_time = time.time() - restore_start_time
                log.info(
                    f"✓ Object {object_key} is already restored (no Restore header). "
                    f"Time: {restore_time:.2f} seconds"
                )
                break

            log.info(
                f"Restore still in progress... waiting {poll_interval}s (elapsed: {elapsed}s)"
            )
            time.sleep(poll_interval)
            elapsed += poll_interval

        # Step 3: Download and verify checksum
        log.info(f"Downloading permanently restored object {object_key}...")
        download_path = f"permanently-restored-{object_key}"
        s3_client.download_file(
            Bucket=bucket_name,
            Key=object_key,
            Filename=download_path,
            ExtraArgs={"VersionId": version_id} if version_id else None,
        )
        log.info(f"✓ Permanently restored object downloaded to {download_path}")

        # Verify checksum
        if original_metadata:
            log.info(
                f"Verifying checksum for permanently restored object {object_key}..."
            )
            verify_object_checksum(
                s3_client,
                bucket_name,
                object_key,
                version_id,
                original_metadata,
                download_path,
            )
            log.info(
                f"✓ Permanent restore checksum verification passed for {object_key}"
            )

        # Verify final storage class
        head_params = {"Bucket": bucket_name, "Key": object_key}
        if version_id:
            head_params["VersionId"] = version_id
        head_response = s3_client.head_object(**head_params)
        restored_storage_class = head_response.get("StorageClass", "STANDARD")
        log.info(f"Object {object_key} final storage class: {restored_storage_class}")

        return download_path

    except ClientError as e:
        log.error(f"Permanent restore failed for {object_key}: {e}")
        raise


def check_restore_expiry(
    s3_client, each_user, config, bucket_name, object_key, version_id=None
):
    """
    Check if the restored object is no longer accessible after the restore period.

    :param s3_client: The S3 client instance.
    :param bucket_name: Name of the S3 bucket.
    :param object_key: Key of the S3 object.
    :param version_id: Version ID of the object (optional).
    """
    try:
        download_path = f"expired-{object_key}"
        s3_client.download_file(
            Bucket=bucket_name,
            Key=object_key,
            Filename=download_path,
            ExtraArgs={"VersionId": version_id} if version_id else None,
        )
        raise Exception(
            "Unexpected: Object is still accessible after the restore period."
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            log.info("Restore has expired and the object is no longer accessible.")
        elif e.response["Error"]["Code"] == "InvalidObjectState":
            log.info(
                "Restore has expired, and the object is no longer in a restored state."
            )
        else:
            log.info("Error while checking restore expiration: %s", e)
