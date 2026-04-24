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
):
    """
    Restore an S3 object, verify restore attributes, and download the restored object.

    :param bucket_name: Name of the S3 bucket.
    :param object_key: Key of the S3 object.
    :param version_id: Version ID of the object (optional).
    :param days: Number of days to keep the restored object.
    :param max_wait_time: Maximum time to wait for restore completion
                          (seconds). Default 600 (10 min).
    :param poll_interval: Time between restore status checks (seconds). Default 30.
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

    except ClientError as e:
        log.info("Error: %s", e)


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
