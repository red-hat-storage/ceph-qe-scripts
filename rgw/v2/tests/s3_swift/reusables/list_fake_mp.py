import concurrent.futures
import logging
import random
import string

from botocore.exceptions import ClientError

log = logging.getLogger()


def generate_random_content(size):
    """Generate random content of a given size."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=size))


def upload_object(client, bucket, index, object_size):
    """Upload an individual object."""
    key = f"data/N27/good/193_tasking/2024-10-31/25/compacted-part-f55a5b45-f11f-4dd7-91e0-79658ca61548-0-object-{index}"
    content = generate_random_content(object_size)
    client.put_object(Bucket=bucket, Key=key, Body=content)
    return f"Uploaded object: {key}"


def create_multipart_upload(client, bucket, index, meta_prefix):
    """Create a fake multipart upload."""
    key = f"{meta_prefix}{index}"
    client.create_multipart_upload(Bucket=bucket, Key=key)
    return f"Created multipart upload: {key}"


def test_listing_incomplete_multipart(
    rgw_client, bucket_name, meta_prefix, num_objects, meta_entries, object_size
):
    """
    Perform the following operations in parallel:
    1. Upload many objects (~10K) to a bucket.
    2. Create ~10K incomplete multipart uploads.
    3. Perform list_objects_v2 with pagination of 1000 objects.

    Parameters:
        rgw_client (boto3.client): S3 client instance.
        bucket_name (str): Name of the bucket.
        meta_prefix (str): Prefix for multipart upload objects.
        num_objects (int): Number of objects to upload/create.
        object_size (int): Size of each object in bytes.
    """
    # Use ThreadPoolExecutor without fixed max_workers
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []

        # Submit upload tasks
        log.info(f"Submitting {num_objects} upload tasks...")
        for i in range(num_objects):
            futures.append(
                executor.submit(upload_object, rgw_client, bucket_name, i, object_size)
            )

        # Submit multipart creation tasks
        log.info(f"Submitting {meta_entries} multipart creation tasks...")
        for i in range(meta_entries):
            futures.append(
                executor.submit(
                    create_multipart_upload, rgw_client, bucket_name, i, meta_prefix
                )
            )

        # Process results as they complete
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    log.info(result)
            except Exception as e:
                log.error(f"Error in task: {e}")

    log.info(
        f"Completed uploading {num_objects} objects and creating {meta_entries} fake multipart uploads."
    )

    # List objects
    log.info(f"Listing objects in the bucket '{bucket_name}'...")
    paginator = rgw_client.get_paginator("list_objects_v2")
    operation_parameters = {"Bucket": bucket_name, "MaxKeys": 1000}
    try:
        for page in paginator.paginate(**operation_parameters):
            if "Contents" in page:
                for obj in page["Contents"]:
                    log.info(f"Key: {obj['Key']} | Size: {obj['Size']} bytes")
            else:
                log.info("No objects found in the bucket.")
    except ClientError as e:
        log.error(f"Error listing objects: {e}")
