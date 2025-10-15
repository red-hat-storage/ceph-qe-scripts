import os
import sys
import time

import boto3

# ---------------- CONFIG ----------------
BUCKET_NAME = os.environ.get("BUCKET_NAME", "test-1")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", f"list_validate_{BUCKET_NAME}.log")
ENDPOINT = os.environ.get("S3_ENDPOINT", "http://10.1.172.231:5000")
LOG_EVERY = int(os.environ.get("LOG_EVERY", "100000"))  # log every N objects
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50000"))  # buffer before writing
# ----------------------------------------

s3 = boto3.client("s3", endpoint_url=ENDPOINT)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, file=sys.stderr, flush=True)


def validate_object(obj):
    """Validate directly from list_objects_v2 metadata"""
    size = obj["Size"]
    storage_class = obj.get("StorageClass", "STANDARD")
    expected_sc = "STANDARD" if size < 1048576 else "ERASURE"
    # expected_sc = "STANDARD"
    # expected_sc = "ERASURE"
    status = "ERROR" if expected_sc != str(storage_class) else "PASS"

    return (
        f"Object: {obj['Key']}\t"
        f"size: {size}\t"
        f"StorageClass: {storage_class}\t"
        f"Expected: {expected_sc}\t"
        f"Validation: {status}\n"
    )


def main():
    log(f"Starting validation for bucket={BUCKET_NAME}")
    processed = 0
    buffer = []

    paginator = s3.get_paginator("list_objects_v2")

    with open(OUTPUT_FILE, "w") as f:
        for page in paginator.paginate(
            Bucket=BUCKET_NAME, PaginationConfig={"PageSize": 1000}
        ):
            for obj in page.get("Contents", []):
                buffer.append(validate_object(obj))
                processed += 1

                if len(buffer) >= BATCH_SIZE:
                    f.writelines(buffer)
                    buffer.clear()

                if processed % LOG_EVERY == 0:
                    log(f"Processed {processed} objects...")

        # final flush
        if buffer:
            f.writelines(buffer)

    log(f"Completed. Total processed={processed}. Results in {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
