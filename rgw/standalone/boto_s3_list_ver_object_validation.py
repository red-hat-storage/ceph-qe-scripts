import os
import sys
import time

import boto3

# ---------------- CONFIG ----------------
BUCKET_NAME = os.environ.get("BUCKET_NAME", "25m-bkt-p2-1")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", f"list_versions_validate_{BUCKET_NAME}.log")
ENDPOINT = os.environ.get("S3_ENDPOINT", "http://10.1.172.231:5000")
LOG_EVERY = int(os.environ.get("LOG_EVERY", "100000"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50000"))
# ----------------------------------------

s3 = boto3.client("s3", endpoint_url=ENDPOINT)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, file=sys.stderr, flush=True)


def validate_version(obj):
    """Validate a specific version of an object."""
    size = obj["Size"]
    storage_class = obj.get("StorageClass", "STANDARD")
    expected_sc = "STANDARD" if size < 1048576 else "ERASURE"
    status = "ERROR" if expected_sc != str(storage_class) else "PASS"

    return (
        f"Object: {obj['Key']}\t"
        f"VersionId: {obj['VersionId']}\t"
        f"IsLatest: {obj.get('IsLatest', False)}\t"
        f"Size: {size}\t"
        f"StorageClass: {storage_class}\t"
        f"Expected: {expected_sc}\t"
        f"Validation: {status}\n"
    )


def main():
    log(f"Starting versioned validation for bucket={BUCKET_NAME}")
    processed = 0
    buffer = []

    paginator = s3.get_paginator("list_object_versions")

    with open(OUTPUT_FILE, "w") as f:
        for page in paginator.paginate(
            Bucket=BUCKET_NAME, PaginationConfig={"PageSize": 1000}
        ):
            # Validate every actual object version
            for obj in page.get("Versions", []):
                buffer.append(validate_version(obj))
                processed += 1

                if len(buffer) >= BATCH_SIZE:
                    f.writelines(buffer)
                    buffer.clear()

                if processed % LOG_EVERY == 0:
                    log(f"Processed {processed} versions...")

        # final flush
        if buffer:
            f.writelines(buffer)

    log(f"Completed. Total versions processed={processed}. Results in {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
