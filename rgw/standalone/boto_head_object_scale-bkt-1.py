import os
import sys
import time

import boto3

BUCKET_NAME = os.environ.get("BUCKET_NAME", "scale-bkt-1")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", f"50Mbotoobj_validate_{BUCKET_NAME}")
LOG_EVERY = int(os.environ.get("LOG_EVERY", "100"))

session = boto3.session.Session(
    aws_access_key_id="s3cmduser",
    aws_secret_access_key="s3cmduser",
    region_name="us-east-1",
)
s3 = session.client("s3", endpoint_url="http://10.1.172.232:5000")


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, file=sys.stderr, flush=True)


def validate(meta, key):
    size = int(meta.get("ContentLength", 0))
    storage_class = meta.get("StorageClass", "STANDARD")
    expected_sc = "STANDARD" if size < 1048576 else "ERASURE"
    status = "ERROR" if expected_sc != str(storage_class) else "PASS"
    return f"Object: {key}\tsize: {size}\tStorageClass: {storage_class}\tExpected: {expected_sc}\tValidation: {status}\n"


def main():
    log(f"Starting head-object validation for bucket={BUCKET_NAME}")
    processed = 0
    paginator = s3.get_paginator("list_objects_v2")

    with open(OUTPUT_FILE, "w") as f:
        for page in paginator.paginate(Bucket=BUCKET_NAME):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                meta = s3.head_object(Bucket=BUCKET_NAME, Key=key)
                f.write(validate(meta, key))
                processed += 1
                if processed % LOG_EVERY == 0:
                    log(f"Processed {processed} objects...")

    log(f"Completed. Total processed={processed}. Results written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
