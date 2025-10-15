#!/usr/bin/env python3
import os
import random
import string

import boto3

# ---------------- CONFIGURATION ----------------
BUCKET_NAME = os.environ.get("BUCKET_NAME", "50m-bkt-p2-1")
OBJECT_COUNT = int(os.environ.get("OBJECT_COUNT", "50000000"))  # 50 Million
STORAGE_CLASS = os.environ.get("STORAGE_CLASS", "ERASURE")  # Ceph RGW Erasure
PREFIX = os.environ.get("PREFIX", "obj_")

S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://10.1.172.231:5000")
ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "s3cmduser")
SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "your_secret_key")

# ------------------------------------------------

session = boto3.session.Session()
s3 = session.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
)


def random_bytes(size_kb):
    """Generate random bytes of given KB size"""
    return "".join(
        random.choices(string.ascii_letters + string.digits, k=size_kb * 1024)
    ).encode("utf-8")


print(
    f"Starting upload of {OBJECT_COUNT} objects to bucket '{BUCKET_NAME}' with storage class '{STORAGE_CLASS}'..."
)

for i in range(1, OBJECT_COUNT + 1):
    key = f"{PREFIX}{i:08d}"

    # Decide size: 95% chance 4KB, 5% chance 1MB
    size_kb = 4 if random.random() < 0.95 else 1024
    data = random_bytes(size_kb)

    s3.put_object(Bucket=BUCKET_NAME, Key=key, Body=data, StorageClass=STORAGE_CLASS)

    if i % 1000 == 0:
        print(f"Uploaded {i} objects...")

print(
    f"\n Completed: {OBJECT_COUNT} objects uploaded to '{BUCKET_NAME}' with storage class '{STORAGE_CLASS}'."
)
