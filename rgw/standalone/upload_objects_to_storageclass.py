#!/usr/bin/env python3
import math
import os
import random
import string
import time

import boto3

# ---------------- CONFIGURATION ----------------
BUCKET_NAME = os.environ.get("BUCKET_NAME", "50m-bkt-p2-1")
OBJECT_COUNT = int(os.environ.get("OBJECT_COUNT", "50000000"))  # 50 Million
STORAGE_CLASS = os.environ.get("STORAGE_CLASS", "ERASURE")  # Ceph RGW Erasure
PREFIX = os.environ.get("PREFIX", "obj_")

S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://10.1.172.231:5000")
ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "s3cmduser")
SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "s3cmduser")

MAX_THREADS = 64
LOG_FILE = f"{BUCKET_NAME}_upload_multipart.log"

# Multipart config
MULTIPART_SIZE_MB = 16.5
PART_SIZE_MB = 5  # each part 5MB

# ------------------------------------------------
session = boto3.session.Session()
s3 = session.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
)


def random_bytes(size_kb):
    return "".join(
        random.choices(string.ascii_letters + string.digits, k=size_kb * 1024)
    ).encode("utf-8")


def multipart_upload(bucket, key, size_mb, part_size_mb, storage_class):
    """Perform multipart upload"""
    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key, StorageClass=storage_class)
    upload_id = mpu["UploadId"]
    parts = []
    total_parts = math.ceil(size_mb / part_size_mb)

    for i in range(1, total_parts + 1):
        part_size = min(part_size_mb, size_mb - (i - 1) * part_size_mb) * 1024 * 1024
        part_data = random_bytes(part_size // 1024)
        part = s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=i, UploadId=upload_id, Body=part_data
        )
        parts.append({"ETag": part["ETag"], "PartNumber": i})

    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": parts},
    )
    return size_mb * 1024 * 1024  # return bytes uploaded


print(
    f"Starting upload of {OBJECT_COUNT} objects to bucket '{BUCKET_NAME}' with storage class '{STORAGE_CLASS}'..."
)
with open(LOG_FILE, "w") as log:
    log.write(
        f"Bucket: {BUCKET_NAME}, StorageClass: {STORAGE_CLASS}\nEndpoint: {S3_ENDPOINT}\nThreads: {MAX_THREADS}\nTotal Objects: {OBJECT_COUNT}\n"
    )

    total_bytes = 0
    start_time = time.time()

    for i in range(1, OBJECT_COUNT + 1):
        key = f"{PREFIX}{i:08d}"
        r = random.random()
        if r < 0.90:
            # 4 KB
            size_kb = 4
            data = random_bytes(size_kb)
            s3.put_object(
                Bucket=BUCKET_NAME, Key=key, Body=data, StorageClass=STORAGE_CLASS
            )
            total_bytes += len(data)
        elif r < 0.98:
            # 1 MB
            size_kb = 1024
            data = random_bytes(size_kb)
            s3.put_object(
                Bucket=BUCKET_NAME, Key=key, Body=data, StorageClass=STORAGE_CLASS
            )
            total_bytes += len(data)
        else:
            # Multipart 16.5 MB
            total_bytes += multipart_upload(
                BUCKET_NAME, key, MULTIPART_SIZE_MB, PART_SIZE_MB, STORAGE_CLASS
            )

        if i % 1000 == 0:
            elapsed = time.time() - start_time
            throughput = i / elapsed
            bandwidth = (total_bytes / (1024 * 1024)) / elapsed
            msg = f"Uploaded {i}/{OBJECT_COUNT} objects | Throughput: {throughput:.2f} obj/s | Bandwidth: {bandwidth:.2f} MB/s"
            print(msg)
            log.write(msg + "\n")

    total_time = time.time() - start_time
    total_mb = total_bytes / (1024 * 1024)
    avg_throughput = OBJECT_COUNT / total_time
    avg_bandwidth = total_mb / total_time

    summary = f"\nCompleted upload of {OBJECT_COUNT} objects to '{BUCKET_NAME}' in {total_time:.2f} seconds.\nTotal Data: {total_mb:.2f} MB\nAverage Throughput: {avg_throughput:.2f} obj/s\nAverage Bandwidth: {avg_bandwidth:.2f} MB/s\n"
    print(summary)
    log.write(summary)
