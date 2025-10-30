"""
Downloads objects from S3 with concurrency
Verifies downloaded size
Calculates total throughput (MB/s) and object throughput (ops/sec) at the end
Archives downloaded objects
Logs summary only at the end
"""

import logging
import os
import shutil
import sys
import time

import boto3
from boto3.s3.transfer import S3Transfer, TransferConfig
from botocore.config import Config

# ---------------- CONFIG ----------------
BUCKET_NAME = os.environ.get("BUCKET_NAME", "scale-multipart-1")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", f"./{BUCKET_NAME}_obj_download")
ARCHIVE_DIR = os.environ.get("ARCHIVE_DIR", f"{OUTPUT_DIR}/archive")
ENDPOINT = os.environ.get("S3_ENDPOINT", "http://10.1.172.231:5000")
MAX_THREADS = int(os.environ.get("MAX_THREADS", "64"))
MAX_SIZE_MB = int(
    os.environ.get("MAX_SIZE_MB", "5000")
)  # skip objects larger than this in MB
BATCH_SIZE_MB = int(
    os.environ.get("BATCH_SIZE_MB", "5000")
)  # max MB per batch for archiving
SUBDIR_PREFIXES = {
    "multipart-obj": "data/scale/multipart-obj-"
}  # logical prefix -> S3 key prefix

LOG_FILE = os.path.join(OUTPUT_DIR, f"{BUCKET_NAME}_download_summary.log")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)

# ---------------- LOGGER ----------------
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)
log = logging.getLogger()

# ---------------- S3 INIT ----------------
def init_s3():
    s3 = boto3.client(
        "s3", endpoint_url=ENDPOINT, config=Config(max_pool_connections=MAX_THREADS)
    )
    transfer_config = TransferConfig(max_concurrency=MAX_THREADS)
    transfer = S3Transfer(s3, config=transfer_config)
    return s3, transfer


# ---------------- PROCESS BATCH ----------------
def process_batch(objects, batch_number, logical_prefix):
    """Download and archive a batch of objects"""
    s3, transfer = init_s3()
    batch_dir = os.path.join(OUTPUT_DIR, f"{logical_prefix}_batch_{batch_number}")
    os.makedirs(batch_dir, exist_ok=True)

    processed = 0
    total_bytes = 0

    for key, obj_size in objects:
        local_path = os.path.join(batch_dir, os.path.basename(key))
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        try:
            transfer.download_file(BUCKET_NAME, key, local_path)
            local_size = os.path.getsize(local_path)
            if local_size != obj_size:
                log.warning(f"Size mismatch: {key} S3={obj_size}B, local={local_size}B")
            processed += 1
            total_bytes += obj_size
        except Exception as e:
            log.error(f"ERROR downloading {key}: {e}")

    # Archive batch
    archive_path = os.path.join(
        ARCHIVE_DIR, f"{logical_prefix}_batch_{batch_number}.tar.gz"
    )
    shutil.make_archive(archive_path.replace(".tar.gz", ""), "gztar", batch_dir)
    shutil.rmtree(batch_dir)

    return processed, total_bytes


# ---------------- WORKER ----------------
def worker(logical_prefix, key_prefix, max_batch_mb=BATCH_SIZE_MB):
    s3, _ = init_s3()
    paginator = s3.get_paginator("list_objects_v2")
    processed_total = 0
    bytes_total = 0
    batch_objects = []
    batch_bytes = 0
    batch_count = 1

    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=key_prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            obj_size = obj["Size"]

            if obj_size / (1024 * 1024) > MAX_SIZE_MB:
                continue

            batch_objects.append((key, obj_size))
            batch_bytes += obj_size / (1024 * 1024)

            if batch_bytes >= max_batch_mb:
                p, b = process_batch(batch_objects, batch_count, logical_prefix)
                processed_total += p
                bytes_total += b
                batch_count += 1
                batch_objects = []
                batch_bytes = 0

    # Process remaining objects
    if batch_objects:
        p, b = process_batch(batch_objects, batch_count, logical_prefix)
        processed_total += p
        bytes_total += b

    return processed_total, bytes_total


# ---------------- MAIN ----------------
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    total_processed = 0
    total_bytes = 0
    start_time = time.time()

    for logical_prefix, key_prefix in SUBDIR_PREFIXES.items():
        processed, bytes_downloaded = worker(logical_prefix, key_prefix)
        total_processed += processed
        total_bytes += bytes_downloaded

    end_time = time.time()
    duration = end_time - start_time

    throughput_MBps = total_bytes / duration / (1024 * 1024) if duration > 0 else 0
    object_throughput = total_processed / duration if duration > 0 else 0

    log.info(f"All prefixes completed. Total objects={total_processed}")
    log.info(
        f"Total bytes downloaded: {total_bytes} bytes ({total_bytes / (1024*1024*1024):.2f} GB)"
    )
    log.info(f"Total time: {duration:.2f} sec")
    log.info(f"Bandwidth: {throughput_MBps:.2f} MB/s")
    log.info(f"Object throughput: {object_throughput:.2f} ops/sec")

    print("\n✅ Download Summary:")
    print(f"Total objects downloaded: {total_processed}")
    print(f"Total data downloaded  : {total_bytes / (1024*1024*1024):.2f} GB")
    print(f"Time taken             : {duration:.2f} sec")
    print(f"Bandwidth              : {throughput_MBps:.2f} MB/s")
    print(f"Object throughput      : {object_throughput:.2f} ops/sec")
    print(f"Log file               : {LOG_FILE}")


if __name__ == "__main__":
    main()
