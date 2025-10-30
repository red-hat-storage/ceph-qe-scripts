"""
 1. Downloads objects from S3 with concurrency
 2. Verifies the downloaded size against the S3 object size
 3. Logs the storage class of each object
 4. Calculates throughput (MB/s) and object throughput (ops/sec)
 5. Archives downloaded objects.
 6. Writes all info to a log file and prints a summary.
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
BUCKET_NAME = os.environ.get("BUCKET_NAME", "scale-bkt-1")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", f"./{BUCKET_NAME}_obj_download")
ARCHIVE_DIR = os.environ.get("ARCHIVE_DIR", f"{OUTPUT_DIR}/archive")
ENDPOINT = os.environ.get("S3_ENDPOINT", "http://10.1.172.231:5000")
MAX_THREADS = int(os.environ.get("MAX_THREADS", "64"))
LOG_EVERY = int(os.environ.get("LOG_EVERY", "1000"))
MAX_SIZE = int(
    os.environ.get("MAX_SIZE", "5000")
)  # skip objects larger than this in bytes
SUBDIR_DEPTHS = {
    "1Mobject": 2,
    "20Mobject": 3,
    "50Mobject": 4,
}  # subdir depth for spreading
SUBDIR_PREFIXES = {
    "1Mobject": "data/scale/1Mobject",
    "20Mobject": "data/scale/20Mobject",
    "50Mobject": "data/scale/50Mobject",
}  # logical prefix -> S3 key prefix

LOG_FILE = os.path.join(OUTPUT_DIR, f"{BUCKET_NAME}_download.log")

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


# ---------------- INIT S3 ----------------
def init_s3():
    s3 = boto3.client(
        "s3", endpoint_url=ENDPOINT, config=Config(max_pool_connections=MAX_THREADS)
    )
    transfer_config = TransferConfig(max_concurrency=MAX_THREADS)
    transfer = S3Transfer(s3, config=transfer_config)
    return s3, transfer


# ---------------- SAFE LOCAL PATH ----------------
def safe_local_path(key):
    base_name = os.path.basename(key)  # e.g., '1Mobject-12345'
    if "-" not in base_name:
        raise ValueError(f"Unexpected object key format: {key}")
    prefix = base_name.split("-")[0]  # '1Mobject'
    numeric_part = base_name.split("-")[-1]
    depth = SUBDIR_DEPTHS.get(prefix, 3)
    subdirs = os.path.join(*numeric_part[:depth])
    local_path = os.path.join(OUTPUT_DIR, prefix, subdirs, base_name)
    prefix_dir = os.path.join(OUTPUT_DIR, prefix)
    return local_path, prefix_dir


# ---------------- WORKER ----------------
def worker(logical_prefix, key_prefix):
    s3, transfer = init_s3()
    processed = 0
    total_bytes = 0
    paginator = s3.get_paginator("list_objects_v2")

    prefix_dir = os.path.join(OUTPUT_DIR, logical_prefix)
    log.info(f"[{logical_prefix}] Starting download...")

    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=key_prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            obj_size = obj["Size"]
            if obj_size > MAX_SIZE:
                continue
            local_path, _ = safe_local_path(key)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            try:
                transfer.download_file(BUCKET_NAME, key, local_path)
                processed += 1
                total_bytes += obj_size

                # Verify downloaded size
                local_size = os.path.getsize(local_path)
                if local_size != obj_size:
                    log.warning(
                        f"[{logical_prefix}] Size mismatch for {key}: S3={obj_size}, local={local_size}"
                    )

                storage_class = obj.get("StorageClass", "STANDARD")
                log.info(
                    f"[{logical_prefix}] Object {key} downloaded from storage class {storage_class}"
                )

            except Exception as e:
                log.error(f"[{logical_prefix}] ERROR downloading {key}: {e}")

            if processed % LOG_EVERY == 0 and processed > 0:
                log.info(f"[{logical_prefix}] Processed {processed} objects...")

    # Archive prefix
    if os.path.exists(prefix_dir):
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        archive_path = os.path.join(ARCHIVE_DIR, f"{logical_prefix}.tar.gz")
        log.info(f"[{logical_prefix}] Archiving {prefix_dir} -> {archive_path}")
        shutil.make_archive(
            archive_path.replace(".tar.gz", ""), "gztar", OUTPUT_DIR, logical_prefix
        )
        shutil.rmtree(prefix_dir)
        log.info(f"[{logical_prefix}] Archived and cleaned up. Saved {archive_path}")

    # Compute throughput
    return processed, total_bytes


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

    throughput_MBps = total_bytes / duration / (1024 * 1024)  # MB/s
    object_throughput = total_processed / duration  # ops/sec

    log.info(f"All prefixes completed. Total objects={total_processed}")
    log.info(
        f"Total bytes downloaded: {total_bytes} bytes ({total_bytes / (1024*1024*1024):.2f} GB)"
    )
    log.info(f"Total time: {duration:.2f} sec")
    log.info(f"Data throughput: {throughput_MBps:.2f} MB/s")
    log.info(f"Object throughput: {object_throughput:.2f} objects/sec")

    print("\n✅ Download Summary:")
    print(f"Total objects downloaded: {total_processed}")
    print(f"Total data downloaded  : {total_bytes / (1024*1024*1024):.2f} GB")
    print(f"Time taken             : {duration:.2f} sec")
    print(f"Data throughput        : {throughput_MBps:.2f} MB/s")
    print(f"Object throughput      : {object_throughput:.2f} ops/sec")
    print(f"Log file               : {LOG_FILE}")


if __name__ == "__main__":
    main()
