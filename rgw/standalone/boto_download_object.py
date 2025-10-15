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
MAX_SIZE = int(os.environ.get("MAX_SIZE", "5000"))
SUBDIR_DEPTHS = {
    "1Mobject": 2,
    "20Mobject": 3,
    "50Mobject": 4,
}  # subdir depth for spreading
SUBDIR_PREFIXES = {  # logical prefix -> S3 key prefix
    "1Mobject": "data/scale/1Mobject",
    "20Mobject": "data/scale/20Mobject",
    "50Mobject": "data/scale/50Mobject",
}
# ----------------------------------------


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, file=sys.stderr, flush=True)


def init_s3():
    s3 = boto3.client(
        "s3", endpoint_url=ENDPOINT, config=Config(max_pool_connections=MAX_THREADS)
    )
    transfer_config = TransferConfig(max_concurrency=MAX_THREADS)
    transfer = S3Transfer(s3, config=transfer_config)
    return s3, transfer


def safe_local_path(key):
    """
    Returns:
      local_path: full path to save file
      prefix_dir: top-level prefix dir for archiving
    """
    bbase_name = os.path.basename(key)  # e.g., '1Mobject-12345'
    if "-" not in base_name:
        raise ValueError(f"Unexpected object key format: {key}")
    prefix = base_name.split("-")[0]  # '1Mobject'
    numeric_part = base_name.split("-")[-1]

    depth = SUBDIR_DEPTHS.get(prefix, 3)  # default depth=3
    subdirs = os.path.join(*numeric_part[:depth])
    local_path = os.path.join(OUTPUT_DIR, prefix, subdirs, base_name)
    prefix_dir = os.path.join(OUTPUT_DIR, prefix)
    return local_path, prefix_dir


def worker(logical_prefix, key_prefix):
    s3, transfer = init_s3()
    processed = 0
    paginator = s3.get_paginator("list_objects_v2")

    prefix_dir = os.path.join(OUTPUT_DIR, logical_prefix)
    log(f"[{logical_prefix}] Starting download...")

    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=key_prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if obj["Size"] > MAX_SIZE:
                continue
            local_path, _ = safe_local_path(key)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            try:
                transfer.download_file(BUCKET_NAME, key, local_path)
                processed += 1
            except Exception as e:
                log(f"[{logical_prefix}] ERROR downloading {key}: {e}")

            if processed % LOG_EVERY == 0 and processed > 0:
                log(f"[{logical_prefix}] Processed {processed} objects...")

    # Archive prefix once done
    if os.path.exists(prefix_dir):
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        archive_path = os.path.join(ARCHIVE_DIR, f"{logical_prefix}.tar.gz")
        log(f"[{logical_prefix}] Archiving {prefix_dir} -> {archive_path}")
        shutil.make_archive(
            archive_path.replace(".tar.gz", ""), "gztar", OUTPUT_DIR, logical_prefix
        )
        shutil.rmtree(prefix_dir)  # free disk + inodes
        log(f"[{logical_prefix}] Archived and cleaned up. Saved {archive_path}")

    log(f"[{logical_prefix}] Completed. Total objects={processed}")
    return processed


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    total_processed = 0
    for logical_prefix, key_prefix in SUBDIR_PREFIXES.items():
        total_processed += worker(logical_prefix, key_prefix)

    log(f"All prefixes completed. Total objects={total_processed}")


if __name__ == "__main__":
    main()
