import argparse
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


# ---------------- CONFIGURE LOGGER ----------------
def setup_logger(bucket_name):
    log_file = f"{bucket_name}_upload_multipart.log"
    logging.basicConfig(
        filename=log_file,
        filemode="a",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)
    return logging.getLogger()


# ---------------- MULTIPART UPLOAD ----------------
def multipart_upload(s3_client, bucket, file_path, object_name, part_size):
    try:
        file_size = os.path.getsize(file_path)
        mpu = s3_client.create_multipart_upload(Bucket=bucket, Key=object_name)
        upload_id = mpu["UploadId"]

        parts = []
        part_number = 1
        with open(file_path, "rb") as f:
            while True:
                data = f.read(part_size)
                if not data:
                    break
                part = s3_client.upload_part(
                    Bucket=bucket,
                    Key=object_name,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=data,
                )
                parts.append({"ETag": part["ETag"], "PartNumber": part_number})
                part_number += 1

        s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=object_name,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        return True
    except ClientError as e:
        logging.error(f"Upload failed for {object_name}: {e}")
        return False


# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(
        description="Multipart upload to S3 with throughput calculation"
    )
    parser.add_argument("--endpoint", required=True, help="S3 endpoint URL")
    parser.add_argument("--bucket", required=True, help="Target bucket name")
    parser.add_argument("--file", required=True, help="Local file to upload")
    parser.add_argument(
        "--num-objects", type=int, default=1, help="Number of times to upload file"
    )
    parser.add_argument(
        "--part-size-mb", type=int, default=8, help="Part size in MB (optional)"
    )
    parser.add_argument(
        "--prefix", default="multipart-object-", help="Object name prefix"
    )
    args = parser.parse_args()

    logger = setup_logger(args.bucket)
    s3 = boto3.client(
        "s3", endpoint_url=args.endpoint, config=Config(max_pool_connections=64)
    )

    part_size = args.part_size_mb * 1024 * 1024
    file_size = os.path.getsize(args.file)
    logger.info(
        f"Starting upload: {args.num_objects} objects × {file_size / (1024*1024):.2f} MB each"
    )
    logger.info(f"Using 64 threads, part size {args.part_size_mb} MB")

    start_time = time.time()
    success_count = 0

    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = []
        for i in range(args.num_objects):
            object_name = f"{args.prefix}{i}"
            futures.append(
                executor.submit(
                    multipart_upload, s3, args.bucket, args.file, object_name, part_size
                )
            )

        for future in as_completed(futures):
            if future.result():
                success_count += 1

    end_time = time.time()
    duration = end_time - start_time
    total_bytes = file_size * success_count

    # ---------------- CALCULATIONS ----------------
    object_throughput = success_count / duration  # op/s
    data_throughput_mb_s = total_bytes / duration / (1024 * 1024)  # MB/s
    bandwidth_mb_s = data_throughput_mb_s  # MB/s (same as throughput in MB/s)

    # ---------------- LOGGING ----------------
    logger.info(f"Upload completed: {success_count}/{args.num_objects} succeeded")
    logger.info(f"Total time: {duration:.2f} sec")
    logger.info(f"Object throughput: {object_throughput:.2f} op/s")
    logger.info(f"Data throughput: {data_throughput_mb_s:.2f} MB/s")
    logger.info(f"Bandwidth: {bandwidth_mb_s:.2f} MB/s")

    # ---------------- PRINT SUMMARY ----------------
    print(f"\n✅ Upload Summary:")
    print(f"Objects uploaded      : {success_count}/{args.num_objects}")
    print(f"Time taken            : {duration:.2f} sec")
    print(f"Object throughput     : {object_throughput:.2f} op/s")
    print(f"Data throughput       : {data_throughput_mb_s:.2f} MB/s")
    print(f"Bandwidth             : {bandwidth_mb_s:.2f} MB/s")
    print(f"Log file              : {args.bucket}_upload_multipart.log")


if __name__ == "__main__":
    main()
