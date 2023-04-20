"""Module to upload a file into rgw bucket.

Module creates an rgw bucket called rbd and uploads mentioned filename
as an object. Module expects s3 user test_rbd with same access_key and
secret_key. Also file name is expected to be an exported rbd image in raw
format.
Args:
    --rgw-node: ip address of rgw node
    --file-name: name of raw file
"""

import argparse
import logging

import boto3

log = logging.getLogger()


if __name__ == "__main__":

    log.info("Executing prepare rbd image as s3 object")

    parser = argparse.ArgumentParser(description="Prepare rbd image s3 object")
    parser.add_argument("--rgw-node", dest="rgw_node")
    parser.add_argument("--file-name", dest="file_name")
    args = parser.parse_args()
    rgw_node = args.rgw_node

    rgw = boto3.client(
        "s3",
        aws_access_key_id="test_rbd",
        aws_secret_access_key="test_rbd",
        endpoint_url=f"http://{rgw_node}:80",
        use_ssl=False,
    )
    rgw.create_bucket(Bucket="rbd")
    rgw.upload_file(f"{args.file_name}", "rbd", f"{args.file_name.split('.')[0][-2:]}")
