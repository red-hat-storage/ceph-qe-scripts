"""
This script will create 10 random file sized between 64KB to 20 MB and upload it to specified bucket.
Install boto3 package on machine to run this script.
"""

import os
from random import randint

import boto3

access_key = "<s3 access key>"
secret_key = "<s3 secret key>"

s3 = boto3.resource(
    "s3",
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    endpoint_url="http://<Hostname or IP>:8080",  # use https:// if RGW runs with SSL
)

bucket_name = "<Bucket name>"
bucket = s3.Bucket(bucket_name)

for i in range(1, 11):
    r = randint(64, 20240)
    cmd = f"dd if=/dev/zero of=testfile{i} bs=1024 count={r}"
    os.system(cmd)

print("creating objects")
for i in range(1000):
    r = randint(1, 10)
    t = f"testfile{r}"
    name = f"{bucket_name}{i}"
    bucket.upload_file(Filename=t, Key=name)
    print(name)
