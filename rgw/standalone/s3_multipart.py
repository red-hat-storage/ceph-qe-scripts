"""
This script will create 50 random large sized file and upload
it to specified bucket.
Install boto package on machine to run this script.
"""

import os
from random import randint

import boto3

session = boto3.session.Session()
access_key = "<s3 access key>"
secret_key = "<s3 secret key>"

s3 = session.client(
    "s3",
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    endpoint_url="http://<Hostname or IP>:8080",
)

for i in range(1, 51):
    r = randint(100000, 150000)
    os.system("dd if=/dev/zero of=testfile1 bs=1024 count=" + str(r))
    r = randint(150000, 200000)
    os.system("dd if=/dev/zero of=testfile2 bs=1024 count=" + str(r))
    k = "multi" + str(i)
    multi_part = s3.create_multipart_upload(Bucket="<Bucket name>", Key=k)
    upload_part1 = s3.upload_part(
        Body=open("testfile1", mode="rb"),
        Bucket="multipart",
        Key=k,
        PartNumber=1,
        UploadId=multi_part["UploadId"],
    )
    upload_part2 = s3.upload_part(
        Body=open("testfile2", mode="rb"),
        Bucket="multipart",
        Key=k,
        PartNumber=2,
        UploadId=multi_part["UploadId"],
    )
    response = s3.complete_multipart_upload(
        Bucket="multipart",
        Key=k,
        MultipartUpload={
            "Parts": [
                {"ETag": upload_part1["ETag"], "PartNumber": 1},
                {"ETag": upload_part2["ETag"], "PartNumber": 2},
            ]
        },
        UploadId=multi_part["UploadId"],
    )
    print(response)
