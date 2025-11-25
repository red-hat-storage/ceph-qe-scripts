"""
This script will list objects from specified bucket.
Install boto3 package on machine to run this script.
"""

import boto3

access_key = "<Access_Key>"
secret_key = "<Secret_Key>"

s3 = boto3.resource(
    "s3",
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    endpoint_url="http://<RGW HOST Name or IP>:8080",  # use https:// if RGW runs with SSL
)

bucket_name = "<Bucket Name>"
bucket = s3.Bucket(bucket_name)

print("Listing objects")
for obj in bucket.objects.all():
    print(f"{obj.key}\t{obj.size}")
