"""
This script will delete specified number of objects from specified bucket.
Install boto3 package on machine to run this script.
"""

import boto3

access_key = "<s3 access key>"
secret_key = "<s3 secret key>"
count = 0

s3 = boto3.resource(
    "s3",
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    endpoint_url="http://<Hostname or IP>:8080",  # Change to https:// if RGW runs with SSL
)

bucket = s3.Bucket("<Bucket name>")

print("deleting object")
for obj in bucket.objects.all():
    print(obj.key)
    obj.delete()
    count += 1
    # if count == <Number of object to delete from bucket>:
    #     break;
