"""
This script will list objects from specified bucket.
Install boto package on machine to run this script.
"""

import boto
import boto.s3.connection

access_key = "<Access_Key>"
secret_key = "<Secret_Key>"

conn = boto.connect_s3(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    host="<RGW HOST Name or IP>",
    port=8080,
    is_secure=False,  # Change it to True if RGW running using SSL
    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
)

bucket = conn.create_bucket("<Bucket Name>")

print("Listing objects")
for key in bucket.list():
    print("{name}\t{size}".format(name=key.name, size=key.size))
