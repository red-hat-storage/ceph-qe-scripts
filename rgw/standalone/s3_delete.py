"""
This script will delete specified number of objects from specified bucket.
Install boto package on machine to run this script.
"""


import boto
import boto.s3.connection

access_key = "<s3 access key>"
secret_key = "<s3 secret key>"
count = 0
conn = boto.connect_s3(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    host="<Hostname or IP>",
    port=8080,
    is_secure=False,  # Change it to True if RGW running using SSL
    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
)

bucket = conn.create_bucket("<Bucket name>")
print("deleting object")
for key in bucket.list():
    print(key.name)
    name = key.name
    key = bucket.delete_key(name)
    count += 1
    # if count == <Number of object to delete from bucket>:
    #     break;
