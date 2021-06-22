"""
This script will create 10 random file sized between 64KB to 20 MB and
upload it to specified versioned container.
Install boto package on machine to run this script.
"""

import os
from random import randint

import boto
import boto.s3.connection

access_key = "<s3 access key>"
secret_key = "<s3 secret key>"

conn = boto.connect_s3(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    host="<Hostname or IP>",
    port=8080,
    is_secure=False,  # Change it to True if RGW running using SSL
    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
)

for i in range(1, 11):
    r = randint(64, 20240)
    cmd = "dd if=/dev/zero of=testfile{i} bs=1024 count={r}".format(i=i, r=r)
    os.system(cmd)

bucket = conn.create_bucket("<Bucket name>")
bucket.configure_versioning(versioning=True)

print("creating objects")
for i in range(1000):
    r = randint(1, 10)
    t = "testfile" + str(r)
    name = "<Bucket name>" + str(i)
    key = bucket.new_key(name)
    key.set_contents_from_filename(t)
    print(name)
