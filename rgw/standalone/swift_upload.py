"""
This script will create 10 random file sized between 64KB to 20 MB and upload it to specified container.
Install swiftclient package on machine to run this script.
"""
import swiftclient
import os
from random import randint
user = '<<Swift user id>>'
key = '<Swift user key>'

conn = swiftclient.Connection(
        user=user,
        key=key,
        authurl='http://<RGW hostname or IP>:8080/auth/1.0',
)
container_name = '<Container name>'
conn.put_container(container_name)

for i in range(1, 11):
    r = randint(64, 20240)
    cmd = 'dd if=/dev/zero of=testfile{i} bs=1024 count={r}'.format(i=i, r=r)
    os.system(cmd)

for i in range(1000):
    r= randint(1, 10)
    t= 'testfile'+ str(r)
    name = '<Container name>' + str(i)
    print(name)
    with open(t, 'r') as hello_file:
        conn.put_object(container_name, name, contents= hello_file.read(),content_type='text/plain')
