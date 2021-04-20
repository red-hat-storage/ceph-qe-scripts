"""
Performs delete of bulk objects in a container
"""


import swiftclient
import os
from random import randint
import requests


user = '<Swift Username>'
key = '<Swift Key>'

conn = swiftclient.Connection(
        user=user,
        key=key,
        authurl='http://<RGW IP or Hostname>:80/auth/1.0'
)

auth_response = conn.get_auth()
token = auth_response[1]
# test.txt file should contain container_name/object_name_to_delete
test_file = open("test.txt", "r") 
url = 'http://<RGW IP or Hostname>:80/swift/v1/?bulk-delete'
headers = {"Accept": "application/json", "Content-Type": "text/plain",
           "X-Auth-Token": token}
response = requests.delete(url, headers=headers,
                           files={"form_field_name": test_file})
if response.status_code == 200:
    print('Bulk delete succeeded')
else:
    print('Bulk delete failed with status code: %d' response.status_code)
