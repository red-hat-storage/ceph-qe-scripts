"""
This script will delete specified number of objects from specified container.
Install swiftclient package on machine to run this script.
"""
import swiftclient

user = "<Swift user id>"
key = "<Swift user key>"
count = 0
conn = swiftclient.Connection(
    user=user,
    key=key,
    authurl="http://<RGW hostname or IP>:8080/auth/1.0",
)
container_name = "<Container name>"

for i in conn.get_container(container_name)[1]:
    name = i["name"]
    conn.delete_object(container_name, name)
    print(i["name"])
    count += 1
    # if count == <Number of objects to delete>:
    #     break;
