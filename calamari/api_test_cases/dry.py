import json

import requests

if __name__ == "__main__":
    client = requests.session()

    ip = ""  # ip address
    port = "8002"  # port number
    username = ""  # calamari login username
    password = ""  # calamari login password

    base_url = "https://%s:%s/api/v2/" % (ip, port)

    # login

    login_url = base_url + "auth/login/"
    login_data = {"username": username, "password": password, "next": "/"}
    response = client.post(login_url, login_data, verify=False)
    token = response.cookies["XSRF-TOKEN"]
    headers = {"X-XSRF-TOKEN": token}

    if response.status_code == 200:
        print "logged in"

    # get fsid

    url = base_url + "cluster"
    print url
    response = client.get(url, verify=False)
    response.raise_for_status()
    fsid = json.loads(response.content)[0]["id"]
    print "got fsid"

    # cli url

    url = base_url + "cluster" + "/" + fsid + "/cli"
    print url
    data1 = {"command": ["ceph", "osd", "tree"]}
    headers["Referer"] = url
    response = client.post(url, data=data1, verify=False, headers=headers)
    response.raise_for_status()
    print response.content

    data2 = {"command": "ceph osd tree"}
    headers["Referer"] = url
    response = client.post(url, data=data2, verify=False, headers=headers)
    response.raise_for_status()

    print response.content
