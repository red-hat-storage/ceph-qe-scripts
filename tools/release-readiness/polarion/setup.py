import os

import yaml

if os.getenv("POLARION_URL") is None:
    with open(r"config/setup.yml", "r") as file:
        yaml_config = yaml.safe_load(file)
    print("--------")
    os.environ["POLARION_URL"] = yaml_config["url"]
    os.environ["POLARION_REPO"] = yaml_config["svn_repo"]
    os.environ["POLARION_USERNAME"] = yaml_config["user"]
    os.environ["POLARION_PASSWORD"] = yaml_config["password"]
    os.environ["POLARION_PROJECT"] = yaml_config["default_project"]

    if os.path.exists("/etc/pki/tls/RH-IT-Root-CA.crt") == False:
        os.system("curl -OL https://password.corp.redhat.com/RH-IT-Root-CA.crt")
        if os.path.exists("RH-IT-Root-CA.crt"):
            os.system("mv RH-IT-Root-CA.crt /etc/pki/tls/RH-IT-Root-CA.crt")
            if os.path.exists("RH-IT-Root-CA.crt") == False:
                os.environ["POLARION_CERT_PATH"] = "/etc/pki/tls/RH-IT-Root-CA.crt"
        else:
            print(
                "File is Not downloaded,please Download it and set manualy. Refer Documentation"
            )
