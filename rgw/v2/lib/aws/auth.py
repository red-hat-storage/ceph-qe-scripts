"""
aws auth file
"""


import logging
import os
import shutil
import sys
from configparser import RawConfigParser
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))
log = logging.getLogger()


from v2.lib.exceptions import AWSConfigFileNotFound
from v2.utils import utils

root_path = str(Path.home())
root_path = root_path + "/.aws/"
home_path = os.path.expanduser("~cephuser")
sample_file_location = home_path + ("/rgw-tests/ceph-qe-scripts/rgw/v2/tests/aws/")


def install_aws():
    """
    Creates .aws/credentials file from sample file
    """
    try:
        if not os.path.exists(root_path + "credentials"):
            utils.exec_shell_cmd(
                "curl 'https://s3.amazonaws.com/aws-cli/awscli-bundle-1.18.223.zip' -o 'awscli-bundle.zip'"
            )
            utils.exec_shell_cmd("yum install unzip -y")
            utils.exec_shell_cmd("unzip awscli-bundle.zip")
            utils.exec_shell_cmd(
                "sudo awscli-bundle/./install -i /usr/local/aws -b /usr/local/bin/aws"
            )
            utils.exec_shell_cmd(f"mkdir {root_path}")
    except:
        raise AssertionError("AWS Installation Failed")


def create_aws_file():
    """
    Creates .aws/credentials file from sample file
    """
    try:
        sample_file = sample_file_location + "aws_sample"
        shutil.copy(sample_file, root_path + "credentials")
    except:
        raise AWSConfigFileNotFound("AWS sample config file not found")


def update_aws_file(user_info):
    """
    Updates .aws/credentials file with user information
    Args:
        user_info(dict): User Information
    """
    parser = RawConfigParser()
    parser.read(root_path + "credentials")
    parser.set("default", "aws_access_key_id", user_info["access_key"])
    parser.set("default", "aws_secret_access_key", user_info["secret_key"])
    with open(root_path + "credentials", "w") as file:
        parser.write(file)


def do_auth_aws(user_info):
    """
    Performs steps for s3 authentication
    Args:
        user_info(dict): User Information
    """
    install_aws()
    create_aws_file()
    update_aws_file(user_info)
