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

is_multisite = utils.is_cluster_multisite()
if is_multisite:
    sample_file_location = home_path + "/rgw-ms-tests/ceph-qe-scripts/rgw/v2/tests/aws/"
else:
    sample_file_location = home_path + "/rgw-tests/ceph-qe-scripts/rgw/v2/tests/aws/"


def install_aws(ssh_con=None):
    """
    Method to install aws on any site
    Args:
        ssh_con: ssh connection object
    """

    try:
        log.info(f"ssh connection is {ssh_con}")
        if not os.path.exists(root_path + "credentials"):
            if ssh_con:
                ssh_con.exec_command(
                    "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
                )
                ssh_con.exec_command("yum install unzip -y")
                ssh_con.exec_command("unzip awscliv2.zip")
                ssh_con.exec_command("sudo aws/./install")
                ssh_con.exec_command(f"mkdir {root_path}")
                log.info(f"AWS version:")
                ssh_con.exec_command("sudo /usr/local/bin/aws --version")
            else:
                utils.exec_shell_cmd(
                    "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
                )
                utils.exec_shell_cmd("yum install unzip -y")
                utils.exec_shell_cmd("unzip awscliv2.zip")
                utils.exec_shell_cmd("sudo aws/./install")
                utils.exec_shell_cmd(f"mkdir {root_path}")
                log.info(f"AWS version:")
                utils.exec_shell_cmd("sudo /usr/local/bin/aws --version")
    except:
        raise AssertionError("AWS Installation Failed")


def create_aws_file(ssh_con=None):
    """
    Creates .aws/credentials file from sample file
    """
    try:
        sample_file = sample_file_location + "aws_sample"
        shutil.copy(sample_file, root_path + "credentials")
    except:
        raise AWSConfigFileNotFound("AWS sample config file not found")


def update_aws_file(user_info, ssh_con=None, checksum_validation_calculation=None):
    """
    Updates .aws/credentials file with user information
    Args:
        user_info(dict): User Information
    """
    parser = RawConfigParser()
    parser.read(root_path + "credentials")
    parser.set("default", "aws_access_key_id", user_info["access_key"])
    parser.set("default", "aws_secret_access_key", user_info["secret_key"])
    if checksum_validation_calculation:
        parser.set(
            "default", "request_checksum_calculation", checksum_validation_calculation
        )
        parser.set(
            "default", "response_checksum_validation", checksum_validation_calculation
        )
    else:
        parser.remove_option("default", "request_checksum_calculation")
        parser.remove_option("default", "response_checksum_validation")
    with open(root_path + "credentials", "w") as file:
        parser.write(file)
    utils.exec_shell_cmd(f'cat {root_path + "credentials"}')


def do_auth_aws(user_info, ssh_con=None):
    """
    Performs steps for s3 authentication
    Args:
        user_info(dict): User Information
    """
    install_aws(ssh_con)
    create_aws_file(ssh_con)
    update_aws_file(user_info, ssh_con)
