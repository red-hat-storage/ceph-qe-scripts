"""
s5cmd auth file
"""


import logging
import os
import shutil
import sys
from configparser import RawConfigParser
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))
log = logging.getLogger()


from v2.lib.exceptions import S5CMDonfigFileNotFound
from v2.utils import utils

root_path = str(Path.home())
root_path = root_path + "/.aws/"
home_path = os.path.expanduser("~cephuser")

is_multisite = utils.is_cluster_multisite()
if is_multisite:
    sample_file_location = (
        home_path + "/rgw-ms-tests/ceph-qe-scripts/rgw/v2/tests/s5cmd/"
    )
else:
    sample_file_location = home_path + "/rgw-tests/ceph-qe-scripts/rgw/v2/tests/s5cmd/"


def create_s5cmd_file(ssh_con=None):
    """
    Creates .aws/credentials file from sample file
    """
    try:
        log.info(f"ssh connection is {ssh_con}")
        if not os.path.exists(root_path + "credentials"):
            if ssh_con:
                ssh_con.exec_command(f"mkdir {root_path}")
            else:
                utils.exec_shell_cmd(f"mkdir {root_path}")
        sample_file = sample_file_location + "../aws/aws_sample"
        shutil.copy(sample_file, root_path + "credentials")
    except:
        raise S5CMDonfigFileNotFound("s5cmd credential file configuration failed")


def update_s5cmd_file(user_info, ssh_con=None):
    """
    Updates s5/credentials file with user information
    Args:
        user_info(dict): User Information
    """
    parser = RawConfigParser()
    parser.read(root_path + "credentials")
    parser.set("default", "aws_access_key_id", user_info["access_key"])
    parser.set("default", "aws_secret_access_key", user_info["secret_key"])
    with open(root_path + "credentials", "w") as file:
        parser.write(file)


def do_auth_s5cmd(user_info, ssh_con=None):
    """
    Performs steps for s3 authentication using s5cmd
    Args:
        user_info(dict): User Information
    """
    create_s5cmd_file(ssh_con)
    update_s5cmd_file(user_info, ssh_con)
    log.info("S5CMD Version:")
    utils.exec_shell_cmd(f"{home_path}/venv/bin/s5cmd version")
