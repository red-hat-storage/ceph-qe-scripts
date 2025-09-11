"""
s3cmd auth file
"""


import logging
import os
import shutil
import sys
from configparser import RawConfigParser
from pathlib import Path

import paramiko

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))
log = logging.getLogger()


from v2.lib.exceptions import S3CMDConfigFileNotFound
from v2.utils import utils

root_path = str(Path.home())
home_path = os.path.expanduser("~cephuser")

is_multisite = utils.is_cluster_multisite()
if is_multisite:
    sample_file_location = (
        home_path + "/rgw-ms-tests/ceph-qe-scripts/rgw/v2/tests/s3cmd/"
    )
else:
    sample_file_location = home_path + "/rgw-tests/ceph-qe-scripts/rgw/v2/tests/s3cmd/"


def create_s3cfg_file():
    """
    Creates s3cfg file from sample file
    """
    try:
        sample_file = sample_file_location + "s3cfg_sample"
        shutil.copy(sample_file, root_path + "/" + "s3cfg")
    except:
        raise S3CMDConfigFileNotFound("S3CMD sample config file not found")


def update_s3cfg_file(user_info, ip_and_port):
    """
    Updates s3cfg file with passed values
    Args:
        user_info(dict): User Information
        ip_and_port(str): RGW ip and port in <ip>:<port> forma
    """
    if ip_and_port.startswith("http://") or ip_and_port.startswith("https://"):
        ip_and_port = ip_and_port.split("://", 1)[1]

    port = str(ip_and_port).split(":")[1]
    log.info(f"Port  is {port}")
    parser = RawConfigParser()
    parser.read(root_path + "/" + "s3cfg")
    if str(port) == "443":
        log.info("SSl Configuration")
        parser.set("default", "use_https", "True")
    parser.set("default", "access_key", user_info["access_key"])
    parser.set("default", "secret_key", user_info["secret_key"])
    parser.set("default", "host_base", ip_and_port)
    parser.set("default", "host_bucket", ip_and_port)
    website_endpoint = parser.get("default", "website_endpoint")
    endpoint = website_endpoint.replace("RGW_IP", ip_and_port.split(":")[0])
    parser.set("default", "website_endpoint", endpoint)
    with open(root_path + "/" + "s3cfg", "w") as file:
        parser.write(file)


def copy_to_home_directory():
    """
    Copies s3cfg file to home directory as .s3cfg
    """
    shutil.copy(root_path + "/" + "s3cfg", root_path + "/" + ".s3cfg")
    log.info("S3CMD config file .s3cfg got created")


def push_s3cfg_to_remote(ssh_remote_host):
    # Copy file via SFTP
    sftp = ssh_remote_host.open_sftp()
    remote_path = "/home/cephuser/.s3cfg"
    sftp.put(f"{root_path}/s3cfg", remote_path)
    sftp.close()

    # Verify on remote
    _, stdout, _ = ssh_remote_host.exec_command(f"ls -l {remote_path}")
    log.info(stdout.read().decode())


def do_auth(user_info, ip_and_port, ssh_remote_host=None):
    """
    Performs steps for s3 authentication
    Args:
        user_info(dict): User Information
        ip_and_port(str): RGW ip and port in <ip>:<port> format
    """
    create_s3cfg_file()
    update_s3cfg_file(user_info, ip_and_port)
    copy_to_home_directory()
    log.info("S3CMD Version:")
    utils.exec_shell_cmd(f"{home_path}/venv/bin/s3cmd --version")
    if ssh_remote_host:  # push config to remote if host given
        push_s3cfg_to_remote(ssh_remote_host)
