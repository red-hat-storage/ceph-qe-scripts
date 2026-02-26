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


def _aws_cli_available(ssh_con=None):
    """Return True if the aws CLI binary is available (in PATH or /usr/local/bin)."""
    if ssh_con:
        try:
            stdin, stdout, stderr = ssh_con.exec_command(
                "which aws 2>/dev/null || test -x /usr/local/bin/aws"
            )
            return stdout.channel.recv_exit_status() == 0
        except Exception:
            return False
    return shutil.which("aws") is not None or os.path.isfile("/usr/local/bin/aws")


def install_aws(ssh_con=None):
    """
    Method to install aws on any site
    Args:
        ssh_con: ssh connection object
    """

    try:
        log.info(f"ssh connection is {ssh_con}")
        credentials_exist = os.path.exists(root_path + "credentials")
        aws_available = _aws_cli_available(ssh_con)
        if not credentials_exist or not aws_available:
            if ssh_con:
                ssh_con.exec_command(
                    "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
                )
                ssh_con.exec_command("yum install unzip -y")
                ssh_con.exec_command("unzip awscliv2.zip")
                ssh_con.exec_command("sudo aws/./install")
                ssh_con.exec_command(f"mkdir -p {root_path}")
                log.info(f"AWS version:")
                ssh_con.exec_command("sudo /usr/local/bin/aws --version")
            else:
                utils.exec_shell_cmd(
                    "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
                )
                utils.exec_shell_cmd("yum install unzip -y")
                utils.exec_shell_cmd("unzip awscliv2.zip")
                utils.exec_shell_cmd("sudo aws/./install")
                utils.exec_shell_cmd(f"mkdir -p {root_path}")
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


def run_remote_cmd(ssh_con, cmd):
    """Helper to run remote commands synchronously and return output/errors"""
    stdin, stdout, stderr = ssh_con.exec_command(cmd)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if exit_status != 0:
        raise RuntimeError(
            f"Remote command failed: {cmd}\nSTDOUT: {out}\nSTDERR: {err}"
        )
    return out


def install_aws_remote(ssh_remote_host):
    """
    Install AWS CLI v2 on remote if not already installed.
    Ensures cephuser can execute the binary without permission issues.
    """
    try:
        # Check if AWS CLI exists
        try:
            aws_path = run_remote_cmd(ssh_remote_host, "command -v aws || true")
        except RuntimeError:
            aws_path = ""

        if aws_path:
            log.info(f"AWS CLI already installed at {aws_path}")
            return

        log.info("AWS CLI not found on remote. Installing...")

        tmp_dir = "/tmp/aws_install"
        zip_path = f"{tmp_dir}/awscliv2.zip"

        # Create temp dir
        run_remote_cmd(ssh_remote_host, f"mkdir -p {tmp_dir}")

        # Download AWS CLI zip silently
        run_remote_cmd(
            ssh_remote_host,
            f"curl -s 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o {zip_path}",
        )

        # Extract using Python zipfile
        run_remote_cmd(
            ssh_remote_host,
            f"python3 -c \"import zipfile; zipfile.ZipFile('{zip_path}').extractall('{tmp_dir}')\"",
        )

        # Find the install script dynamically
        aws_install_path = run_remote_cmd(
            ssh_remote_host, f"find {tmp_dir} -type f -name install | head -n1"
        ).strip()

        if not aws_install_path:
            raise RuntimeError("AWS install script not found after extraction!")

        # Make the install script executable
        run_remote_cmd(ssh_remote_host, f"chmod +x {aws_install_path}")

        # Run installer via absolute path with update to fix permissions
        run_remote_cmd(
            ssh_remote_host,
            f"sudo {aws_install_path} -i /usr/local/aws-cli -b /usr/local/bin --update",
        )

        # Ensure full execute permissions for cephuser
        run_remote_cmd(ssh_remote_host, "sudo chmod -R a+rx /usr/local/aws-cli")
        run_remote_cmd(ssh_remote_host, "sudo chmod a+rx /usr/local/bin/aws")

        # Cleanup temp dir
        run_remote_cmd(ssh_remote_host, f"rm -rf {tmp_dir}")

        # Verify AWS CLI as non-root user
        aws_version = run_remote_cmd(ssh_remote_host, "/usr/local/bin/aws --version")
        log.info(f"AWS CLI verified on remote: {aws_version}")

    except Exception as e:
        raise AssertionError(f"AWS installation failed on remote: {str(e)}")


def push_cred_to_remote(ssh_remote_host):
    """
    Ensures AWS CLI is installed on remote
    Copies credentials to /home/cephuser/.aws/credentials
    """
    # Ensure AWS CLI is installed
    install_aws_remote(ssh_remote_host)

    # Ensure remote .aws directory exists
    remote_dir = "/home/cephuser/.aws"
    remote_path = f"{remote_dir}/credentials"
    run_remote_cmd(ssh_remote_host, f"mkdir -p {remote_dir}")

    # Copy credentials via SFTP
    sftp = ssh_remote_host.open_sftp()
    sftp.put(root_path + "credentials", remote_path)
    sftp.close()
    log.info(f"Credentials copied to {remote_path}")


def do_auth_aws(user_info, ssh_con=None, ssh_remote_host=None):
    """
    Performs steps for s3 authentication
    Args:
        user_info(dict): User Information
    """
    install_aws(ssh_con)
    create_aws_file(ssh_con)
    update_aws_file(user_info, ssh_con)
    if ssh_remote_host:  # push config to remote if host given
        push_cred_to_remote(ssh_remote_host)
