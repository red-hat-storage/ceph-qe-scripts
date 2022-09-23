"""
Reusable methods for S3CMD
"""


import logging
import os
import socket
import sys

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

from v2.lib.exceptions import S3CommandExecError
from v2.lib.manage_data import io_generator
from v2.lib.s3cmd.resource_op import S3CMD
from v2.utils import utils
from v2.utils.utils import exec_shell_cmd


def create_bucket(bucket_name):
    """
    Creates bucket
    Args:
        bucket_name(str): Name of the bucket to be created
    """
    mb_method = S3CMD(operation="mb")
    command = mb_method.command(params=[f"s3://{bucket_name}"])
    try:
        mb_response = exec_shell_cmd(command)
        log.debug(f"Response for create bucket command: {mb_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = f"Bucket 's3://{bucket_name}/' created"
    error_message = f"Expected: {expected_response}, Actual: {mb_response}"
    assert expected_response in mb_response, error_message


def upload_file(bucket_name, file_name=None, file_size=1024, test_data_path=None):
    """
    Uploads file to the bucket
    Args:
        bucket_name(str): Name of the bucket
        file_name(str): Name of the file to be uploaded
        file_size(int): Size of the file to be uploaded, defaults to 1024
        test_data_path(str): Local test data path
    Returns: File information
    """
    # If no file_name passed, it generates file_name and returns in file information
    # It is to have support for file which is already created
    if file_name is None:
        file_name = utils.gen_s3_object_name(bucket_name, 1)

    local_file_path = test_data_path + "/" + file_name
    file_info = io_generator(local_file_path, file_size)
    file_info["name"] = file_name

    upload_file_method = S3CMD(operation="put")
    remote_s3_path = f"s3://{bucket_name}/{file_name}"
    command = upload_file_method.command(params=[local_file_path, remote_s3_path])
    try:
        upload_file_response = exec_shell_cmd(command)
        log.debug(f"Response for upload file command: {upload_file_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "100%" in str(upload_file_response), "upload file operation not succeeded"
    return file_info


def download_file(
    bucket_name, remote_file_name, local_file_name=None, test_data_path=None
):
    """
    Downloads file from the bucket
    Args:
        bucket_name(str): Name of the bucket
        remote_file_name(str): Name of the remote file
        local_file_name(str): Name of the local file to be set
        test_data_path(str): Local test data path
    Returns: Name with path of the downloaded file
    """
    if local_file_name is None:
        local_file_name = "test_s3cmd.txt"

    download_file_method = S3CMD(operation="get", options=["--force"])
    remote_s3_path = f"s3://{bucket_name}/{remote_file_name}"
    local_file_path = test_data_path + "/" + local_file_name
    command = download_file_method.command(params=[remote_s3_path, local_file_path])
    try:
        download_file_response = exec_shell_cmd(command)
        log.debug(f"Response for upload file command: {download_file_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "100%" in str(
        download_file_response
    ), "download file operation not succeeded"
    return local_file_path


def delete_file(bucket_name, file_name):
    """
    Deletes file from bucket
    Args:
        bucket_name(str): Name of the bucket
        file_name(str): Name of the file to be deleted
    """
    delete_file_method = S3CMD(operation="del")
    remote_s3_path = f"s3://{bucket_name}/{file_name}"
    command = delete_file_method.command(params=[remote_s3_path])
    try:
        delete_file_response = exec_shell_cmd(command)
        log.debug(f"Response for delete file command: {delete_file_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = f"delete: '{remote_s3_path}'"
    error_message = f"Expected: {expected_response}, Actual: {delete_file_response}"
    assert expected_response in delete_file_response, error_message


def delete_bucket(bucket_name):
    """
    Deletes the bucket
    Args:
        bucket_name(str): Name of the bucket to deleted
    """
    delete_bucket_method = S3CMD(operation="rb")
    command = delete_bucket_method.command(params=[f"s3://{bucket_name}"])
    try:
        delete_bucket_response = exec_shell_cmd(command)
        log.debug(f"Response for delete bucket command: {delete_bucket_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = f"Bucket 's3://{bucket_name}/' removed"
    error_message = f"Expected: {expected_response}, Actual: {delete_bucket_response}"
    assert expected_response in delete_bucket_response, error_message


def create_local_file(file_size, file_name):
    """
    Creates a local file with specified size
    Args:
        file_size(int): Size of the file to be created
        file_name(str): Name of the file to be created
    """
    exec_shell_cmd(f"fallocate -l {file_size} {file_name}")


def get_file_size(file_name):
    """
    Returns size of the file in bytes
    Args:
        file_name(str): Name of the file to be created
    Returns: File size in bytes
    """
    return os.path.getsize(file_name)


def get_rgw_ip_and_port(ssh_con=None):
    """
    Returns RGW ip and port in <ip>:<port> format
    Returns: RGW ip and port
    """

    if ssh_con:
        _, stdout, _ = ssh_con.exec_command("hostname")
        hostname = stdout.readline().strip()
        ip = socket.gethostbyname(str(hostname))
        port = utils.get_radosgw_port_no(ssh_con)
    else:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = utils.get_radosgw_port_no()
    ip_and_port = f"{ip}:{port}"
    return ip_and_port


def run_subprocess(cmd):
    """
    :param cmd: command to run
    :return: stdout, stderr
    """
    try:
        rc = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    return stdout, stderr


def rate_limit_read(bucket, max_read_ops, file=None):
    """
    max_read_ops: Loop until the max_read_ops value to check for a 503
    slowdown warning
    """
    # increment max_read_ops to induce warning
    max_read_ops += 1
    range_val = f"1..{max_read_ops}"
    cmd = (
        f"for i in {{{range_val}}}; do /home/cephuser/venv/bin/s3cmd ls "
        f"s3://{bucket}/{file} ;done;"
    )
    stdout, stderr = run_subprocess(cmd)
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"


def rate_limit_write(bucket, max_write_ops):
    """
    :param bucket: bucket to write
    :param max_write_ops: Loop until the max write opsto check for 503
    :param file: file to write
    """
    # increment max_write_ops to induce warning
    max_write_ops += 1
    create_local_file("1k", "file1")
    range_val = f"1..{max_write_ops}"
    cmd = (
        f"for i in {{{range_val}}}; do /home/cephuser/venv/bin/s3cmd "
        f"put file1 s3://{bucket}/file$i ;done;"
    )
    stdout, stderr = run_subprocess(cmd)
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"
