"""
Reusable methods for S3CMD
"""


import logging
import os
import sys

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

from v2.lib.exceptions import S3CommandExecError
from v2.lib.s3cmd.resource_op import S3CMD
from v2.utils.utils import exec_shell_cmd


def create_bucket(bucket_name):
    """
    Creates bucket
    Args:
        bucket_name(str): Name of the bucket to be created
    """
    mb_method = S3CMD(operation="mb")
    command = mb_method.command(params=["s3://{}".format(bucket_name)])
    try:
        mb_response = exec_shell_cmd(command)
        log.debug("Response for create bucket command: %s" % mb_response)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = "Bucket 's3://{}/' created".format(bucket_name)
    error_message = "Expected: %s, Actual: %s" % (expected_response, mb_response)
    assert expected_response in mb_response, error_message


def upload_file(bucket_name):
    """
    Uploads file to the bucket
    Args:
        bucket_name(str): Name of the bucket
    Returns: Name of the uploaded file
    """
    file_name = "test_s3cmd.txt"
    with open(file_name, "w") as f:
        f.write("Test file")

    upload_file_method = S3CMD(operation="put")
    remote_s3_path = "s3://{}/{}".format(bucket_name, file_name)
    command = upload_file_method.command(params=[file_name, remote_s3_path])
    try:
        upload_file_response = exec_shell_cmd(command)
        log.debug("Response for upload file command: %s" % upload_file_response)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "100%" in str(upload_file_response), "upload file operation not succeeded"
    return file_name


def delete_file(bucket_name, file_name):
    """
    Deletes file from bucket
    Args:
        bucket_name(str): Name of the bucket
        file_name(str): Name of the file to be deleted
    """
    delete_file_method = S3CMD(operation="del")
    remote_s3_path = "s3://{}/{}".format(bucket_name, file_name)
    command = delete_file_method.command(params=[remote_s3_path])
    try:
        delete_file_response = exec_shell_cmd(command)
        log.debug("Response for delete file command: %s" % delete_file_response)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = "delete: '{}'".format(remote_s3_path)
    error_message = "Expected: %s, Actual: %s" % (
        expected_response,
        delete_file_response,
    )
    assert expected_response in delete_file_response, error_message


def delete_bucket(bucket_name):
    """
    Deletes the bucket
    Args:
        bucket_name(str): Name of the bucket to deleted
    """
    delete_bucket_method = S3CMD(operation="rb")
    command = delete_bucket_method.command(params=["s3://{}".format(bucket_name)])
    try:
        delete_bucket_response = exec_shell_cmd(command)
        log.debug("Response for delete bucket command: %s" % delete_bucket_response)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = "Bucket 's3://{}/' removed".format(bucket_name)
    error_message = "Expected: %s, Actual: %s" % (
        expected_response,
        delete_bucket_response,
    )
    assert expected_response in delete_bucket_response, error_message
