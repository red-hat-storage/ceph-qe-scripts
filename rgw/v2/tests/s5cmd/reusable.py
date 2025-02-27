"""
Reusable methods for s5cmd
"""


import glob
import json
import logging
import os
import socket
import subprocess
import sys
import time
from configparser import RawConfigParser
from pathlib import Path

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

import v2.utils.utils as utils
from v2.lib.exceptions import S5CMDCommandExecError, TestExecError
from v2.lib.manage_data import io_generator


def create_bucket(bucket_name, end_point):
    """
    Creates bucket
    ex: s5cmd --endpoint-url http://x.x.x.x:xxxx mb s3://bucket_name/
    Args:
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
    """
    cmd = f"s5cmd --endpoint-url {end_point} mb s3://{bucket_name}"
    try:
        create_response = utils.exec_shell_cmd(cmd)
        log.info(f"bucket creation response is {create_response}")
    except Exception as e:
        raise S5CMDCommandExecError(message=str(e))
    expected_response = f"mb s3://{bucket_name}"
    error_message = f"Expected: {expected_response}, Actual: {create_response}"
    assert expected_response in create_response, error_message


def get_endpoint(ssh_con=None, haproxy=None, ssl=None):
    """
    Returns RGW ip and port in <ip>:<port> format
    Returns: RGW ip and port
    """

    if ssh_con:
        _, stdout, _ = ssh_con.exec_command("hostname")
        hostname = stdout.readline().strip()
        ip = socket.gethostbyname(str(hostname))
        port = 5000 if haproxy else utils.get_radosgw_port_no(ssh_con)
    else:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = 5000 if haproxy else utils.get_radosgw_port_no()
    ip_and_port = f"http://{ip}:{port}"
    if ssl:
        ip_and_port = f"https://{ip}:{port}"
    return ip_and_port


def put_object_via_copy(bucket_name, end_point, object_name, local_file_path):
    """
    copy object to the bucket
    Ex: s5cmd --endpoint-url http://x.x.x.x:xxxx cp object_name s3://bucket_name/object_name
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        test_data_path(str): Local test data path
    Return:
        Response of put-object operation
    """
    cmd = f"s5cmd --endpoint-url {end_point} cp {local_file_path} s3://{bucket_name}/{object_name}"
    try:
        copy_response = utils.exec_shell_cmd(cmd)
        log.info(copy_response)
        if not copy_response:
            raise Exception(f"copy object failed for {bucket_name}")
    except Exception as e:
        raise S5CMDCommandExecError(message=str(e))
    return copy_response


def list_objects(end_point, bucket_name=None):
    """
    List all the buckets or objects in the bucket
    Ex: s5cmd --endpoint-url http://x.x.x.x:xxxx ls s3://bucket_name/
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
        marker(str): The key name from where the listing needs to start
    Return:
        Returns details of every object in the bucket post the marker
    """
    bucket_param = f" s3://{bucket_name}" if bucket_name else ""
    cmd = f"s5cmd --endpoint-url {end_point} ls{bucket_param}"
    try:
        list_response = utils.exec_shell_cmd(cmd)
    except Exception as e:
        raise S5CMDCommandExecError(message=str(e))
    return list_response


def delete_object(bucket_name, object_name, end_point):
    """
    Deletes object from the bucket
    Ex: s5cmd --endpoint-url http://x.x.x.x:xxxx rm s3://bucket_name/object_name
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
    Return:
        Response of delete-object operation
    """
    cmd = f"s5cmd --endpoint-url {end_point} rm s3://{bucket_name}/{object_name}"
    try:
        delete_response = utils.exec_shell_cmd(cmd)
        if not delete_response:
            raise Exception(f"delete object failed for {bucket_name}")
    except Exception as e:
        raise S5CMDCommandExecError(message=str(e))
    return delete_response


def delete_bucket(bucket_name, end_point):
    """
    Deletes object from the bucket
    Ex: s5cmd --endpoint-url http://x.x.x.x:xxxx rb s3://bucket_name/
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
    Return:
        Response of delete-object operation
    """
    cmd = f"s5cmd --endpoint-url {end_point} rb s3://{bucket_name}"
    try:
        delete_response = utils.exec_shell_cmd(cmd)
        log.info(f"bucket removal response is {create_response}")
        if not delete_response:
            raise Exception(f"delete bucket failed for {bucket_name}")
    except Exception as e:
        raise S5CMDCommandExecError(message=str(e))
    expected_response = f"rb s3://{bucket_name}"
    error_message = f"Expected: {expected_response}, Actual: {delete_response}"
    assert expected_response in delete_response, error_message
