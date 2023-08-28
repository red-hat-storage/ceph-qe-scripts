"""
Reusable methods for aws
"""


import json
import logging
import os
import socket
import subprocess
import sys
from configparser import RawConfigParser
from pathlib import Path

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

import v2.utils.utils as utils
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import AWSCommandExecError
from v2.lib.manage_data import io_generator


def create_bucket(bucket_name, end_point, ssl=None):
    """
    Creates bucket
    ex: /usr/local/bin/aws s3api create-bucket --bucket verbkt1 --endpoint-url http://x.x.x.x:xx
    Args:
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
    """
    create_method = AWS(operation="create-bucket")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = create_method.command(
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}", ssl_param]
    )
    try:
        create_response = utils.exec_shell_cmd(command)
        if create_response:
            raise Exception(
                f"Create bucket failed for {bucket_name} with {create_response}"
            )
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def list_object_versions(bucket_name, end_point, ssl=None):
    """
    Lists object versions for an bucket
    Ex: /usr/local/bin/aws s3api list-object-versions --bucket <bucket_name> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
        ssl:
    Return:
        Response of list-object-versions operation
    """
    list_method = AWS(operation="list-object-versions")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = list_method.command(
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}", ssl_param]
    )
    try:
        create_response = utils.exec_shell_cmd(command)
        return create_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_object(bucket_name, object_name, end_point, ssl=None):
    """
    Put/uploads object to the bucket
    Ex: /usr/local/bin/aws s3api put-object --bucket <bucket_name> --key <object_name> --body <content> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        ssl:
    Return:
        Response of put-object operation
    """
    put_method = AWS(operation="put-object")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = put_method.command(
        params=[
            f"--bucket {bucket_name} --key {object_name} --body {object_name} --endpoint-url {end_point}",
            ssl_param,
        ]
    )
    try:
        create_response = utils.exec_shell_cmd(command)
        return create_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def delete_object(bucket_name, object_name, end_point, ssl=None, versionid=None):
    """
    Deletes object from the bucket
    Ex: /usr/local/bin/aws s3api delete-object --bucket <bucket_name> --key <object_name> --endpoint <endpoint_url>
        --version-id {versionid}
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        ssl:
        versionid(str): Id of object version which needs to be deleted
    Return:
        Response of delete-object operation
    """
    delete_method = AWS(operation="delete-object")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = delete_method.command(
        params=[
            f"--bucket {bucket_name} --key {object_name} --endpoint-url {end_point}",
            ssl_param,
        ]
    )
    if versionid:
        command = delete_method.command(
            params=[
                f"--bucket {bucket_name} --key {object_name} --endpoint-url {end_point}"
                f" --version-id {versionid}",
                ssl_param,
            ]
        )
    try:
        create_response = utils.exec_shell_cmd(command)
        return create_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_get_bucket_versioning(bucket_name, end_point, status="Enabled", ssl=None):
    """
    make bucket created as versioned
    ex:
    /usr/local/bin/aws s3api  put-bucket-versioning --bucket versioned-bkt-3 --versioning-configuration Status=Enabled --endpoint http://x.x.x.x:xx
    /usr/local/bin/aws s3api get-bucket-versioning --bucket versioned-bkt-1 --endpoint http://x.x.x.x:xx
    Args:
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
    """
    put_method = AWS(
        operation=f"put-bucket-versioning --versioning-configuration Status={status}"
    )
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    put_cmd = put_method.command(
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}", ssl_param]
    )
    try:
        put_response = utils.exec_shell_cmd(put_cmd)
        if put_response:
            raise Exception(
                f"Version Enabling failed for {bucket_name} with {put_response}"
            )
        get_method = AWS(operation="get-bucket-versioning")
        get_cmd = get_method.command(
            params=[f"--bucket {bucket_name} --endpoint-url {end_point}", ssl_param]
        )
        get_response = json.loads(utils.exec_shell_cmd(get_cmd))
        if get_response["Status"] != status:
            raise Exception(
                f"Get bucket version response is not as expected: {get_response}"
            )
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def get_endpoint(ssh_con=None):
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
    ip_and_port = f"http://{ip}:{port}"
    return ip_and_port


def update_aws_file_with_sts_user(sts_user_info):
    """
    Updates .aws/credentials file with sts user information
    Args:
        sts_user_info(dict): sts User Information (or sts profile)
    """
    root_path = str(Path.home())
    root_path = root_path + "/.aws/credentials"
    if not os.path.exists(root_path):
        raise AssertionError(f"AWS credential file {root_path} not found")
    parser = RawConfigParser()
    parser.read(root_path + "credentials")
    if not parser.has_section("sts"):
        parser.add_section("sts")
    parser.set("sts", "aws_access_key_id", sts_user_info["access_key"])
    parser.set("sts", "aws_secret_access_key", sts_user_info["secret_key"])
    parser.set("sts", "aws_session_token", sts_user_info["session_token"])

    # save the keyring back to the file
    with open(root_path, "a") as file:
        parser.write(file)
    utils.exec_shell_cmd(f"cat {root_path}")


def verify_object_with_version_id_null(
    bucket_name, object_name, endpoint, created=True
):
    """
    Method to verify whether object with version is created or deleted
    Args:
        bucket_name(str): Name of the bucket
        object_name(str): Name of the object
        endpoint(str): endpoint usrl
        created(boolean): True for creation validation
                          False for deletion validation
    Exception:
        Raise assertion error when validation fails.
    """
    version_id_null = False
    version_list = list_object_versions(bucket_name, endpoint)
    version_list = json.loads(version_list)
    for ver in version_list["Versions"]:
        log.info(f"ver is {ver}")
        if ver["Key"] == object_name:
            log.info(f"version id is {ver['VersionId']}")
            if ver["VersionId"] == "null":
                version_id_null = True
                log.info(
                    f"object with versioned id null is present at the endpoint:{endpoint}!"
                )
    if created and not version_id_null:
        raise AssertionError(
            f"Object with version id null is not created at the endpoint {endpoint}!"
        )
    elif not created and version_id_null:
        raise AssertionError(
            f"Object with version id null is not Deleted at the endpoint {endpoint}!"
        )
