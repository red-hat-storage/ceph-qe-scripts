"""
Reusable methods for aws
"""


import glob
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
from v2.lib.exceptions import AWSCommandExecError, TestExecError
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
        log.info(f"bucket creation response is {create_response}")
        if create_response:
            raise Exception(f"Create bucket failed for {bucket_name}")
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
        list_response = utils.exec_shell_cmd(command)
        if not list_response:
            raise Exception(f"List object versions on bucket failed for {bucket_name}")
        return list_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def create_multipart_upload(bucket_name, key_name, end_point, ssl=None):
    """
    Initiate multipart uploads for given object on a given bucket
    Ex: /usr/local/bin/aws s3api create-multipart-upload --bucket <bucket_name> --key <key_name> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object for which multipart upload has to be initiated
        end_point(str): endpoint
        ssl:
    Return:
        Response of create-multipart-upload
    """
    create_mp_method = AWS(operation="create-multipart-upload")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = create_mp_method.command(
        params=[
            f"--bucket {bucket_name} --key {key_name} --endpoint-url {end_point}",
            ssl_param,
        ]
    )
    try:
        response = utils.exec_shell_cmd(command)
        if not response:
            raise Exception(
                f"creating multipart upload failed for bucket {bucket_name} with object name {key_name}"
            )
        return response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def upload_part(
    bucket_name, key_name, part_number, upload_id, body, end_point, ssl=None
):
    """
    Upload part to the key in a bucket
    Ex: /usr/local/bin/aws s3api upload-part --bucket <bucket_name> --key <key_name> --part-number <part_number>
        --upload-id <upload_id> --body <body> --endpoint <endpoint_url>

    Args:
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object for which part has to be uploaded
        part_number(int): part number
        upload_id(str): upload id fetched during initiating multipart upload
        body(str): part file which needed to be uploaded
        end_point(str): endpoint
        ssl:
    Return:
        Response of uplaod_part i.e Etag
    """
    upload_part_method = AWS(operation="upload-part")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = upload_part_method.command(
        params=[
            f"--bucket {bucket_name} --key {key_name} --part-number {part_number} --upload-id {upload_id}"
            f" --body {body} --endpoint-url {end_point}",
            ssl_param,
        ]
    )
    try:
        response = utils.exec_shell_cmd(command)
        if not response:
            raise Exception(
                f"Uploading part failed for bucket {bucket_name} with key {key_name} and upload id"
                f" {upload_id}"
            )
        return response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def complete_multipart_upload(
    bucket_name, key_name, upload_file, upload_id, end_point, ssl=None
):
    """
    Complete multipart uploads for given object on a given bucket
    Ex: /usr/local/bin/aws s3api complete-multipart-upload --multipart-upload file://<upload_file>
        --bucket <bucket_name> --key <key_name> --upload-id <upload_id> --endpoint <endpoint_url>
    Args:
        upload_file(str): Name of a file containing mpstructure
                          ex: {
                                  "Parts": [
                                    {
                                      "ETag": "e868e0f4719e394144ef36531ee6824c",
                                      "PartNumber": 1
                                    }
                                  ]
                                }
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object for which multipart upload has to be Completed
        upload_id(str): upload id fetched during initiating multipart upload
        end_point(str): endpoint
        ssl:
    Return:
        Response of create-multipart-upload
    """
    complete_mp_method = AWS(operation="complete-multipart-upload")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = complete_mp_method.command(
        params=[
            f"--multipart-upload file://{upload_file} --bucket {bucket_name} --key {key_name} --upload-id {upload_id} "
            f"--endpoint-url {end_point}",
            ssl_param,
        ]
    )
    try:
        response = utils.exec_shell_cmd(command)
        if not response:
            raise Exception(
                f"creating multipart upload failed for bucket {bucket_name} with key {key_name} and"
                f" upload id {upload_id}"
            )
        return response
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
        log.info(create_response)
        if not create_response:
            raise Exception(f"Create object failed for {bucket_name}")
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
        delete_response = utils.exec_shell_cmd(command)
        if not delete_response:
            raise Exception(f"delete object failed for {bucket_name}")
        return delete_response
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
        log.info(f"response of put versioning:{put_response}")
        if put_response:
            raise Exception(f"Version Enabling failed for {bucket_name}")
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


def upload_multipart_aws(
    bucket_name,
    key_name,
    TEST_DATA_PATH,
    endpoint,
    config,
    append_data=False,
    append_msg=None,
):
    """
    Args:
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object
        TEST_DATA_PATH(str): Test data path
        endpoint(str): endpoint url
        config: configuration used
        append_data(boolean)
        append_msg(str)
    Return:
        Response of aws complete multipart upload operation
    """
    log.info("Create multipart upload")
    create_mp_upload_resp = create_multipart_upload(bucket_name, key_name, endpoint)
    upload_id = json.loads(create_mp_upload_resp)["UploadId"]

    log.info(f"object name: {key_name}")
    object_path = os.path.join(TEST_DATA_PATH, key_name)
    log.info(f"object path: {object_path}")
    object_size = config.obj_size
    log.info(f"object_size: {object_size}")
    split_size = config.split_size if hasattr(config, "split_size") else 5
    log.info(f"split size: {split_size}")
    if append_data is True:
        data_info = io_generator(
            object_path,
            object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = io_generator(object_path, object_size)
    if data_info is False:
        TestExecError("data creation failed")

    mp_dir = os.path.join(TEST_DATA_PATH, key_name + ".mp.parts")
    log.info(f"mp part dir: {mp_dir}")
    log.info("making multipart object part dir")
    mkdir = utils.exec_shell_cmd(f"sudo mkdir {mp_dir}")
    if mkdir is False:
        raise TestExecError("mkdir failed creating mp_dir_name")
    utils.split_file(object_path, split_size, mp_dir + "/")
    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
    log.info("parts_list: %s" % parts_list)

    part_number = 1
    mpstructure = {"Parts": []}
    log.info("no of parts: %s" % len(parts_list))

    for each_part in parts_list:
        log.info(f"upload part {part_number} of object: {key_name}")
        upload_part_resp = json.loads(
            upload_part(
                bucket_name, key_name, part_number, upload_id, each_part, endpoint
            )
        )
        part_info = {"PartNumber": part_number, "ETag": upload_part_resp["ETag"]}
        mpstructure["Parts"].append(part_info)
        if each_part != parts_list[-1]:
            # increase the part number only if the current part is not the last part
            part_number += 1
        log.info("curr part_number: %s" % part_number)
    os.system("touch mpstructure.json")
    with open("mpstructure.json", "w") as fd:
        json.dump(mpstructure, fd)
    log.info(f"mpstructure data is: {mpstructure}")
    if config.local_file_delete is True:
        log.info("deleting local file part")
        utils.exec_shell_cmd(f"rm -rf {mp_dir}")

    if len(parts_list) == part_number:
        log.info("all parts upload completed")
        complete_multipart_upload_resp = json.loads(
            complete_multipart_upload(
                bucket_name, key_name, "mpstructure.json", upload_id, endpoint
            )
        )
        return complete_multipart_upload_resp


def get_object(bucket_name, object_name, end_point, ssl=None):
    """
    Does a get object from the bucket
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        ssl:
    Return:
        Response of get object operation
    """
    get_method = AWS(operation="get-object")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = get_method.command(
        params=[
            f"--bucket {bucket_name} --key {object_name} out_object --endpoint-url {end_point}",
            ssl_param,
        ]
    )
    try:
        get_response = utils.exec_shell_cmd(command)
        if "ETag" not in get_response:
            raise Exception(f"get object failed for {bucket_name}")
        return get_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))
