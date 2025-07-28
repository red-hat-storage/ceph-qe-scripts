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
import time
from configparser import RawConfigParser
from pathlib import Path

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

import v2.utils.utils as utils
from v2.lib.exceptions import AWSCommandExecError, TestExecError
from v2.lib.manage_data import io_generator


def create_bucket(aws_auth, bucket_name, end_point):
    """
    Creates bucket
    ex: /usr/local/bin/aws s3api create-bucket --bucket verbkt1 --endpoint-url http://x.x.x.x:xx
    Args:
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
    """
    command = aws_auth.command(
        operation="create-bucket",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    try:
        create_response = utils.exec_shell_cmd(command, return_err=True)
        log.info(f"bucket creation response is {create_response}")
        if create_response:
            raise Exception(f"Create bucket failed for {bucket_name}")
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def list_buckets(aws_auth, endpoint):
    """
    List all the buckets the user ownes
    Args:
        aws_auth: user auth details
        end_point(str): endpoint
    Return:
        Returns details of buckets
    """
    command = aws_auth.command(
        operation="list-buckets",
        params=[
            f"--endpoint-url {endpoint}",
        ],
    )
    try:
        get_response = utils.exec_shell_cmd(command)
        return get_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_bkt_acl(aws_auth, bucket_name, end_point, acl):
    """
    Put bucket acl
    ex: /usr/local/bin/aws s3api put-bucket-acl --bucket buck1 --acl public-read-write --endpoint-url http://x.x.x.x:xx
    Args:
        bucket_name(str): Name of the bucket
        acl(str): acl type
        end_point(str): endpoint
    """
    command = aws_auth.command(
        operation="put-bucket-acl",
        params=[f"--bucket {bucket_name} --acl {acl} --endpoint-url {end_point}"],
    )
    try:
        acl_put_response = utils.exec_shell_cmd(command)
        log.info(f"Put acl response is {acl_put_response}")
        if acl_put_response:
            raise Exception(f"Put acl failed for bucket {bucket_name}")
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def get_bkt_acl(aws_auth, bucket_name, end_point):
    """
    Get bucket acl
    ex: /usr/local/bin/aws s3api get-bucket-acl --bucket buck1 --endpoint-url http://x.x.x.x:xx
    Args:
        bucket_name(str): Name of the bucket
        end_point(str): endpoint
    """
    command = aws_auth.command(
        operation="get-bucket-acl",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    try:
        acl_get_response = utils.exec_shell_cmd(command)
        log.info(f"Get acl response is {acl_get_response}")
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def list_object_versions(aws_auth, bucket_name, end_point):
    """
    Lists object versions for an bucket
    Ex: /usr/local/bin/aws s3api list-object-versions --bucket <bucket_name> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
    Return:
        Response of list-object-versions operation
    """
    command = aws_auth.command(
        operation="list-object-versions",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    try:
        list_response = utils.exec_shell_cmd(command)
        if not list_response:
            raise Exception(f"List object versions on bucket failed for {bucket_name}")
        return list_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def create_multipart_upload(
    aws_auth, bucket_name, key_name, end_point, checksum_algo=None
):
    """
    Initiate multipart uploads for given object on a given bucket
    Ex: /usr/local/bin/aws s3api create-multipart-upload --bucket <bucket_name> --key <key_name> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object for which multipart upload has to be initiated
        end_point(str): endpoint
    Return:
        Response of create-multipart-upload
    """
    if checksum_algo:
        command = aws_auth.command(
            operation="create-multipart-upload",
            params=[
                f"--bucket {bucket_name} --key {key_name} --endpoint-url {end_point} --checksum-algorithm {checksum_algo}",
            ],
        )
    else:
        command = aws_auth.command(
            operation="create-multipart-upload",
            params=[
                f"--bucket {bucket_name} --key {key_name} --endpoint-url {end_point}",
            ],
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


def upload_part_copy(
    aws_auth,
    bucket_name,
    key_name,
    part_number,
    upload_id,
    version_id,
    endpoint,
    ignore_error=False,
):
    """
    Method to perform upload part copy operation using awscli
    Ex: /usr/local/bin/aws s3api upload-part-copy --bucket <bucket_name> --key <object_name> --copy-source <source_version>
        --part-number <part_number> --upload-id <upload_id> --endpoint <endpoint>
    Args:
        bucket_name(str): Name of the bucket
        key_name(str): Name of teh object
        part_number(int): part number
        upload_id(str): upload id of initiated multipart upload
        version_id(str): version id of the object to be copied
        end_point(str): endpoint
    Return:
        Response of upload_part_copy operation

    """
    command = aws_auth.command(
        operation="upload-part-copy",
        params=[
            f"--bucket {bucket_name} --key {key_name} --copy-source '{bucket_name}/{key_name}?versionId={version_id}' --part-number {part_number} --upload-id {upload_id}"
            f" --endpoint {endpoint}",
        ],
    )
    try:
        response = utils.exec_shell_cmd(command, return_err=True)
        if not response:
            if ignore_error:
                log.info(
                    f"Uploading part copy with source failed for bucket {bucket_name} with key {key_name} and upload id {upload_id}"
                )
                return response
            else:
                raise Exception(
                    f"Uploading part copy with source failed for bucket {bucket_name} with key {key_name} and upload id"
                    f" {upload_id}"
                )
        return response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def upload_part(
    aws_auth,
    bucket_name,
    key_name,
    part_number,
    upload_id,
    body,
    end_point,
    checksum_algo=None,
    checksum=None,
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
    Return:
        Response of uplaod_part i.e Etag
    """
    if checksum_algo:
        if checksum_algo is "crc32c":
            algo = "crc32-c"
        else:
            algo = checksum_algo
        cmd = f"--body {body} --endpoint-url {end_point} --checksum-algorithm {checksum_algo}"
        if checksum:
            cmd = cmd + f" --checksum-{algo} {checksum}"
        command = aws_auth.command(
            operation="upload-part",
            params=[
                f"--bucket {bucket_name} --key {key_name} --part-number {part_number} --upload-id {upload_id}"
                f" {cmd}",
            ],
        )
    else:
        command = aws_auth.command(
            operation="upload-part",
            params=[
                f"--bucket {bucket_name} --key {key_name} --part-number {part_number} --upload-id {upload_id}"
                f" --body {body} --endpoint-url {end_point}",
            ],
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
    aws_auth, bucket_name, key_name, upload_file, upload_id, end_point
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
    Return:
        Response of create-multipart-upload
    """
    command = aws_auth.command(
        operation="complete-multipart-upload",
        params=[
            f"--multipart-upload file://{upload_file} --bucket {bucket_name} --key {key_name} --upload-id {upload_id} "
            f"--endpoint-url {end_point}",
        ],
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


def put_object(aws_auth, bucket_name, object_name, end_point):
    """
    Put/uploads object to the bucket
    Ex: /usr/local/bin/aws s3api put-object --bucket <bucket_name> --key <object_name> --body <content> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
    Return:
        Response of put-object operation
    """
    command = aws_auth.command(
        operation="put-object",
        params=[
            f"--bucket {bucket_name} --key {object_name} --body {object_name} --endpoint-url {end_point}",
        ],
    )
    try:
        create_response = utils.exec_shell_cmd(command)
        log.info(create_response)
        if not create_response:
            raise Exception(f"Create object failed for {bucket_name}")
        return create_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_object_checksum(
    aws_auth, bucket_name, object_name, end_point, checksum_algorithm, checksum=None
):
    """
    Put/uploads object to the bucket with provided checksum value
    Ex: /usr/local/bin/aws s3api put-object --bucket <bucket_name> --key <object_name> --body <content> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        checksum_algorithm: one of sha1,sha256,crc32,crc-32c
        checksum
    Return:

    """
    if checksum_algorithm is "crc32c":
        algo = "crc32-c"
    else:
        algo = checksum_algorithm
    command = aws_auth.command(
        operation="put-object",
        params=[
            f"--bucket {bucket_name} --key {object_name} --body {object_name} --endpoint-url {end_point} --checksum-algorithm {checksum_algorithm} --checksum-{algo} {checksum}",
        ],
    )

    out = utils.exec_shell_cmd(command, return_err=True)
    if out:
        log.info(f"Output : {out}")
        if "not iterable" in out:
            log.info("Upload failed as expected for wrong checksum")
        else:
            log.info(f"Upload successful for {algo}")
    else:
        raise AssertionError("Upload failed")


def delete_object(aws_auth, bucket_name, object_name, end_point, versionid=None):
    """
    Deletes object from the bucket
    Ex: /usr/local/bin/aws s3api delete-object --bucket <bucket_name> --key <object_name> --endpoint <endpoint_url>
        --version-id {versionid}
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        versionid(str): Id of object version which needs to be deleted
    Return:
        Response of delete-object operation
    """
    command = aws_auth.command(
        operation="delete-object",
        params=[
            f"--bucket {bucket_name} --key {object_name} --endpoint-url {end_point}",
        ],
    )
    if versionid:
        command = aws_auth.command(
            operation="delete-object",
            params=[
                f"--bucket {bucket_name} --key {object_name} --endpoint-url {end_point}"
                f" --version-id {versionid}",
            ],
        )
    try:
        delete_response = utils.exec_shell_cmd(command)
        if not delete_response:
            raise Exception(f"delete object failed for {bucket_name}")
        return delete_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_get_bucket_versioning(aws_auth, bucket_name, end_point, status="Enabled"):
    """
    make bucket created as versioned
    ex:
    /usr/local/bin/aws s3api  put-bucket-versioning --bucket versioned-bkt-3 --versioning-configuration Status=Enabled --endpoint http://x.x.x.x:xx
    /usr/local/bin/aws s3api get-bucket-versioning --bucket versioned-bkt-1 --endpoint http://x.x.x.x:xx
    Args:
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
    """
    put_cmd = aws_auth.command(
        operation=f"put-bucket-versioning --versioning-configuration Status={status}",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    try:
        put_response = utils.exec_shell_cmd(put_cmd)
        log.info(f"response of put versioning:{put_response}")
        if put_response:
            raise Exception(f"Version Enabling failed for {bucket_name}")
        get_cmd = aws_auth.command(
            operation="get-bucket-versioning",
            params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
        )
        get_response = json.loads(utils.exec_shell_cmd(get_cmd))
        if get_response["Status"] != status:
            raise Exception(
                f"Get bucket version response is not as expected: {get_response}"
            )
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def get_endpoint(ssh_con=None, ssl=None, haproxy=None):
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
    if haproxy:
        port = 5000
    ip_and_port = f"http://{ip}:{port}"
    if ssl:
        ip_and_port = f"https://{ip}:{port}"
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
    aws_auth, bucket_name, object_name, endpoint, created=True
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
    version_list = list_object_versions(aws_auth, bucket_name, endpoint)
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
    aws_auth,
    bucket_name,
    key_name,
    TEST_DATA_PATH,
    endpoint,
    config,
    append_data=False,
    append_msg=None,
    checksum_algo=None,
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
    create_mp_upload_resp = create_multipart_upload(
        aws_auth, bucket_name, key_name, endpoint, checksum_algo
    )
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
                aws_auth,
                bucket_name,
                key_name,
                part_number,
                upload_id,
                each_part,
                endpoint,
                checksum_algo=checksum_algo,
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
                aws_auth, bucket_name, key_name, "mpstructure.json", upload_id, endpoint
            )
        )
        return complete_multipart_upload_resp


def get_object(aws_auth, bucket_name, object_name, end_point):
    """
    Does a get object from the bucket
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
    Return:
        Response of get object operation
    """
    command = aws_auth.command(
        operation="get-object",
        params=[
            f"--bucket {bucket_name} --key {object_name} out_object --endpoint-url {end_point}",
        ],
    )
    try:
        get_response = utils.exec_shell_cmd(command)
        if "ETag" not in get_response:
            raise Exception(f"get object failed for {bucket_name}")
        return get_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def copy_object(aws_auth, bucket_name, object_name, end_point):
    """
    Does a copy object from the bucket
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
    Return:
        Response of get object operation
    """
    command = aws_auth.command(
        operation="copy-object",
        params=[
            f"--copy-source {bucket_name}/{object_name} --bucket {bucket_name} --key {object_name}  --metadata-directive 'REPLACE' --content-type 'text/plain' --endpoint-url {end_point}",
        ],
    )
    try:
        copy_response = utils.exec_shell_cmd(command)
        return copy_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def list_objects(aws_auth, bucket_name, endpoint, marker=None):
    """
    List all the objects in the bucket
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
        marker(str): The key name from where the listing needs to start
    Return:
        Returns details of every object in the bucket post the marker
    """
    if marker:
        marker_param = marker
    else:
        marker_param = " "
    command = aws_auth.command(
        operation="list-objects",
        params=[
            f"--bucket {bucket_name} --marker {marker_param} --endpoint-url {endpoint}",
        ],
    )
    try:
        get_response = utils.exec_shell_cmd(command)
        return get_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_bucket_cors(aws_auth, bucket_name, policy_file, endpoint):
    """
    Put a CORS policy on the bucket
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
        policy(json): CORS policy to Upload
    Return:
    """
    command = aws_auth.command(
        operation="put-bucket-cors",
        params=[
            f"--bucket {bucket_name} --cors-configuration file://{policy_file} --endpoint-url {endpoint}",
        ],
    )
    try:
        create_response = utils.exec_shell_cmd(command, debug_info=True)
        log.info(create_response)
        if not create_response:
            raise Exception(f"Put CORS policy failed for {bucket_name}")
        return create_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def calculate_checksum(algo, file):
    """
    Return the base64 encoded checksum for the provided algorithm
    """
    log.info("Install Rhash program")
    utils.exec_shell_cmd(
        "rpm -ivh https://rpmfind.net/linux/epel/9/Everything/x86_64/Packages/r/rhash-1.4.2-1.el9.x86_64.rpm"
    )
    time.sleep(2)
    if algo is "sha1" or "sha256":
        checksum = utils.exec_shell_cmd(f"rhash --sha1 --base64 {file}").split(" ", 1)[
            0
        ]
        return checksum
    elif algo is "crc32":
        checksum = utils.exec_shell_cmd(f"rhash --crc32 --base64 {file}").split(" ", 1)[
            1
        ]
        return checksum
    elif algo is "crc32c":
        utils.exec_shell_cmd("sudo pip install botocore[crt]")
        checksum = utils.exec_shell_cmd(f"rhash --crc32c --base64 {file}").split(
            " ", 1
        )[0]
        return checksum


def get_object_attributes(aws_auth, bucket_name, key, endpoint):
    """
    Return object attributes for a specified key name in a bucket
    """
    command = aws_auth.command(
        operation="get-object-attributes",
        params=[
            f"--bucket {bucket_name} --key {key}  --endpoint-url {endpoint} --object-attributes checksum",
        ],
    )
    try:
        resp = utils.exec_shell_cmd(command)
        if "Checksum" not in resp:
            raise Exception(f"get object failed for {bucket_name}")
        log.info("Checksum is present in object attributes")
        return resp
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def put_keystone_conf(rgw_service_name, user, passw, project, tenant="true"):
    """
    Apply the conf options required for keystone integration to rgw service
    """
    log.info("Apply keystone conf options")
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_api_version 3"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_admin_user {user}"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_admin_password {passw}"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_admin_domain Default"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_admin_project {project}"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_implicit_tenants {tenant}"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_keystone_accepted_roles admin,user"
    )
    utils.exec_shell_cmd(
        f"ceph config set client.{rgw_service_name} rgw_s3_auth_use_keystone true"
    )
    log.info("restart RGW for options to take effect")
    utils.exec_shell_cmd(f"ceph orch restart {rgw_service_name}")
    time.sleep(20)


def verify_namespace_swift(keystone_server, bucket, rgw_ip, port, user="admin"):
    """
    Verify the unified namespace behaviour from swift
    """
    ssh = utils.connect_remote(keystone_server)
    log.info("Setting up swift endpoints")
    cmd = f"source /home/cephuser/key_{user}.rc; openstack endpoint create --region RegionOne swift internal http://{rgw_ip}:{port}/swift/v1; openstack endpoint create --region RegionOne swift public http://{rgw_ip}:{port}/swift/v1; openstack endpoint create --region RegionOne swift admin http://{rgw_ip}:{port}/swift/v1"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)

    cmd = f"source /home/cephuser/key_{user}.rc; swift list"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    if bucket in out:
        log.info("S3 bucket visible to swift")
    else:
        raise TestExecError("S3 bucket not visible to swift, diverged namespace")
    sw_bucket = "swift_bucket"
    cmd = f"source /home/cephuser/key_{user}.rc; swift post {sw_bucket}"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    return sw_bucket


def get_ec2_details(keystone_server, sw_user):
    """Get EC2 credentials and project details for swift user"""
    ssh = utils.connect_remote(keystone_server)
    cmd = f"source /home/cephuser/key_{sw_user}.rc; openstack ec2 credentials list"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    line = out.splitlines()[3]
    if not line:
        log.info("Ec2 user not created for this project")
        raise TestExecError
    access = line.split("|")[1].strip()
    secret = line.split("|")[2].strip()
    project = line.split("|")[3].strip()
    return access, secret, project


def cleanup_keystone(keystone_server, user="admin"):
    """
    Delete the swift endpoints added earlier from the keystone server
    """
    ssh = utils.connect_remote(keystone_server)
    log.info("Deleting the swift endpoints")
    cmd = f"source /home/cephuser/key_{user}.rc; openstack endpoint list"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    idlist = []
    for line in out.splitlines():
        if "swift" in line:
            idlist.append(line.split("|")[1].strip())

    for endpoint in idlist:
        cmd = (
            f"source /home/cephuser/key_{user}.rc; openstack endpoint delete {endpoint}"
        )
        out = utils.remote_exec_shell_cmd(ssh, cmd)


def perform_gc_process_and_list():
    """
    Method to Perform GC process and validate GC list post process
    """
    utils.exec_shell_cmd("radosgw-admin gc list --include-all")
    utils.exec_shell_cmd("radosgw-admin gc process --include-all")
    out = utils.exec_shell_cmd("radosgw-admin gc list --include-all")
    gc_list = json.loads(out)
    if len(gc_list) != 0:
        raise AssertionError("GC process does not emptied the GC list")
