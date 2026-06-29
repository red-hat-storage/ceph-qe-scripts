"""
Reusable methods for aws
"""

import copy
import glob
import json
import logging
import os
import random
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from configparser import RawConfigParser
from pathlib import Path

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

import v2.utils.utils as utils
from v2.lib.exceptions import AWSCommandExecError, TestExecError
from v2.lib.manage_data import io_generator


def create_bucket(
    aws_auth,
    bucket_name,
    end_point,
    region=None,
    retries=3,
    wait_time=5,
    object_lock_enabled=False,
):
    """
    Creates bucket
    ex: /usr/local/bin/aws s3api create-bucket --bucket verbkt1 --endpoint-url http://x.x.x.x:xx
    ex: /usr/local/bin/aws s3api create-bucket --bucket bkt1 --object-lock-enabled-for-bucket ...
    Args:
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
        object_lock_enabled(bool): pass --object-lock-enabled-for-bucket on create
    """

    for attempt in range(1, retries + 1):
        output = utils.exec_shell_cmd(f"curl -k --connect-timeout 10 {end_point}")
        if output:
            log.info(f"Endpoint {end_point} is reachable on attempt {attempt}.")
            break
        else:
            log.warning(
                f"Attempt {attempt}: Endpoint {end_point} not reachable, retrying in {wait_time}s..."
            )
            time.sleep(wait_time)
    else:
        log.error(f"Endpoint {end_point} is not reachable after {retries} attempts.")
        return

    if region:
        command = aws_auth.command(
            operation="create-bucket",
            params=[
                f"--bucket {bucket_name} --region {region} --create-bucket-configuration LocationConstraint={region} --endpoint-url {end_point}"
            ],
        )
    else:
        command = aws_auth.command(
            operation="create-bucket",
            params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
        )
    bucket_params = f"--bucket {bucket_name} --endpoint-url {end_point}"
    if object_lock_enabled:
        bucket_params += " --object-lock-enabled-for-bucket"
    command = aws_auth.command(
        operation="create-bucket",
        params=[bucket_params],
    )
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            create_response = utils.exec_shell_cmd(command)
            log.info(f"bucket creation response is {create_response}")
            return
        except Exception as e:
            last_error = e
            log.warning(
                f"Attempt {attempt}: Create bucket {bucket_name} failed: {e}. "
                f"Retrying in {wait_time}s..."
            )
            if attempt < retries:
                time.sleep(wait_time)
    raise AWSCommandExecError(message=str(last_error))


def verify_bucket_object_lock_stats(bucket_name, expected_objects=None):
    """
    Verify bucket stats show versioning enabled and object lock enabled.
    Optionally assert minimum object count in rgw.main usage.
    """
    out = utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket_name}")
    data = json.loads(out)
    info = data[0] if isinstance(data, list) else data
    if info.get("versioning") != "enabled":
        raise AssertionError(
            f"Bucket {bucket_name}: expected versioning enabled, got {info.get('versioning')}"
        )
    if not info.get("object_lock_enabled"):
        raise AssertionError(
            f"Bucket {bucket_name}: expected object_lock_enabled true, got {info.get('object_lock_enabled')}"
        )
    if expected_objects is not None:
        usage = info.get("usage", {})
        main_usage = usage.get("rgw.main", {})
        num_objects = main_usage.get("num_objects", 0)
        if num_objects < expected_objects:
            raise AssertionError(
                f"Bucket {bucket_name}: expected at least {expected_objects} objects, got {num_objects}"
            )
    log.info(
        f"Bucket {bucket_name}: versioning=enabled, object_lock_enabled=true"
        + (f", num_objects>={expected_objects}" if expected_objects is not None else "")
    )
    return info


def get_object_lock_configuration(aws_auth, bucket_name, end_point):
    """Return parsed get-object-lock-configuration response."""
    command = aws_auth.command(
        operation="get-object-lock-configuration",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    out = utils.exec_shell_cmd(command)
    if not out:
        raise Exception(f"get-object-lock-configuration failed for {bucket_name}")
    return json.loads(out)


def put_object_lock_default_retention(
    aws_auth, bucket_name, end_point, mode="COMPLIANCE", days=1
):
    """Apply bucket default retention policy via put-object-lock-configuration."""
    lock_cfg = json.dumps(
        {
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": mode, "Days": days}},
        }
    )
    command = aws_auth.command(
        operation="put-object-lock-configuration",
        params=[
            f"--bucket {bucket_name} --endpoint-url {end_point} "
            f"--object-lock-configuration '{lock_cfg}'"
        ],
    )
    out = utils.exec_shell_cmd(command)
    if out is False:
        raise Exception(f"put-object-lock-configuration failed for {bucket_name}")
    log.info(f"Set default retention {mode} {days} day(s) on {bucket_name}")


LUA_ENABLE_OBJECT_LOCK_PREREQUEST = """
-- enablog object lock on bucket creation

if Request.RGWOp == "create_bucket" then
  Request.HTTP.Metadata["x-amz-bucket-object-lock-enabled"] = "true"
  RGWDebugLog("object lock is enabled on bucket: " .. Request.Bucket.Name)
end
"""

LUA_ENABLE_OBJECT_LOCK_DEBUG_PATTERN = r"object lock is enabled on bucket"

LUA_BLOCK_OBJECT_LOCK_PREREQUEST = """
-- enforcing object lock on bucket creation

if Request.RGWOp == "create_bucket" and
  Request.HTTP.Metadata["x-amz-bucket-object-lock-enabled"] ~= "true" then
  RGWDebugLog("object lock is missing on bucket: " .. Request.Bucket.Name)
  Request.Response.Message = "Bucket must have object lock enabled"
  return RGW_ABORT_REQUEST
end
"""

LUA_BLOCK_OBJECT_LOCK_DEBUG_PATTERN = r"object lock is missing on bucket"


def delete_bucket(aws_auth, bucket_name, end_point):
    """
    deletes bucket
    ex: /usr/local/bin/aws s3api delete-bucket --bucket verbkt1 --endpoint-url http://x.x.x.x:xx
    Args:
        aws_auth: user auth details
        bucket_name(str): Name of the bucket to be created
        end_point(str): endpoint
    """
    command = aws_auth.command(
        operation="delete-bucket",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    try:
        delete_response = utils.exec_shell_cmd(command, return_err=True)
        log.info(f"bucket deletion response is {delete_response}")
        if delete_response:
            raise Exception(f"delete bucket failed for {bucket_name}")
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
        if not response or response is False:
            raise Exception(
                f"creating multipart upload failed for bucket {bucket_name} with object name {key_name}. Response: {response}"
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
        if checksum_algo == "crc32c":
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
                f"complete multipart upload failed for bucket {bucket_name} with key {key_name} and"
                f" upload id {upload_id}"
            )
        return response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def conditional_put_object(
    aws_auth, bucket_name, object_name, end_point, etag=None, return_err=False
):
    """
    Put/uploads object to the bucket based on given condition matches
    Ex: /usr/local/bin/aws s3api put-object --bucket <bucket_name> --key <object_name> --body <content> --endpoint <endpoint_url> --if-none-match | --if-match <Etag>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        etag(str): if Etag given checks for condition --if-match <etag> else proceed with condition --if-none-match "*"
        return_err(boolean): If True returns error
    """
    params = [f"--bucket {bucket_name} --key {object_name} --endpoint-url {end_point}"]
    if etag:
        params = [params[0] + f" --if-match {etag}"]
    else:
        params = [params[0] + f' --if-none-match "*"']

    command = aws_auth.command(
        operation="put-object",
        params=params,
    )
    try:
        put_response = utils.exec_shell_cmd(command, return_err=True)
        log.info(f"delete object response: {put_response}")
        if not put_response and not return_err:
            raise Exception(f"delete object failed for {bucket_name}")
        return put_response
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
    aws_auth,
    bucket_name,
    object_name,
    end_point,
    checksum_algorithm,
    checksum=None,
    s3_object_path=None,
    failure_expected=False,
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
        s3_object_path
        failure_expected
    Return:

    """
    if checksum_algorithm == "crc32c":
        algo = "crc32-c"
    elif checksum_algorithm == "crc64nvme":
        algo = "crc64-nvme"
    else:
        algo = checksum_algorithm
    body = s3_object_path if s3_object_path else object_name
    cmd = (
        f"--bucket {bucket_name} --key {object_name} --body {body} "
        f"--endpoint-url {end_point} --checksum-algorithm {checksum_algorithm}"
    )
    cmd = cmd + f" --checksum-{algo} {checksum}"
    command = aws_auth.command(
        operation="put-object",
        params=[cmd],
    )

    out = utils.exec_shell_cmd(command)
    log.info(f"Output : {out}")
    if out is False:
        if failure_expected:
            log.info("Upload failed as expected for wrong checksum")
        else:
            raise Exception(f"put object with checksum failed for {bucket_name}")

    else:
        log.info(f"Upload successful for {algo}")
        return out


def validate_gc():
    """
    Method to Check for GC list creation and validates GC process
    """
    log.info("Verify GC Process")
    cmd1 = f"radosgw-admin gc list --include-all"
    gc_list = utils.exec_shell_cmd(cmd1)
    gc_list_json = json.loads(gc_list)
    if len(gc_list_json) == 0:
        raise AssertionError("GC list not generated for deleted objects")
    utils.exec_shell_cmd("radosgw-admin gc process --include-all")
    gc_list = utils.exec_shell_cmd(cmd1)
    gc_list_json = json.loads(gc_list)
    if len(gc_list_json) != 0:
        raise AssertionError("GC process is not successful!")


def conditional_delete_object(
    aws_auth,
    bucket_name,
    object_name,
    end_point,
    versionid=None,
    etag=None,
    last_modified_time=None,
    size=None,
    return_err=False,
):
    """
    Method to perform conditional delete operation using Etag, Last modified time and size of the object
    Ex: /usr/local/bin/aws s3api delete-object --bucket <bucket_name> --key <object_name> --endpoint <endpoint_url> --if-match <etag> |
    --if-match-last-modified-time <last_modified_time> | --if-match-size <size> | --version-id <versionid>
    Args:
        aws_auth: authentication for awscli
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        versionid(str): version id of object
        etag(str): etag of an object
        last_modified_time(str): last modified time of an object
        size(int): size of an object
        return_err(boolean): if true returns error
    Return:

    """
    params = [f"--bucket {bucket_name} --key {object_name} --endpoint-url {end_point}"]

    if versionid:
        params = [params[0] + f" --version-id {versionid}"]

    if etag:
        params = [params[0] + f" --if-match {etag}"]

    if last_modified_time:
        params = [params[0] + f" --if-match-last-modified-time {last_modified_time}"]

    if size:
        params = [params[0] + f" --if-match-size {size}"]

    command = aws_auth.command(
        operation="delete-object",
        params=params,
    )
    try:
        delete_response = utils.exec_shell_cmd(command, return_err=True)
        log.info(f"delete object response: {delete_response}")
        if delete_response is False and not return_err:
            raise Exception(f"delete object failed for {bucket_name}")
        return delete_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


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
        log.info(f"delete object response: {delete_response}")
        if delete_response is False:
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
        _, stdout, _ = ssh_con.exec_command("hostname -I")
        ip = stdout.readline().strip().split()[0]  # first IP
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
    if not create_mp_upload_resp or create_mp_upload_resp is False:
        raise TestExecError(
            f"Failed to create multipart upload for bucket {bucket_name} with key {key_name}. Response was: {create_mp_upload_resp}"
        )
    if not isinstance(create_mp_upload_resp, str):
        raise TestExecError(
            f"Invalid response type for multipart upload. Expected string, got {type(create_mp_upload_resp)}: {create_mp_upload_resp}"
        )
    try:
        upload_id = json.loads(create_mp_upload_resp)["UploadId"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise TestExecError(
            f"Failed to parse multipart upload response for bucket {bucket_name} with key {key_name}. "
            f"Response: {create_mp_upload_resp}, Error: {e}"
        )

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


def get_object(
    aws_auth, bucket_name, object_name, end_point, download_path="out_object"
):
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
            f"--bucket {bucket_name} --key {object_name} {download_path} --endpoint-url {end_point}",
        ],
    )
    try:
        get_response = utils.exec_shell_cmd(command)
        if "ETag" not in get_response:
            raise Exception(f"get object failed for {bucket_name}")
        return get_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def copy_object(aws_auth, bucket_name, object_name, end_point, dest_obj_name=None):
    """
    Does a copy object from the bucket
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        dest_obj_name(str): destination object name
    Return:
        Response of get object operation
    """
    command = aws_auth.command(
        operation="copy-object",
        params=[
            f"--copy-source {bucket_name}/{object_name} --bucket {bucket_name} --key {dest_obj_name if dest_obj_name else object_name} {'--metadata-directive REPLACE' if dest_obj_name is None else ''} --content-type 'text/plain' --endpoint-url {end_point}",
        ],
    )
    try:
        copy_response = utils.exec_shell_cmd(command)
        if copy_response is False:
            raise Exception(f"copy object failed for {object_name}")
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
        marker_param = f"--marker {marker}"
    else:
        marker_param = " "
    command = aws_auth.command(
        operation="list-objects",
        params=[
            f"--bucket {bucket_name} {marker_param} --endpoint-url {endpoint}",
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

    if algo == "sha1" or algo == "sha256":
        checksum = utils.exec_shell_cmd(f"rhash --{algo} --base64 {file}").split(
            " ", 1
        )[0]
        return checksum
    elif algo == "crc32":
        checksum = (
            utils.exec_shell_cmd(f"rhash --crc32 --base64 {file}")
            .strip()
            .split("\n")[-1]
            .split(" ")[1]
        )
        return checksum
    elif algo == "crc32c":
        checksum = utils.exec_shell_cmd(f"rhash --crc32c --base64 {file}").split(
            " ", 1
        )[0]
        return checksum
    elif algo == "crc64nvme":
        out = utils.exec_shell_cmd(
            f'venvawsv1/bin/python -c \'import awscrt.checksums, base64; print(base64.b64encode(awscrt.checksums.crc64nvme(open("{file}","rb").read()).to_bytes(8,"big")).decode())\''
        )
        if out is False:
            raise Exception("crc64nvme calculation failed")
        checksum = out.strip()
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
        resp = json.loads(resp)
        return resp
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def verify_checksum(response, checksum_algo, checksum, upload_type):
    """
    verifying checksum fields (checksum and checksum_type) in the response
    """
    log.info("verifying checksum fields in the response")
    checksum_key = f"Checksum{str(checksum_algo).upper()}"
    checksum_type = response["ChecksumType"]

    checksum_type_expected = "FULL_OBJECT"
    if checksum_algo == "sha1" or checksum_algo == "sha256":
        if upload_type == "multipart":
            checksum_type_expected = "COMPOSITE"
    if checksum_type != checksum_type_expected:
        raise AssertionError(
            f"Checksum not same as expected in the response. Expected {checksum_type_expected}, but received {checksum_type}"
        )
    else:
        log.info("checksum_type verified successfully")

    if response[checksum_key] != checksum:
        if checksum_type == "COMPOSITE":
            log.info(
                f"As it is a COMPOSITE checksum, checksum is different than locally calculated entire object checksum '{checksum}'"
            )
        else:
            raise AssertionError("Checksum not same as expected in the response")
    log.info(f"{checksum_key} verified successfully")


def put_keystone_conf(rgw_service_name, user, passw, project, tenant="true"):
    """
    Apply the conf options required for keystone integration to rgw service
    """
    log.info("Apply keystone conf options")
    ceph_version_id, version_name = utils.get_ceph_version()
    ceph_version_id = ceph_version_id.split("-")[0]
    ceph_version_id = ceph_version_id.split(".")[0]
    if ceph_version_id < "20":
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


def create_s3_replication_json(config, bucket_name, json_file="replication.json"):
    """
    Extract replication config from a YAML file and apply it to a bucket.
    Ceph 8.1 (< 20.2.1): plain bucket name. Ceph 9.0+ (>= 20.2.1): bucket ARN.
    """
    replication_config = copy.deepcopy(config.test_ops["s3_replication"])
    dest_bucket = bucket_name
    if dest_bucket.startswith("arn:aws:s3:::"):
        dest_bucket = dest_bucket[len("arn:aws:s3:::") :]
    ceph_version_id, _ = utils.get_ceph_version()
    release = ceph_version_id.split("-")[0].split(".")
    if len(release) >= 3:
        try:
            if (int(release[0]), int(release[1]), int(release[2])) >= (20, 2, 1):
                dest_bucket = f"arn:aws:s3:::{dest_bucket}"
        except ValueError:
            pass
    replication_config["Rules"][0]["Destination"]["Bucket"] = dest_bucket
    log.info(f"replication configuration data: {replication_config}")
    with open(json_file, "w") as f:
        json.dump(replication_config, f, indent=4)


def put_bucket_s3_replication(
    aws_auth, bucket_name, end_point, json_file="replication.json"
):
    """
    Put bucket s3 replication
    Ex: /usr/local/bin/aws s3api put-bucket-replication --bucket <bucket> --replication-configuration file://replication.json --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
        json_file(str): Name/path of the file
    Return:
        Response of put-bucket-replication operation
    """
    command = aws_auth.command(
        operation="put-bucket-replication",
        params=[
            f"--bucket {bucket_name} --replication-configuration file://{json_file} --endpoint-url {end_point}",
        ],
    )
    try:
        put_response = utils.exec_shell_cmd(command)
        if put_response is False:
            raise Exception(f"put s3 replication failed for bucket {bucket_name}")
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def get_bucket_s3_replication(aws_auth, bucket_name, end_point):
    """
    Get bucket s3 replication
    Ex: /usr/local/bin/aws s3api get-bucket-replication --bucket <bucket> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
    Return:
        Response of get-bucket-replication operation
    """
    command = aws_auth.command(
        operation="get-bucket-replication",
        params=[
            f"--bucket {bucket_name} --endpoint-url {end_point}",
        ],
    )
    try:
        get_response = utils.exec_shell_cmd(command)
        log.info(get_response)
        if not get_response:
            raise Exception(f"get s3 replication failed for bucket {bucket_name}")
        return get_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def delete_bucket_s3_replication(aws_auth, bucket_name, end_point):
    """
    Delete bucket s3 replication
    Ex: /usr/local/bin/aws s3api delete-bucket-replication --bucket <bucket> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        end_point(str): endpoint
    Return:
        Response of delete-bucket-replication operation
    """
    command = aws_auth.command(
        operation="delete-bucket-replication",
        params=[
            f"--bucket {bucket_name} --endpoint-url {end_point}",
        ],
    )
    try:
        delete_response = utils.exec_shell_cmd(command)
        log.info(delete_response)
        if delete_response is False:
            raise Exception(f"delete s3 replication failed for bucket {bucket_name}")
        return delete_response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def set_lua_script(context, script_content=None, script_file=None, rgw_realm=None):
    """
    Set a Lua script using radosgw-admin.
    Parameters:
        context (str): Script context - must be "prerequest", "postrequest", "background", "getdata", or "putdata"
        script_content (str, optional): Lua script content as a string
        script_file (str, optional): Path to a file containing the Lua script
        rgw_realm (str, optional): RGW realm name
    Returns:
        str: Output from the radosgw-admin command
    Raises:
        TestExecError: If script setting fails or if both script_content and script_file are provided
    """
    valid_contexts = ["prerequest", "postrequest", "background", "getdata", "putdata"]
    if context not in valid_contexts:
        raise TestExecError(f"Context must be one of {valid_contexts}, got: {context}")

    if script_content and script_file:
        raise TestExecError(
            "Cannot specify both script_content and script_file. Use only one."
        )

    if not script_content and not script_file:
        raise TestExecError("Either script_content or script_file must be provided.")

    log.info(f"Setting Lua script with context: {context}")
    cmd = f"radosgw-admin script put --context={context}"
    if rgw_realm:
        cmd += f" --rgw-realm={rgw_realm}"

    if script_file:
        if not os.path.exists(script_file):
            raise TestExecError(f"Script file not found: {script_file}")
        cmd += f" --infile={script_file}"
        log.info(f"Using script file: {script_file}")
    else:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".lua", delete=False
        ) as tmp_file:
            tmp_file.write(script_content)
            tmp_script_file = tmp_file.name
        cmd += f" --infile={tmp_script_file}"
        log.info(
            f"Using inline script content (written to temp file: {tmp_script_file})"
        )

    out = utils.exec_shell_cmd(cmd)
    if script_content and "tmp_script_file" in locals():
        try:
            os.unlink(tmp_script_file)
        except OSError:
            pass

    if out is False:
        raise TestExecError(f"Failed to set Lua script with context {context}")

    log.info(f"Successfully set Lua script with context {context}")
    return out


def get_lua_script(context, rgw_realm=None):
    """
    Get a Lua script using radosgw-admin.
    Parameters:
        context (str): Script context - must be "prerequest", "postrequest", "background", "getdata", or "putdata"
        rgw_realm (str, optional): RGW realm name
    Returns:
        str: The Lua script content
    Raises:
        TestExecError: If script retrieval fails
    """
    valid_contexts = ["prerequest", "postrequest", "background", "getdata", "putdata"]
    if context not in valid_contexts:
        raise TestExecError(f"Context must be one of {valid_contexts}, got: {context}")

    log.info(f"Getting Lua script with context: {context}")
    cmd = f"radosgw-admin script get --context={context}"
    if rgw_realm:
        cmd += f" --rgw-realm={rgw_realm}"

    out = utils.exec_shell_cmd(cmd)

    if out is False:
        raise TestExecError(f"Failed to get Lua script with context {context}")

    log.info(f"Successfully retrieved Lua script with context {context}")
    return out


def remove_lua_script(context, rgw_realm=None):
    """
    Remove a Lua script using radosgw-admin.
    Parameters:
        context (str): Script context - must be "prerequest", "postrequest", "background", "getdata", or "putdata"
        rgw_realm (str, optional): RGW realm name
    Returns:
        str: Output from the radosgw-admin command
    Raises:
        TestExecError: If script removal fails
    """
    valid_contexts = ["prerequest", "postrequest", "background", "getdata", "putdata"]
    if context not in valid_contexts:
        raise TestExecError(f"Context must be one of {valid_contexts}, got: {context}")

    log.info(f"Removing Lua script with context: {context}")
    cmd = f"radosgw-admin script rm --context={context}"
    if rgw_realm:
        cmd += f" --rgw-realm={rgw_realm}"

    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"Failed to remove Lua script with context {context}")

    log.info(f"Successfully removed Lua script with context {context}")
    return out


def create_storage_class_single_site(pool_name, storage_class):
    """
    Create storage class in a single site or multisite cluster.
    This function sets up storage class prerequisites for object placement
    in RGW cluster. Works for clusters with or without realm configuration.
    For multisite clusters, automatically updates the period after placement changes.
    Parameters:
        pool_name (str): Name of the OSD pool to create
        storage_class (str): Name of the storage class to create
    Returns:
        None
    Raises:
        TestExecError: If storage class creation fails
    """
    log.info(f"Creating storage class '{storage_class}' for single site cluster")
    log.info(f"Pool name: {pool_name}")
    zonegroup = None
    current_zone = None

    # Nested helper function: defined inside this function scope, only used within create_storage_class_single_site
    def safe_json_parse(cmd, description):
        try:
            result = utils.exec_shell_cmd(cmd)
            if result is False or not isinstance(result, str):
                return None
            return json.loads(result)
        except Exception as e:
            log.warning(f"Could not {description}: {e}")
            return None

    zone_out = safe_json_parse("radosgw-admin zone get", "get zone name from zone get")
    if zone_out:
        current_zone = zone_out.get("name")
        if current_zone:
            log.info(f"Retrieved zone name from zone get: {current_zone}")

    if not zonegroup:
        zonegroup_data = safe_json_parse(
            "radosgw-admin zonegroup get", "get zonegroup from zonegroup get"
        )
        if zonegroup_data:
            zonegroup = zonegroup_data.get("name")
            if zonegroup:
                log.info(f"Retrieved zonegroup from zonegroup get: {zonegroup}")

    if not zonegroup or not current_zone:
        log.info("Falling back to parsing sync status output")
        op = utils.exec_shell_cmd("radosgw-admin sync status")
        if op and isinstance(op, str):
            lines = list(op.split("\n"))
            for line in lines:
                line_lower = line.lower()
                if (
                    "zonegroup" in line_lower
                    and "(" in line
                    and ")" in line
                    and not zonegroup
                ):
                    paren_pairs = []
                    start_idx = -1
                    for i, char in enumerate(line):
                        if char == "(":
                            start_idx = i
                        elif char == ")" and start_idx >= 0:
                            paren_pairs.append((start_idx + 1, i))
                            start_idx = -1
                    if paren_pairs:
                        start_idx, end_idx = paren_pairs[-1]
                        extracted = line[start_idx:end_idx].strip()
                        if (
                            extracted
                            and " " not in extracted
                            and ":" not in extracted
                            and len(extracted) < 50
                        ):
                            if not any(
                                word in extracted.lower()
                                for word in [
                                    "features",
                                    "enabled",
                                    "resharding",
                                    "notification",
                                    "zonegroup",
                                ]
                            ):
                                zonegroup = extracted
                                log.info(
                                    f"Extracted zonegroup from sync status: {zonegroup}"
                                )
                elif (
                    "zone" in line_lower
                    and "zonegroup" not in line_lower
                    and "(" in line
                    and ")" in line
                    and not current_zone
                ):
                    paren_pairs = []
                    start_idx = -1
                    for i, char in enumerate(line):
                        if char == "(":
                            start_idx = i
                        elif char == ")" and start_idx >= 0:
                            paren_pairs.append((start_idx + 1, i))
                            start_idx = -1
                    if paren_pairs:
                        start_idx, end_idx = paren_pairs[-1]
                        extracted = line[start_idx:end_idx].strip()
                        if (
                            extracted
                            and " " not in extracted
                            and ":" not in extracted
                            and len(extracted) < 50
                        ):
                            if not any(
                                word in extracted.lower()
                                for word in [
                                    "is",
                                    "master",
                                    "features",
                                    "enabled",
                                    "zone",
                                ]
                            ):
                                current_zone = extracted
                                log.info(
                                    f"Extracted zone from sync status: {current_zone}"
                                )

    if not zonegroup or not current_zone:
        raise TestExecError(
            "Could not retrieve zonegroup or zone name from sync status or JSON output"
        )

    log.info(f"Retrieved zonegroup name: {zonegroup} and zone name: {current_zone}")
    if not zone_out:
        zone_out = safe_json_parse("radosgw-admin zone get", "get zone info")

    zonegroup_out = None
    zonegroup_out = safe_json_parse(
        f"radosgw-admin zonegroup get --rgw-zonegroup {zonegroup}", "get zonegroup info"
    )
    if not zonegroup_out:
        zonegroup_out = safe_json_parse(
            "radosgw-admin zonegroup get", "get zonegroup info"
        )

    storage_class_exists_in_zg = False
    if zonegroup_out:
        for placement in zonegroup_out.get("placement_targets", []):
            if placement.get("key") == "default-placement":
                storage_classes = placement.get("val", {}).get("storage_classes", [])
                if storage_class in storage_classes:
                    storage_class_exists_in_zg = True
                    log.info(
                        f"Storage class '{storage_class}' already exists in zonegroup '{zonegroup}' placement"
                    )
                    break

    if not storage_class_exists_in_zg:
        log.info(f"Adding storage class to zonegroup '{zonegroup}' placement")
        try:
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add --rgw-zonegroup {zonegroup} "
                f"--placement-id default-placement --storage-class {storage_class}"
            )
            placement_changed = True
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                log.info(
                    f"Storage class '{storage_class}' already exists in zonegroup, skipping addition"
                )
            else:
                raise
    else:
        log.info(
            f"Storage class '{storage_class}' already exists in zonegroup, skipping addition"
        )

    storage_class_exists_in_zone = False
    if zone_out:
        for placement in zone_out.get("placement_pools", []):
            if placement.get("key") == "default-placement":
                storage_classes = placement.get("val", {}).get("storage_classes", {})
                if storage_class in storage_classes:
                    storage_class_exists_in_zone = True
                    log.info(
                        f"Storage class '{storage_class}' already exists in zone '{current_zone}' placement"
                    )
                    break

    if not storage_class_exists_in_zone:
        log.info(f"Adding storage class to zone '{current_zone}' placement")
        try:
            utils.exec_shell_cmd(
                f"radosgw-admin zone placement add --rgw-zone {current_zone} "
                f"--placement-id default-placement --storage-class {storage_class} "
                f"--data-pool {pool_name}"
            )
            placement_changed = True
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                log.info(
                    f"Storage class '{storage_class}' already exists in zone, skipping addition"
                )
            else:
                raise
    else:
        log.info(
            f"Storage class '{storage_class}' already exists in zone, skipping addition"
        )

    if utils.is_cluster_multisite() and placement_changed:
        log.info(f"Updating period for multisite cluster")
        try:
            utils.exec_shell_cmd(f"radosgw-admin period update --commit")
            log.info("Period updated successfully")
        except Exception as e:
            log.warning(
                f"Period update failed: {e}. This may be expected in some configurations."
            )

    log.info(f"Creating OSD pool: {pool_name}")
    try:
        utils.exec_shell_cmd(f"ceph osd pool create {pool_name}")
    except Exception as e:
        if "already exists" in str(e).lower() or "EEXIST" in str(e):
            log.info(f"Pool {pool_name} already exists, skipping creation")
        else:
            # Re-raise any other exceptions (not related to pool already existing)
            raise

    log.info(f"Enabling RGW application on pool: {pool_name}")
    utils.exec_shell_cmd(f"ceph osd pool application enable {pool_name} rgw")
    log.info(f"Successfully created storage class '{storage_class}'")


def extract_debug_pattern_from_lua_script(lua_script_content, storage_class=None):
    """
    Extract debug log pattern from lua script by parsing RGWDebugLog statements.
    Returns regex pattern to match debug log messages.
    Raises TestExecError if RGWDebugLog statement is not found or cannot be parsed.
    """
    if not lua_script_content:
        raise TestExecError(
            "lua_script_content is empty. Cannot extract debug pattern."
        )

    if storage_class:
        pattern = rf"Lua INFO:.*request\.\s+storage\s+class\s+(set\s+to\s+{re.escape(storage_class)}|not\s+set).*for\s+bucket:"
        log.info(f"Created pattern using storage_class '{storage_class}': {pattern}")
        return pattern

    rrgw_debug_pattern = r"RGWDebugLog\s*\((.*?)\)"
    match = re.search(rgw_debug_pattern, lua_script_content, re.DOTALL)
    if not match:
        raise TestExecError(
            "No RGWDebugLog statement found in lua script. Cannot extract debug pattern."
        )

    debug_log_content = match.group(1)
    string_literals = re.findall(r'["\']([^"\']*)["\']', debug_log_content)
    if not string_literals:
        raise TestExecError(
            "No string literals found in RGWDebugLog statement. Cannot extract debug pattern."
        )

    pattern_parts = []
    for literal in string_literals:
        escaped = re.escape(literal)
        pattern_parts.append(escaped)

    pattern = r"Lua INFO:.*" + r".*".join(pattern_parts)
    log.info(f"Extracted debug pattern from lua script: {pattern}")
    log.info(
        f"Pattern will match messages containing these string literals: {string_literals}"
    )
    return pattern


def get_rgw_log_files(log_dir, ssh_con=None, node_name=None):
    """
    Get list of RGW log files from a directory.
    Returns list of log file paths, or empty list if none found.
    """
    if ssh_con:
        stdin, stdout, stderr = ssh_con.exec_command(
            f"sudo find {log_dir} -maxdepth 1 -name 'ceph-client.rgw*.log' -type f 2>/dev/null | sort"
        )
        rgw_log_files_output = stdout.read().decode().strip()
        rgw_log_files = [
            f.strip() for f in rgw_log_files_output.split("\n") if f.strip()
        ]
    else:
        rgw_log_files = []
        if os.path.exists(log_dir):
            for file in os.listdir(log_dir):
                if file.startswith("ceph-client.rgw") and file.endswith(".log"):
                    rgw_log_files.append(os.path.join(log_dir, file))
    return rgw_log_files


def check_log_directory_exists(log_dir, ssh_con=None):
    """
    Check if log directory exists.
    Returns True if exists, False otherwise.
    """
    if ssh_con:
        stdin, stdout, stderr = ssh_con.exec_command(
            f"sudo test -d {log_dir} && echo 'exists' || echo 'not_exists'"
        )
        return stdout.read().decode().strip() == "exists"
    else:
        return os.path.exists(log_dir)


def search_lua_messages_in_log_file(
    log_file, message_pattern, ssh_con=None, node_name=None, since_epoch=None
):
    """
    Search for lua debug messages in a log file.
    Returns list of matching lines, or empty list if none found.
    """
    try:
        # Bucket names contain '.'; only treat intentional regex (e.g. '.*') as regex.
        use_regex_pattern = bool(
            message_pattern
            and re.search(r"(\.\*|\.\+|\[\^?|\(\?|\(\)|\||\^|\$|\\)", message_pattern)
        )
        if message_pattern and not use_regex_pattern:
            grep_cmd = (
                f"sudo grep 'Lua INFO:' {log_file} 2>/dev/null "
                f"| grep -F '{message_pattern}'"
            )
        else:
            grep_cmd = f"sudo grep 'Lua INFO:' {log_file} 2>/dev/null"

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(grep_cmd)
            grep_output = stdout.read().decode().strip()
            err_output = stderr.read().decode().strip()
        else:
            grep_output = utils.exec_shell_cmd(grep_cmd)
            err_output = ""

        if (
            err_output
            and "No such file" not in err_output
            and "Permission denied" not in err_output
        ):
            log.warning(
                f"Error checking log file {log_file}"
                + (f" on {node_name}" if node_name else "")
                + f": {err_output}"
            )

        if grep_output:
            all_lines = grep_output.strip().split("\n")
            if message_pattern:
                if use_regex_pattern:
                    pattern_re = re.compile(message_pattern)
                    matching_lines = [
                        line for line in all_lines if pattern_re.search(line)
                    ]
                else:
                    matching_lines = [
                        line for line in all_lines if message_pattern in line
                    ]
                log.info(
                    f"Found {len(all_lines)} Lua INFO messages, {len(matching_lines)} match pattern"
                    + (f" on {node_name}" if node_name else "")
                )
                if len(matching_lines) == 0 and len(all_lines) > 0:
                    log.warning(
                        f"Pattern '{message_pattern}' did not match any of {len(all_lines)} Lua INFO messages. Sample message: {all_lines[0][:150]}"
                    )
                if since_epoch is not None:
                    from datetime import datetime

                    cutoff = since_epoch - 1
                    recent_lines = []
                    for line in matching_lines:
                        ts_match = re.match(r"^(\S+)\s", line)
                        if not ts_match:
                            continue
                        ts = ts_match.group(1)
                        if ts.endswith("+0000"):
                            ts = ts[:-5] + "+00:00"
                        try:
                            if datetime.fromisoformat(ts).timestamp() >= cutoff:
                                recent_lines.append(line)
                        except ValueError:
                            continue
                    matching_lines = recent_lines
                if since_epoch is not None and matching_lines:
                    log.info(
                        f"{len(matching_lines)} matching message(s) after negative create"
                        + (f" on {node_name}" if node_name else "")
                    )
                return matching_lines
            else:
                if since_epoch is not None:
                    from datetime import datetime

                    cutoff = since_epoch - 1
                    recent_lines = []
                    for line in all_lines:
                        ts_match = re.match(r"^(\S+)\s", line)
                        if not ts_match:
                            continue
                        ts = ts_match.group(1)
                        if ts.endswith("+0000"):
                            ts = ts[:-5] + "+00:00"
                        try:
                            if datetime.fromisoformat(ts).timestamp() >= cutoff:
                                recent_lines.append(line)
                        except ValueError:
                            continue
                    all_lines = recent_lines
                log.info(
                    f"Found {len(all_lines)} Lua INFO messages"
                    + (f" on {node_name}" if node_name else "")
                )
                return all_lines
        return []
    except Exception as e:
        log.warning(
            f"Failed to check log file {log_file}"
            + (f" on {node_name}" if node_name else "")
            + f": {e}"
        )
        return []


def check_logs_on_node(
    log_dir, message_pattern, ssh_con=None, node_name=None, since_epoch=None
):
    """
    Check logs on a single node (local or remote via SSH).
    Returns count of lua messages found, or None if checking was skipped.
    """
    if not check_log_directory_exists(log_dir, ssh_con):
        location = f" on {node_name}" if node_name else " on local node"
        if not node_name and not ssh_con:
            location = " on local node (may be running from client node)"
        log.warning(
            f"Log directory {log_dir} does not exist{location}. Skipping log checking."
        )
        return None

    rgw_log_files = get_rgw_log_files(log_dir, ssh_con, node_name)
    if not rgw_log_files:
        location = (
            f" on {node_name}" if node_name else " on remote node" if ssh_con else ""
        )
        log.warning(
            f"No RGW log files found in {log_dir}{location}. Skipping log checking."
        )
        return None

    location = f" on {node_name}" if node_name else " on remote node" if ssh_con else ""
    log.info(f"Found {len(rgw_log_files)} RGW log files{location}")
    total_messages = 0
    for log_file in rgw_log_files:
        lines = search_lua_messages_in_log_file(
            log_file, message_pattern, ssh_con, node_name, since_epoch
        )
        if lines:
            total_messages += len(lines)
            log.info(
                f"Found {len(lines)} lua debug messages in {os.path.basename(log_file)}"
                + (f" on node {node_name}" if node_name else "")
            )
            message_prefix = f"  [{node_name}] " if node_name else "  "
            for line in lines:
                log.info(message_prefix + line)

    return total_messages


def get_all_rgw_hosts():
    """
    Get all unique RGW hostnames/IPs from ceph orch ps.
    Returns set of hostnames.
    """
    cmd_ps = "ceph orch ps --daemon_type rgw -f json"
    out_ps = utils.exec_shell_cmd(cmd_ps)
    rgw_daemons = json.loads(out_ps)
    rgw_hosts = set()
    for daemon in rgw_daemons:
        hostname = daemon.get("hostname")
        if hostname:
            rgw_hosts.add(hostname)

    return rgw_hosts


def check_rgw_debug_logs_and_reset(
    message_pattern=None,
    ssh_con=None,
    haproxy=None,
    expected_count=None,
    check_all_rgw_nodes=False,
    optional=False,
    since_epoch=None,
    exact_count=False,
):
    """
    Check RGW debug logs for lua script messages and reset debug_rgw to default level.
    message_pattern: regex pattern to search (None = any 'Lua INFO:' messages).
    ssh_con: SSH connection object for remote execution (optional).
    haproxy: If True, check logs on all RGW nodes (since requests can go to any node).
    check_all_rgw_nodes: If True, aggregate logs from every RGW host (optional; use with
        haproxy or multi-node endpoints only).
    optional: If True, log a warning when expected messages are missing but do not raise
        (use when functional checks already prove behavior, e.g. block Lua on RGW 9.1).
    since_epoch: Only count log lines at or after this Unix timestamp (ignores stale entries).
    exact_count: If True, require found count to equal expected_count (not just >=).
    expected_count: Expected number of lua debug messages. If provided, raises TestExecError if count doesn't match.
    Raises TestExecError if log checking or debug_rgw reset fails, or if expected_count is not met.
    """
    log.info("Checking RGW debug logs for lua script messages")
    validation_error = None
    try:
        fsid = utils.get_cluster_fsid()
        log_dir = f"/var/log/ceph/{fsid}"
        found_count = 0
        nodes_searched = False
        search_all = haproxy or check_all_rgw_nodes

        if not search_all:
            local_count = check_logs_on_node(
                log_dir,
                message_pattern,
                ssh_con=ssh_con,
                since_epoch=since_epoch,
            )
            if local_count is not None and local_count > 0:
                found_count = local_count
                nodes_searched = True
                log.info(f"Total lua debug messages found: {found_count}")
            elif local_count is not None and expected_count is None:
                nodes_searched = True
            elif local_count is not None:
                log.info(
                    "No matching lua debug messages on local node. Checking all RGW nodes..."
                )
            else:
                log.info(
                    "Log directory not available on local node. Trying to check logs on RGW nodes..."
                )

        if search_all or not nodes_searched:
            if search_all:
                reason = (
                    "HAProxy is enabled"
                    if haproxy
                    else "check_all_rgw_nodes is enabled"
                )
                log.info(f"{reason} - checking logs on all RGW nodes")
            rgw_hosts = get_all_rgw_hosts()
            if not rgw_hosts:
                if expected_count is not None:
                    raise TestExecError(
                        f"No RGW hosts found, expected {expected_count} messages"
                    )
            else:
                log.info(f"Found {len(rgw_hosts)} RGW host(s): {rgw_hosts}")
                nodes_checked = 0
                found_count = 0
                for host in rgw_hosts:
                    try:
                        log.info(f"Checking logs on RGW node: {host}")
                        node_ssh_con = utils.connect_remote(host)
                        host_messages = check_logs_on_node(
                            log_dir,
                            message_pattern,
                            node_ssh_con,
                            host,
                            since_epoch,
                        )
                        if host_messages is not None:
                            nodes_checked += 1
                            found_count += host_messages
                        node_ssh_con.close()
                    except Exception as e:
                        log.warning(f"Failed to check logs on RGW node {host}: {e}")
                if nodes_checked == 0:
                    if expected_count is not None:
                        raise TestExecError(
                            f"Could not check logs on any RGW nodes, expected {expected_count} messages"
                        )
                else:
                    nodes_searched = True
                    if search_all or expected_count is not None:
                        log.info(
                            f"Total lua debug messages found across all RGW nodes: {found_count}"
                        )

        if expected_count is not None:
            if not nodes_searched:
                raise TestExecError(
                    f"Could not check RGW logs, expected {expected_count} messages"
                )
            if found_count == 0:
                if message_pattern:
                    log.warning(
                        f"No lua debug messages found matching pattern '{message_pattern}' in RGW logs"
                    )
                else:
                    log.warning("No lua debug messages found in RGW logs")
                raise TestExecError(
                    f"No lua debug messages found, expected {expected_count} messages"
                )
            if exact_count and found_count != expected_count:
                raise TestExecError(
                    f"Found {found_count} lua debug messages, but expected exactly {expected_count}"
                )
            if not exact_count and found_count < expected_count:
                raise TestExecError(
                    f"Found {found_count} lua debug messages, but expected at least {expected_count}"
                )
            log.info(
                f"Validation passed: Found {found_count} messages (expected: {expected_count})"
            )

    except TestExecError as e:
        validation_error = e
        if optional:
            log.warning(
                f"Optional lua debug log check: {e}. Continuing (functional checks are authoritative)."
            )
            validation_error = None
        else:
            log.warning(
                f"Validation failed: {e}. Will reset debug_rgw and then fail the test."
            )
    except Exception as e:
        log.warning(
            f"Failed to check RGW debug logs: {e}. Continuing with debug_rgw reset."
        )
        validation_error = None

    log.info("Resetting debug_rgw to default level")
    try:
        cmd_ps = "ceph orch ps --daemon_type rgw -f json"
        out_ps = utils.exec_shell_cmd(cmd_ps)
        rgw_daemons = json.loads(out_ps)
        for daemon in rgw_daemons:
            daemon_name = daemon.get("daemon_name") or daemon.get("service_name")
            if daemon_name:
                debug_cmd = f"ceph config rm client.{daemon_name} debug_rgw"
                log.info(f"Resetting debug_rgw for {daemon_name}: {debug_cmd}")
                utils.exec_shell_cmd(debug_cmd)

        log.info("debug_rgw reset to default for all RGW daemons")
    except Exception as e:
        raise TestExecError(f"Failed to reset debug_rgw: {e}")

    if "validation_error" in locals() and validation_error is not None:
        raise validation_error


def delete_objects(
    aws_auth,
    bucket_name,
    objects_list,
    end_point,
    quiet=False,
    return_err=False,
):
    """
    Delete multiple objects in a single request (DeleteObjects API).
    Supports conditional delete per object via ETag, VersionId, etc.
    See: https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-objects.html

    Each entry in objects_list is a dict with:
      - Key (required): object key
      - VersionId (optional): version to delete
      - ETag (optional): delete only if current ETag matches (conditional delete)
      - LastModifiedTime (optional): directory buckets
      - Size (optional): directory buckets

    Args:
        aws_auth: authentication for awscli
        bucket_name(str): Name of the bucket
        objects_list(list): List of dicts, each with at least "Key"; optionally "ETag", "VersionId"
        end_point(str): endpoint URL
        quiet(bool): If True, response includes only keys that had errors
        return_err(bool): If True, return stderr/output on failure instead of raising

    Returns:
        Command output (JSON string) with "Deleted" and/or "Errors" list
    """
    delete_spec = {"Objects": objects_list, "Quiet": quiet}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="delete_objects_", delete=False
    ) as f:
        json.dump(delete_spec, f)
        tmp_path = f.name
    try:
        command = aws_auth.command(
            operation="delete-objects",
            params=[
                f"--bucket {bucket_name} --delete file://{tmp_path} --endpoint-url {end_point}",
            ],
        )
        response = utils.exec_shell_cmd(command, return_err=return_err)
        log.info(f"delete-objects response: {response}")
        if response is False and not return_err:
            raise Exception(
                f"delete-objects failed for bucket {bucket_name} ({len(objects_list)} objects)"
            )
        return response
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def wrong_etag(etag):
    if not etag:
        return "wrong"
    s = etag
    pos = random.randint(0, len(s))
    return s[:pos] + "x" + s[pos:]


def normalize_last_modified(last_modified_str, ceph_version_id):
    """
    Normalize LastModified from list-object-versions for use as LastModifiedTime
    in delete-objects. Ceph 20+ may return ISO8601 with '+' timezone suffix.
    """
    if not last_modified_str:
        return ""
    if len(ceph_version_id) > 0 and float(ceph_version_id[0]) >= 20:
        return last_modified_str.split("+")[0]
    return last_modified_str.split(".")[0]


def complete_multipart_upload_conditional(
    aws_auth,
    bucket_name,
    key_name,
    upload_file,
    upload_id,
    end_point,
    if_match_etag=None,
    if_none_match=False,
):
    """
    Complete multipart upload with conditional write headers (if-match or if-none-match).
    Per AWS S3 conditional writes, condition is applied at CompleteMultipartUpload.
    Ex: /usr/local/bin/aws s3api complete-multipart-upload --multipart-upload file://<upload_file>
        --bucket <bucket_name> --key <key_name> --upload-id <upload_id> --endpoint <endpoint_url>
        [--if-match <etag> | --if-none-match "*"]
    Args:
        upload_file(str): Name of a file containing mpstructure (Parts with PartNumber, ETag).
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object for which multipart upload has to be completed
        upload_id(str): upload id from create-multipart-upload
        end_point(str): endpoint
        if_match_etag(str|None): If set, add --if-match <etag> (complete only when existing object ETag matches).
        if_none_match(bool): If True, add --if-none-match "*" (complete only when object does not exist).
    Return:
        Response of complete-multipart-upload
    """
    params_str = (
        f"--multipart-upload file://{upload_file} --bucket {bucket_name} --key {key_name} "
        f"--upload-id {upload_id} --endpoint-url {end_point}"
    )
    if if_match_etag:
        params_str += f" --if-match {if_match_etag}"
    elif if_none_match:
        params_str += ' --if-none-match "*"'
    command = aws_auth.command(
        operation="complete-multipart-upload",
        params=[params_str],
    )
    try:
        response = utils.exec_shell_cmd(command)
        if not response:
            raise Exception(
                f"complete multipart upload (conditional) failed for bucket {bucket_name} with key {key_name} and"
                f" upload id {upload_id}"
            )
        return response
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def conditional_put_multipart_upload(
    aws_auth,
    bucket_name,
    key_name,
    TEST_DATA_PATH,
    endpoint,
    config,
    etag=None,
    return_err=False,
    checksum_algo=None,
):
    """
    Perform multipart upload with conditional complete (if-match or if-none-match).
    Covers both conditional put scenarios for multipart upload; condition is applied
    at CompleteMultipartUpload per AWS S3 conditional writes.
    Ex: create-multipart-upload -> upload-part (x N) -> complete-multipart-upload
        with --if-match <etag> or --if-none-match "*"

    Args:
        aws_auth: AWS auth instance
        bucket_name(str): Name of the bucket
        key_name(str): Name of the object
        TEST_DATA_PATH(str): Test data path for part files
        endpoint(str): Endpoint URL
        config: Config object with obj_size, split_size, local_file_delete, etc.
        etag(str|None): If given, use if-match <etag> (complete only when existing
            object ETag matches). If None, use if-none-match "*" (complete only
            when object does not exist).
        return_err(bool): If True, on conditional failure return error string instead
            of raising.
        checksum_algo(str|None): Optional checksum algorithm for create/upload-part.

    Return:
        Response of complete-multipart-upload (dict), or on conditional failure
        when return_err=True, the error string.
    """
    log.info("Create multipart upload (conditional put)")
    create_mp_upload_resp = create_multipart_upload(
        aws_auth, bucket_name, key_name, endpoint, checksum_algo
    )
    if not create_mp_upload_resp or create_mp_upload_resp is False:
        raise TestExecError(
            f"Failed to create multipart upload for bucket {bucket_name} with key {key_name}. "
            f"Response was: {create_mp_upload_resp}"
        )
    if not isinstance(create_mp_upload_resp, str):
        raise TestExecError(
            f"Invalid response type for multipart upload. Expected string, "
            f"got {type(create_mp_upload_resp)}: {create_mp_upload_resp}"
        )
    try:
        upload_id = json.loads(create_mp_upload_resp)["UploadId"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise TestExecError(
            f"Failed to parse multipart upload response for bucket {bucket_name} with key {key_name}. "
            f"Response: {create_mp_upload_resp}, Error: {e}"
        )

    object_path = os.path.join(TEST_DATA_PATH, key_name)
    object_size = config.obj_size
    split_size = config.split_size if hasattr(config, "split_size") else 5
    data_info = io_generator(object_path, object_size)
    if data_info is False:
        raise TestExecError("data creation failed")

    mp_dir = os.path.join(TEST_DATA_PATH, key_name + ".mp.parts")
    mkdir = utils.exec_shell_cmd(f"sudo mkdir {mp_dir}")
    if mkdir is False:
        raise TestExecError("mkdir failed creating mp_dir_name")
    utils.split_file(object_path, split_size, mp_dir + "/")
    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))

    part_number = 1
    mpstructure = {"Parts": []}
    for each_part in parts_list:
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
            part_number += 1
    with open("mpstructure.json", "w") as fd:
        json.dump(mpstructure, fd)
    if getattr(config, "local_file_delete", False):
        utils.exec_shell_cmd(f"rm -rf {mp_dir}")

    if_match_etag = etag if etag else None
    if_none_match = not etag

    try:
        if return_err:
            complete_resp = utils.exec_shell_cmd(
                aws_auth.command(
                    operation="complete-multipart-upload",
                    params=[
                        f"--multipart-upload file://mpstructure.json --bucket {bucket_name} "
                        f"--key {key_name} --upload-id {upload_id} --endpoint-url {endpoint}"
                        + (
                            f" --if-match {if_match_etag}"
                            if if_match_etag
                            else ' --if-none-match "*"'
                        )
                    ],
                ),
                return_err=True,
            )
            if complete_resp:
                try:
                    return json.loads(complete_resp)
                except (json.JSONDecodeError, TypeError):
                    pass
            return complete_resp
        response = complete_multipart_upload_conditional(
            aws_auth,
            bucket_name,
            key_name,
            "mpstructure.json",
            upload_id,
            endpoint,
            if_match_etag=if_match_etag,
            if_none_match=if_none_match,
        )
        return json.loads(response)
    except Exception as e:
        if return_err:
            return str(e)
        raise AWSCommandExecError(message=str(e))


def get_bucket_location(aws_auth, bucket_name, end_point):
    """
    Get bucket location
    ex: /usr/local/bin/aws s3api get-bucket-location --bucket verbkt1 --endpoint-url http://x.x.x.x:xx
    Args:
        aws_auth: AWS auth object
        bucket_name(str): Name of the bucket
        end_point(str): endpoint
    Returns:
        Location constraint of the bucket
    """
    command = aws_auth.command(
        operation="get-bucket-location",
        params=[f"--bucket {bucket_name} --endpoint-url {end_point}"],
    )
    try:
        location_response = utils.exec_shell_cmd(command)
        log.info(f"bucket location response is {location_response}")
        if not location_response:
            raise Exception(f"Get bucket location failed for {bucket_name}")
        location_data = json.loads(location_response)
        return location_data.get("LocationConstraint", "")
    except Exception as e:
        raise AWSCommandExecError(message=str(e))
