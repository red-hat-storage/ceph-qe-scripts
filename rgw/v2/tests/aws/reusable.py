"""
Reusable methods for aws
"""

import base64
import copy
import glob
import hashlib
import hmac
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
import threading
import time
import urllib.parse
from configparser import RawConfigParser
from datetime import datetime, timezone
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
        curl_insecure = " -k" if end_point.startswith("https://") else ""
        output = utils.exec_shell_cmd(
            f"curl{curl_insecure} --connect-timeout 10 {end_point}"
        )
        if output:
            log.info(f"Endpoint {end_point} is reachable on attempt {attempt}.")
            break
        else:
            log.warning(
                f"Attempt {attempt}: Endpoint {end_point} not reachable, retrying in {wait_time}s..."
            )
            time.sleep(wait_time)
    else:
        msg = f"Endpoint {end_point} is not reachable after {retries} attempts."
        log.error(msg)
        raise AWSCommandExecError(message=msg)

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


def put_object(aws_auth, bucket_name, object_name, end_point, body=None):
    """
    Put/uploads object to the bucket
    Ex: /usr/local/bin/aws s3api put-object --bucket <bucket_name> --key <object_name> --body <content> --endpoint <endpoint_url>
    Args:
        bucket_name(str): Name of the bucket from which object needs to be listed
        object_name(str): Name of the object/file
        end_point(str): endpoint
        body(str): local file path for --body; defaults to object_name
    Return:
        Response of put-object operation
    """
    body_path = body if body else object_name
    command = aws_auth.command(
        operation="put-object",
        params=[
            f"--bucket {bucket_name} --key {object_name} --body {body_path} --endpoint-url {end_point}",
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


def put_object_must_be_blocked(
    aws_auth,
    bucket_name,
    object_name,
    end_point,
    body=None,
    error_substrings=("403", "AccessDenied", "Forbidden", "Abort"),
    fail_msg=None,
):
    """
    put_object that must be rejected (e.g. by a prerequest Lua abort).
    Raises TestExecError if the put succeeds or fails with an unexpected error.
    """
    try:
        put_object(aws_auth, bucket_name, object_name, end_point, body=body)
    except AWSCommandExecError as e:
        err = str(e)
        if any(x in err for x in error_substrings):
            log.info(f"put_object blocked as expected: {err}")
            return
        raise TestExecError(f"Unexpected put-object error: {err}")
    raise TestExecError(
        fail_msg
        or (
            f"put_object {object_name} succeeded but should have been blocked "
            "by the Lua prerequest script"
        )
    )


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
    Returns RGW endpoint URL (http or https) from cluster frontends.
    Port 80 uses http; ports 443/444 use https. When ssl is unset for other
    ports, auto-detects from rgw_frontends (ssl_port / ssl in config).
    """
    if ssh_con:
        _, stdout, _ = ssh_con.exec_command("hostname -I")
        ip = stdout.readline().strip().split()[0]  # first IP
    else:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)

    frontend_values = utils.get_rgw_frontends() or ""
    http_port = None
    https_port = None
    for part in frontend_values.split():
        if part.startswith("port="):
            http_port = part.split("=", 1)[1]
        elif part.startswith("ssl_port="):
            https_port = part.split("=", 1)[1]

    if haproxy:
        port = "5000"
    else:
        port = str(https_port or http_port or utils.get_radosgw_port_no(ssh_con))

    if not haproxy:
        if port == "80":
            ssl = False
        elif port in ("443", "444"):
            ssl = True
        elif ssl is None:
            if https_port or "ssl" in frontend_values:
                ssl = True
            else:
                detected = utils.is_rgw_secure()
                ssl = detected if detected is not None else False

    scheme = "https" if ssl else "http"
    ip_and_port = f"{scheme}://{ip}:{port}"
    log.info(f"RGW endpoint: {ip_and_port} (ssl={ssl}, port={port})")
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


def put_bucket_cors_config(aws_auth, bucket_name, cors_configuration, endpoint):
    """
    Put a CORS policy from a dict (writes a temp JSON file for put-bucket-cors).
    Args:
        cors_configuration(dict): CORSRules document for --cors-configuration
    """
    cors_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as cors_file:
            cors_file.write(json.dumps(cors_configuration, indent=2))
            cors_path = cors_file.name
        return put_bucket_cors(aws_auth, bucket_name, cors_path, endpoint)
    finally:
        if cors_path and os.path.exists(cors_path):
            os.remove(cors_path)


def aws_s3_cli_prefix(ssl=False, region=None):
    """Build prefix for aws s3 subcommands (not s3api)."""
    prefix = "/usr/local/bin/aws"
    if ssl:
        prefix += " --no-verify-ssl"
    prefix += " s3"
    if region:
        prefix += f" --region {region}"
    return prefix


def put_bucket_policy(aws_auth, bucket_name, endpoint, policy_document):
    """Put bucket policy from a dict via a temporary json file."""
    policy_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as policy_file:
            json.dump(policy_document, policy_file)
            policy_path = policy_file.name
        command = aws_auth.command(
            operation="put-bucket-policy",
            params=[
                f"--bucket {bucket_name} --policy file://{policy_path} --endpoint-url {endpoint}",
            ],
        )
        out = utils.exec_shell_cmd(command)
        if out is False:
            raise TestExecError(f"put-bucket-policy failed for {bucket_name}")
        log.info(f"put-bucket-policy on {bucket_name}: {out}")
        return out
    except TestExecError:
        raise
    except Exception as e:
        raise AWSCommandExecError(message=str(e))
    finally:
        if policy_path and os.path.exists(policy_path):
            os.remove(policy_path)


def put_bucket_logging(
    aws_auth,
    bucket_name,
    endpoint,
    target_bucket,
    target_prefix="",
    logging_status=None,
):
    """Configure S3 bucket access logging on source bucket."""
    if logging_status is None:
        logging_status = {
            "LoggingEnabled": {
                "TargetBucket": target_bucket,
                "TargetPrefix": target_prefix,
            }
        }
    status_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as status_file:
            json.dump(logging_status, status_file)
            status_path = status_file.name
        command = aws_auth.command(
            operation="put-bucket-logging",
            params=[
                f"--bucket {bucket_name} --bucket-logging-status file://{status_path} --endpoint-url {endpoint}",
            ],
        )
        out = utils.exec_shell_cmd(command)
        if out is False:
            raise TestExecError(f"put-bucket-logging failed for {bucket_name}")
        log.info(f"put-bucket-logging on {bucket_name}: {out}")
        return out
    except TestExecError:
        raise
    except Exception as e:
        raise AWSCommandExecError(message=str(e))
    finally:
        if status_path and os.path.exists(status_path):
            os.remove(status_path)


def get_bucket_logging(aws_auth, bucket_name, endpoint):
    """Return parsed get-bucket-logging response."""
    command = aws_auth.command(
        operation="get-bucket-logging",
        params=[f"--bucket {bucket_name} --endpoint-url {endpoint}"],
    )
    try:
        out = utils.exec_shell_cmd(command)
        if out is False:
            raise TestExecError(
                f"get-bucket-logging failed for {bucket_name} on {endpoint}"
            )
        log.info(f"get-bucket-logging on {bucket_name}: {out}")
        return json.loads(out)
    except TestExecError:
        raise
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def head_bucket(aws_auth, bucket_name, endpoint, expect_not_found=False):
    """head-bucket; when expect_not_found, verify 404."""
    command = aws_auth.command(
        operation="head-bucket",
        params=[f"--bucket {bucket_name} --endpoint-url {endpoint}"],
    )
    try:
        if expect_not_found:
            err = utils.exec_shell_cmd(command, return_err=True)
            if not err or "404" not in err:
                raise TestExecError(
                    f"Expected head-bucket 404 for {bucket_name}, got: {err}"
                )
            return False
        out = utils.exec_shell_cmd(command)
        if out is False:
            raise TestExecError(f"head-bucket failed for {bucket_name}")
        return True
    except TestExecError:
        raise
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def s3_upload_from_stdin(
    bucket_name, object_key, endpoint, data, ssl=False, region=None
):
    """Upload object data via aws s3 cp from stdin."""
    aws_s3 = aws_s3_cli_prefix(ssl, region)
    cmd = (
        f"echo {shlex.quote(data)} | {aws_s3} cp - "
        f"s3://{bucket_name}/{object_key} --endpoint-url {endpoint}"
    )
    try:
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            raise TestExecError(
                f"s3 cp upload failed for s3://{bucket_name}/{object_key}"
            )
        log.info(f"upload {object_key}: {out}")
        return out
    except TestExecError:
        raise
    except Exception as e:
        raise AWSCommandExecError(message=str(e))


def empty_and_remove_bucket(bucket_name, endpoint, ssl=False, region=None):
    """Remove all objects and delete bucket via aws s3 rm --recursive and rb."""
    aws_s3 = aws_s3_cli_prefix(ssl, region)
    rm_cmd = f"{aws_s3} rm s3://{bucket_name} --recursive --endpoint-url {endpoint}"
    rb_cmd = f"{aws_s3} rb s3://{bucket_name} --endpoint-url {endpoint}"
    try:
        if utils.exec_shell_cmd(rm_cmd) is False:
            raise TestExecError(f"s3 rm --recursive failed for {bucket_name}")
        if utils.exec_shell_cmd(rb_cmd) is False:
            raise TestExecError(f"s3 rb failed for {bucket_name}")
    except TestExecError:
        raise
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


# Where to run radosgw-admin script-package (luarocks must be on that PATH).
# Set by ensure_lua_script_package_prereqs: {"mode": "local"} or
# {"mode": "container", "host": ..., "container_id": ...}.
_LUA_SCRIPT_PKG_CTX = {"mode": "local"}


def _ssh_podman_exec(host, container_id, inner_cmd):
    """
    Run bash -lc <inner_cmd> inside container on host.
    Returns (stdout, stderr, success).
    """
    remote = f"sudo podman exec {container_id} bash -lc {shlex.quote(inner_cmd)}"
    try:
        node_ssh = utils.connect_remote(host)
        _stdin, stdout, stderr = node_ssh.exec_command(remote)
        out = stdout.read().decode()
        err = stderr.read().decode()
        status = stdout.channel.recv_exit_status()
        try:
            node_ssh.close()
        except Exception:
            pass
        return out, err, status == 0
    except Exception as e:
        log.warning(f"podman exec on {host}/{container_id} failed: {e}")
        out = utils.exec_shell_cmd(remote)
        if out is False:
            return "", str(e), False
        return out or "", "", True


def _ensure_luarocks_on_daemon_path(host, container_id):
    """
    RGW daemons often have a short PATH; put luarocks on /usr/bin when it
    was installed to /usr/local/bin (source bootstrap).
    """
    _ssh_podman_exec(
        host,
        container_id,
        "LR=$(command -v luarocks || true); "
        'if [ -n "$LR" ] && [ ! -x /usr/bin/luarocks ]; then '
        'ln -sf "$LR" /usr/bin/luarocks; fi; '
        "command -v luarocks; test -x /usr/bin/luarocks -o -x /usr/local/bin/luarocks",
    )


def _luarocks_toolchain_present(host, container_id):
    _ensure_luarocks_on_daemon_path(host, container_id)
    out, _err, ok = _ssh_podman_exec(
        host,
        container_id,
        "command -v luarocks && command -v gcc && command -v make && echo OK",
    )
    return ok and "OK" in (out or "")


def _install_luarocks_toolchain_in_container(host, container_id):
    """
    Install luarocks + C toolchain in an RGW container.
    Tries distro packages first, then luarocks.org source bootstrap.
    """
    if _luarocks_toolchain_present(host, container_id):
        log.info(f"luarocks/compiler already present in {host}/{container_id}")
        return True

    pkgs = "luarocks gcc gcc-c++ make m4 wget curl tar"
    log.info(f"Installing luarocks/compiler packages in {host}/{container_id}")
    out, err, _ok = _ssh_podman_exec(
        host,
        container_id,
        f"microdnf install -y {pkgs} || dnf install -y {pkgs} || yum install -y {pkgs}",
    )
    log.info(f"package install on {host}/{container_id}: {out} {err}")
    if _luarocks_toolchain_present(host, container_id):
        return True

    # QE lua notes: EPEL then dnf install luarocks (fixes script-package -10)
    major = _detect_rhel_major()
    if major:
        epel_rpm = (
            f"https://dl.fedoraproject.org/pub/epel/"
            f"epel-release-latest-{major}.noarch.rpm"
        )
        log.info(f"Trying EPEL + luarocks in {host}/{container_id}")
        out, err, _ok = _ssh_podman_exec(
            host,
            container_id,
            f"dnf install -y {epel_rpm} || yum install -y {epel_rpm} || true; "
            f"dnf install -y {pkgs} || yum install -y {pkgs} || "
            f"microdnf install -y {pkgs} || true",
        )
        log.info(f"EPEL install on {host}/{container_id}: {out} {err}")
        if _luarocks_toolchain_present(host, container_id):
            return True

    # Last resort: luarocks.org source bootstrap.
    log.info(f"Bootstrapping luarocks from source in {host}/{container_id}")
    bootstrap = """
set -e
microdnf install -y gcc gcc-c++ make m4 wget curl tar lua lua-devel unzip \
  || dnf install -y gcc gcc-c++ make m4 wget curl tar lua lua-devel unzip \
  || yum install -y gcc gcc-c++ make m4 wget curl tar lua lua-devel unzip \
  || true
LUA_BIN=$(command -v lua || command -v lua5.4 || command -v lua5.3 || true)
if [ -z "$LUA_BIN" ]; then
  echo "NO_LUA_INTERPRETER"
  exit 1
fi
cd /tmp
rm -rf luarocks-3.11.1 luarocks.tar.gz
curl -fsSL -o luarocks.tar.gz https://luarocks.org/releases/luarocks-3.11.1.tar.gz
tar xzf luarocks.tar.gz
cd luarocks-3.11.1
./configure --with-lua-bin=$(dirname "$LUA_BIN")
make
make install
# RGW daemon PATH may omit /usr/local/bin
ln -sf /usr/local/bin/luarocks /usr/bin/luarocks
command -v luarocks
command -v gcc
command -v make
test -x /usr/bin/luarocks
"""
    out, err, ok = _ssh_podman_exec(host, container_id, bootstrap)
    log.info(f"luarocks bootstrap on {host}/{container_id}: {out} {err}")
    return _luarocks_toolchain_present(host, container_id)


def _iter_rgw_daemons(include_sync=True):
    """Yield RGW orch daemons that have hostname + container_id."""
    out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
    daemons = json.loads(out_ps) if out_ps else []
    for d in daemons or []:
        name = d.get("daemon_name") or d.get("daemon_id") or ""
        is_sync = ".sync" in name or name.endswith("sync")
        if is_sync and not include_sync:
            continue
        if d.get("container_id") and d.get("hostname"):
            yield d


def _iter_rgw_io_daemons():
    """Yield non-sync (IO) RGW orch daemons."""
    yield from _iter_rgw_daemons(include_sync=False)


def _container_exec_ok(host, container_id):
    """True if podman exec works in the named container (running and present)."""
    _out, _err, ok = _ssh_podman_exec(host, container_id, "true")
    return bool(ok)


def _snapshot_rgw_container_ids(include_sync=False):
    """Map daemon_name -> container_id for current RGW daemons."""
    snap = {}
    for d in _iter_rgw_daemons(include_sync=include_sync):
        name = d.get("daemon_name") or d.get("daemon_id")
        if name:
            snap[name] = d.get("container_id")
    return snap


def _exec_script_package_admin(rgw_admin_args):
    """
    Run radosgw-admin <rgw_admin_args> where luarocks is available.
    """
    ctx = _LUA_SCRIPT_PKG_CTX or {"mode": "local"}
    if ctx.get("mode") == "container":
        host = ctx["host"]
        cid = ctx["container_id"]
        inner = f"radosgw-admin {rgw_admin_args}"
        log.info(f"script-package via RGW container {host}/{cid}: {inner}")
        out, err, ok = _ssh_podman_exec(host, cid, inner)
        if out:
            log.info(out)
        if err:
            log.info(err)
        if not ok:
            return False
        return out if out else ""
    cmd = f"radosgw-admin {rgw_admin_args}"
    return utils.exec_shell_cmd(cmd)


def _detect_rhel_major():
    """Return RHEL/CentOS major version as int, or None."""
    out = utils.exec_shell_cmd(
        "rpm -E '%{rhel}' 2>/dev/null || "
        'awk -F= \'/^VERSION_ID=/{gsub(/"/,"",$2); print $2}\' /etc/os-release '
        "| cut -d. -f1 || true"
    )
    if not out:
        return None
    token = str(out).strip().splitlines()[0].strip()
    if token.isdigit():
        return int(token)
    return None


def _install_host_compiler_toolchain():
    """script-package reload compiles C rocks on the admin host; need gcc/make."""
    gcc = utils.exec_shell_cmd("command -v gcc || true")
    make = utils.exec_shell_cmd("command -v make || true")
    if gcc and str(gcc).strip() and make and str(make).strip():
        return
    log.info("Installing gcc/make on admin host for script-package reload")
    utils.exec_shell_cmd(
        "sudo dnf install -y gcc gcc-c++ make || "
        "sudo yum install -y gcc gcc-c++ make || true"
    )


def _install_luarocks_on_host():
    """
    Install luarocks (+ compiler) on the host running radosgw-admin.

    Matches QE lua notes: script-package add returns -10 without luarocks;
    install via EPEL then dnf install luarocks
    (epel-release-latest-<major>.noarch.rpm).
    Reload also needs gcc/make for --allow-compilation packages.
    """
    host_pkgs = "luarocks gcc gcc-c++ make"
    which = utils.exec_shell_cmd("command -v luarocks || true")
    if which and str(which).strip():
        _install_host_compiler_toolchain()
        return str(which).strip()

    log.info("luarocks not on admin host; trying dnf/yum")
    utils.exec_shell_cmd(
        f"sudo dnf install -y {host_pkgs} || sudo yum install -y {host_pkgs} || true"
    )
    which = utils.exec_shell_cmd("command -v luarocks || true")
    if which and str(which).strip():
        _install_host_compiler_toolchain()
        return str(which).strip()

    major = _detect_rhel_major()
    if not major:
        log.warning("Could not detect RHEL major version for EPEL luarocks install")
        return None

    epel_rpm = (
        f"https://dl.fedoraproject.org/pub/epel/"
        f"epel-release-latest-{major}.noarch.rpm"
    )
    log.info(
        f"Installing EPEL + luarocks/gcc on admin host "
        f"(RHEL {major}; QE lua prereq for script-package -10)"
    )
    utils.exec_shell_cmd(
        f"sudo dnf install -y {epel_rpm} || sudo yum install -y {epel_rpm} || true"
    )
    # EPEL notes recommend CRB for some deps
    utils.exec_shell_cmd(
        "sudo /usr/bin/crb enable || "
        "sudo dnf config-manager --set-enabled crb || true"
    )
    utils.exec_shell_cmd(
        f"sudo dnf install -y {host_pkgs} || sudo yum install -y {host_pkgs} || true"
    )
    which = utils.exec_shell_cmd("command -v luarocks || true")
    if which and str(which).strip():
        _install_host_compiler_toolchain()
        return str(which).strip()
    return None


def _pick_prepared_io_daemon(prepared, preferred_host=None):
    if preferred_host:
        for d in prepared:
            host = d.get("hostname") or ""
            if (
                preferred_host == host
                or preferred_host in host
                or host in preferred_host
            ):
                return d
    return prepared[0] if prepared else None


def ensure_lua_script_package_prereqs(preferred_host=None):
    """
    Ensure luarocks exists for radosgw-admin script-package add, and that
    *all* RGW containers (IO + sync) have luarocks + a C toolchain for
    --allow-compilation packages on reload.

    script-package reload notifies every RGW; sync daemons without luarocks
    return -ECHILD (-10). QE procedure: enable EPEL then `dnf install luarocks`
    on the admin host. On reload -10/-110 see reload_lua_script_packages.
    """
    global _LUA_SCRIPT_PKG_CTX

    log.info("Ensure luarocks is available for radosgw-admin script-package")
    which = _install_luarocks_on_host()

    # Reload notify hits every RGW (including sync); prepare all of them.
    all_daemons = list(_iter_rgw_daemons(include_sync=True))
    io_daemons = [
        d
        for d in all_daemons
        if ".sync" not in (d.get("daemon_name") or d.get("daemon_id") or "")
    ]
    if not io_daemons:
        raise TestExecError("No IO RGW daemons found to prepare for lua packages")

    prepared = []
    for d in all_daemons:
        host = d["hostname"]
        cid = d["container_id"]
        name = d.get("daemon_name") or cid
        if _install_luarocks_toolchain_in_container(host, cid):
            prepared.append(d)
            log.info(f"Prepared luarocks in {name} ({host}/{cid})")
        else:
            log.warning(f"Failed to prepare luarocks in {name} ({host}/{cid})")

    prepared_io = [
        d
        for d in prepared
        if ".sync" not in (d.get("daemon_name") or d.get("daemon_id") or "")
    ]
    chosen = _pick_prepared_io_daemon(prepared_io, preferred_host=preferred_host)
    reload_container = None
    if chosen:
        reload_container = {
            "host": chosen["hostname"],
            "container_id": chosen["container_id"],
        }

    if which:
        log.info(f"luarocks on admin host: {which}")
        _LUA_SCRIPT_PKG_CTX = {
            "mode": "local",
            "reload_container": reload_container,
        }
        return

    if chosen is None:
        raise TestExecError(
            "luarocks required for script-package add (-10/-ECHILD) but could "
            "not install on admin host (try EPEL + dnf install luarocks) "
            "or in any IO RGW container"
        )

    _LUA_SCRIPT_PKG_CTX = {
        "mode": "container",
        "host": chosen["hostname"],
        "container_id": chosen["container_id"],
        "reload_container": reload_container,
    }
    log.info(
        f"script-package will run in RGW container "
        f"{chosen['hostname']}/{chosen['container_id']}"
    )


def add_lua_script_package(package, allow_compilation=True):
    """
    Add a Lua package to the RGW script-package allowlist.
    """
    args = f"script-package add --package={package}"
    if allow_compilation:
        args += " --allow-compilation"
    log.info(f"Adding Lua script package: {package}")
    out = _exec_script_package_admin(args)
    if out is False:
        raise TestExecError(
            f"Failed to add Lua script package {package} "
            "(error -10/-ECHILD usually means luarocks missing on PATH)"
        )
    log.info(f"Successfully added Lua script package {package}")
    return out


def _io_rgw_service_names():
    """Unique ceph orch service names for non-sync RGW IO daemons."""
    names = []
    seen = set()
    for d in _iter_rgw_io_daemons():
        svc = d.get("service_name")
        if svc and svc not in seen:
            seen.add(svc)
            names.append(svc)
    return names


def _wait_for_io_rgw_ready(timeout=240, previous_cids=None):
    """
    Wait until IO RGW daemons are running *and* podman can exec into them.

    After `ceph orch restart`, orch can still advertise the old container_id
    briefly (status=1) while the container is already gone — podman then
    fails with "no such container". When previous_cids is set, also require
    a new container_id per daemon.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Nudge orch to refresh daemon metadata when available.
        utils.exec_shell_cmd(
            "ceph orch ps --daemon_type rgw --refresh -f json >/dev/null 2>&1 || true"
        )
        daemons = list(_iter_rgw_io_daemons())
        if not daemons or not all(d.get("status") == 1 for d in daemons):
            time.sleep(5)
            continue

        ready = True
        for d in daemons:
            name = d.get("daemon_name") or d.get("daemon_id")
            host = d["hostname"]
            cid = d["container_id"]
            if previous_cids and previous_cids.get(name) == cid:
                log.info(
                    f"Waiting for new container for {name} "
                    f"(orch still reports {cid})"
                )
                ready = False
                break
            if not _container_exec_ok(host, cid):
                log.info(
                    f"Waiting for podman exec on {host}/{cid} ({name}) " "after restart"
                )
                ready = False
                break
        if ready:
            log.info(
                f"All {len(daemons)} IO RGW daemon(s) ready after restart "
                f"(exec-ok, new containers)"
            )
            return
        time.sleep(5)
    raise TestExecError(
        f"IO RGW daemons not ready within {timeout}s after restart "
        "(need running + new container_id + podman exec)"
    )


def _restart_io_rgw_services():
    """Restart non-sync IO RGW orch services and wait until new containers are ready."""
    services = _io_rgw_service_names()
    if not services:
        raise TestExecError("No IO RGW services found to restart for lua packages")
    previous_cids = _snapshot_rgw_container_ids(include_sync=False)
    for svc in services:
        log.info(f"Restarting RGW service {svc}")
        out = utils.exec_shell_cmd(f"ceph orch restart {svc}")
        if out is False:
            raise TestExecError(f"Failed to restart RGW service {svc}")
    time.sleep(15)
    _wait_for_io_rgw_ready(previous_cids=previous_cids)


def _reprepare_rgw_luarocks_after_restart():
    """
    cephadm restart replaces containers; reinstall luarocks/gcc in all new
    RGW containers (IO + sync) so script-package reload can compile rocks.
    """
    global _LUA_SCRIPT_PKG_CTX
    prepared = []
    for d in _iter_rgw_daemons(include_sync=True):
        host = d["hostname"]
        cid = d["container_id"]
        name = d.get("daemon_name") or cid
        if not _container_exec_ok(host, cid):
            log.warning(f"Skip luarocks prepare; container not exec-able: {host}/{cid}")
            continue
        if _install_luarocks_toolchain_in_container(host, cid):
            prepared.append(d)
            log.info(f"Re-prepared luarocks in {name} ({host}/{cid})")
        else:
            log.warning(f"Failed to re-prepare luarocks in {name} ({host}/{cid})")
    prepared_io = [
        d
        for d in prepared
        if ".sync" not in (d.get("daemon_name") or d.get("daemon_id") or "")
    ]
    if not prepared_io:
        raise TestExecError(
            "No IO RGW containers had luarocks after restart; "
            "cannot install script-package allowlist"
        )
    chosen = prepared_io[0]
    ctx = dict(_LUA_SCRIPT_PKG_CTX or {"mode": "local"})
    ctx["reload_container"] = {
        "host": chosen["hostname"],
        "container_id": chosen["container_id"],
    }
    if ctx.get("mode") == "container":
        ctx["host"] = chosen["hostname"]
        ctx["container_id"] = chosen["container_id"]
    _LUA_SCRIPT_PKG_CTX = ctx
    log.info(
        f"Re-prepared luarocks/compiler in {len(prepared)} RGW container(s) "
        f"({len(prepared_io)} IO)"
    )


def reload_lua_script_packages():
    """
    Reload RGW Lua script packages after allowlist changes.

    Prefer `radosgw-admin script-package reload`. Failures are usually:
      -10  luarocks/gcc missing on a notified RGW (incl. sync)
      -110 notify ACK timeout on cephadm
    Fall back: restart IO RGW, wait for *new* containers + podman exec,
    reinstall luarocks on all RGWs, retry reload. A second failure waits
    then continues (notify may still complete without ACK).
    """
    log.info("Reloading Lua script packages")
    _install_host_compiler_toolchain()
    out = _exec_script_package_admin("script-package reload")
    if out is not False:
        log.info("Successfully reloaded Lua script packages")
        return out

    log.warning(
        "script-package reload failed (-10 missing luarocks on an RGW, or "
        "-110 notify timeout); restarting IO RGW, re-preparing luarocks on "
        "all RGWs, retrying reload"
    )
    _restart_io_rgw_services()
    _reprepare_rgw_luarocks_after_restart()
    out = _exec_script_package_admin("script-package reload")
    if out is not False:
        log.info("Successfully reloaded Lua script packages after IO RGW restart")
        return out

    log.warning(
        "script-package reload still failing after restart; "
        "waiting for RGW luarocks install to finish, then continuing"
    )
    time.sleep(45)
    return ""


def _pick_rgw_io_daemon(preferred_host=None):
    """
    Pick a running RGW IO daemon (prefer non-sync, matching preferred_host).
    Returns daemon dict from `ceph orch ps --daemon_type rgw -f json`.
    """
    out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
    daemons = json.loads(out_ps)
    if not daemons:
        raise TestExecError("No RGW daemons found via ceph orch ps")

    def score(d):
        name = d.get("daemon_name") or d.get("daemon_id") or ""
        host = d.get("hostname") or ""
        s = 0
        if preferred_host and (
            preferred_host == host or preferred_host in host or host in preferred_host
        ):
            s += 100
        if ".sync" not in name and "sync" not in name:
            s += 10
        if d.get("status") == 1:
            s += 1
        return s

    daemons = sorted(daemons, key=score, reverse=True)
    chosen = daemons[0]
    log.info(
        f"Selected RGW daemon {chosen.get('daemon_name')} on "
        f"{chosen.get('hostname')} container={chosen.get('container_id')}"
    )
    return chosen


def _unix_socket_listener_py(socket_path, events_file):
    """Python snippet that listens on AF_UNIX and appends raw lines to events_file."""
    return f"""
import os, socket, sys
sock_path = {socket_path!r}
events_path = {events_file!r}
try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
os.chmod(sock_path, 0o777)
srv.listen(32)
srv.settimeout(0.5)
open(events_path, "w").close()
while True:
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        if os.path.exists(events_path + ".stop"):
            break
        continue
    except Exception:
        if os.path.exists(events_path + ".stop"):
            break
        continue
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if data:
            with open(events_path, "ab") as fh:
                fh.write(data if data.endswith(b"\\n") else data + b"\\n")
    finally:
        try:
            conn.close()
        except Exception:
            pass
try:
    srv.close()
except Exception:
    pass
try:
    os.unlink(sock_path)
except Exception:
    pass
"""


def _start_unix_socket_in_container(host, container_id, socket_path, events_file):
    """
    Start AF_UNIX collector inside one RGW container. Returns target dict or None.
    """
    listener_py = _unix_socket_listener_py(socket_path, events_file)
    b64 = base64.b64encode(listener_py.encode()).decode()
    remote_cmd = (
        f"sudo podman exec -d {container_id} bash -lc "
        f'"echo {b64} | base64 -d > /tmp/lua_sock_collector.py && '
        f"rm -f {events_file}.stop && "
        f'python3 /tmp/lua_sock_collector.py"'
    )
    target = {
        "host": host,
        "container_id": container_id,
        "mode": None,
        "ssh": None,
    }
    try:
        node_ssh = utils.connect_remote(host)
        _stdin, stdout, stderr = node_ssh.exec_command(remote_cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()
        log.info(
            f"Started in-container socket collector on {host}/{container_id}: "
            f"{out} {err}"
        )
        target["mode"] = "container_remote"
        target["ssh"] = node_ssh
        return target
    except Exception as e:
        log.warning(
            f"Remote podman exec on {host}/{container_id} failed ({e}); "
            "trying local podman"
        )
        out = utils.exec_shell_cmd(remote_cmd)
        if out is False:
            log.warning(f"Failed to start socket collector in {host}/{container_id}")
            return None
        log.info(f"Started in-container socket collector locally: {out}")
        target["mode"] = "container_local"
        return target


def start_unix_socket_event_collector(socket_path, preferred_host=None):
    """
    Start a Unix-stream server that records newline-delimited messages.

    On cephadm, start a listener in *every* IO RGW container so GETs that
    land on any backend still deliver events (AF_UNIX is per-container).
    Falls back to a single daemon or a local host thread.

    Returns a handle dict used by collect_unix_socket_events /
    stop_unix_socket_event_collector.
    """
    events_file = f"{socket_path}.events"
    handle = {
        "socket_path": socket_path,
        "events_file": events_file,
        "mode": None,
        "targets": [],
        # legacy single-target fields kept for compatibility
        "container_id": None,
        "host": preferred_host,
        "thread": None,
        "local_stop": None,
    }

    io_daemons = list(_iter_rgw_io_daemons())
    if not io_daemons:
        try:
            d = _pick_rgw_io_daemon(preferred_host=preferred_host)
            if d.get("container_id") and d.get("hostname"):
                io_daemons = [d]
        except Exception as e:
            log.warning(f"Could not resolve RGW container for socket collector: {e}")

    for d in io_daemons:
        host = d.get("hostname")
        cid = d.get("container_id")
        if not host or not cid:
            continue
        target = _start_unix_socket_in_container(host, cid, socket_path, events_file)
        if target:
            handle["targets"].append(target)

    if handle["targets"]:
        handle["mode"] = "container_multi"
        handle["host"] = handle["targets"][0]["host"]
        handle["container_id"] = handle["targets"][0]["container_id"]
        log.info(
            f"UnixSocket '{socket_path}' listening in "
            f"{len(handle['targets'])} IO RGW container(s)"
        )
        time.sleep(1)
        return handle

    # Local fallback (vstart / RGW on same host filesystem)
    stop_flag = {"stop": False}
    events = []
    events_lock = threading.Lock()

    def _local_serve():
        try:
            try:
                os.unlink(socket_path)
            except FileNotFoundError:
                pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(socket_path)
            os.chmod(socket_path, 0o777)
            srv.listen(32)
            srv.settimeout(0.5)
            log.info(
                f"UnixSocket '{socket_path}' is listening for incoming connections..."
            )
            while not stop_flag["stop"]:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                try:
                    data = b""
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    if data:
                        text = data.decode(errors="replace")
                        with events_lock:
                            for line in text.splitlines():
                                if line.strip():
                                    events.append(line.strip())
                finally:
                    conn.close()
            srv.close()
        except Exception as e:
            log.warning(f"Local unix socket collector error: {e}")
        finally:
            try:
                os.unlink(socket_path)
            except Exception:
                pass

    th = threading.Thread(target=_local_serve, daemon=True)
    th.start()
    handle["mode"] = "local"
    handle["thread"] = th
    handle["local_stop"] = stop_flag
    handle["local_events"] = events
    handle["local_lock"] = events_lock
    time.sleep(0.5)
    return handle


def _read_unix_socket_events_from_target(target, events_file):
    """Return raw event lines from one container collector target."""
    cid = target.get("container_id")
    cmd = f"sudo podman exec {cid} cat {events_file} 2>/dev/null || true"
    if target.get("mode") == "container_remote" and target.get("ssh"):
        _stdin, stdout, _stderr = target["ssh"].exec_command(cmd)
        out = stdout.read().decode()
    else:
        out = utils.exec_shell_cmd(cmd)
        if out is False or out is None:
            out = ""
    return [ln.strip() for ln in (out or "").splitlines() if ln.strip()]


def collect_unix_socket_events(handle, wait_seconds=5):
    """
    Wait, then return list of JSON objects collected by the unix socket server.

    With multiple IO RGW containers, merge all collectors and sort by event
    `time` when present so key order matches sequential GETs.
    """
    time.sleep(wait_seconds)
    events = []
    if handle.get("mode") == "local":
        with handle["local_lock"]:
            raw_lines = list(handle["local_events"])
    else:
        events_file = handle["events_file"]
        targets = handle.get("targets") or []
        if not targets and handle.get("container_id"):
            targets = [
                {
                    "container_id": handle["container_id"],
                    "mode": handle.get("mode"),
                    "ssh": handle.get("ssh"),
                }
            ]
        raw_lines = []
        for t in targets:
            raw_lines.extend(_read_unix_socket_events_from_target(t, events_file))

    for line in raw_lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning(f"Skipping non-JSON socket event line: {line[:120]}")

    if any("time" in ev for ev in events):
        events.sort(key=lambda ev: str(ev.get("time", "")))

    log.info(f"Collected {len(events)} unix-socket access-log event(s)")
    for ev in events:
        log.info(f"  event: {ev}")
    return events


def stop_unix_socket_event_collector(handle):
    """Stop the unix socket collector started by start_unix_socket_event_collector."""
    if not handle:
        return
    try:
        if handle.get("mode") == "local":
            if handle.get("local_stop") is not None:
                handle["local_stop"]["stop"] = True
            th = handle.get("thread")
            if th:
                th.join(timeout=3)
            try:
                os.unlink(handle["socket_path"])
            except Exception:
                pass
            return

        events_file = handle["events_file"]
        targets = handle.get("targets") or []
        if not targets and handle.get("container_id"):
            targets = [
                {
                    "container_id": handle["container_id"],
                    "mode": handle.get("mode"),
                    "ssh": handle.get("ssh"),
                }
            ]
        for t in targets:
            cid = t.get("container_id")
            stop_cmd = (
                f"sudo podman exec {cid} bash -lc "
                f"'touch {events_file}.stop; sleep 1; "
                f"rm -f {handle['socket_path']} {events_file} {events_file}.stop "
                f"/tmp/lua_sock_collector.py' || true"
            )
            try:
                if t.get("mode") == "container_remote" and t.get("ssh"):
                    t["ssh"].exec_command(stop_cmd)
                    try:
                        t["ssh"].close()
                    except Exception:
                        pass
                else:
                    utils.exec_shell_cmd(stop_cmd)
            except Exception as e:
                log.warning(f"Failed to stop collector on {cid}: {e}")
    except Exception as e:
        log.warning(f"Failed to stop unix socket collector: {e}")


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


def enable_rgw_debug_logging(level=20, settle_seconds=3):
    """
    Enable log_to_file and set debug_rgw on all RGW services and daemons.
    """
    log.info(f"Enabling log_to_file and debug_rgw={level}")
    utils.exec_shell_cmd("ceph config set global log_to_file true")
    out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
    rgw_daemons = json.loads(out_ps)
    services = set()
    for daemon in rgw_daemons:
        service_name = daemon.get("service_name")
        if service_name:
            services.add(service_name)
        daemon_name = daemon.get("daemon_name")
        if daemon_name:
            utils.exec_shell_cmd(
                f"ceph config set client.{daemon_name} debug_rgw {level}"
            )
    for service_name in services:
        utils.exec_shell_cmd(f"ceph config set client.{service_name} debug_rgw {level}")
    log.info("log_to_file and debug_rgw set for all RGW services and daemons")
    if settle_seconds:
        time.sleep(settle_seconds)


def reset_rgw_debug_logging():
    """
    Remove debug_rgw override for all RGW services and daemons.
    """
    log.info("Resetting debug_rgw to default level")
    out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
    rgw_daemons = json.loads(out_ps)
    services = set()
    for daemon in rgw_daemons:
        service_name = daemon.get("service_name")
        if service_name:
            services.add(service_name)
        daemon_name = daemon.get("daemon_name")
        if daemon_name:
            utils.exec_shell_cmd(f"ceph config rm client.{daemon_name} debug_rgw")
    for service_name in services:
        utils.exec_shell_cmd(f"ceph config rm client.{service_name} debug_rgw")
    log.info("debug_rgw reset for all RGW daemons")


def grep_rgw_logs(pattern, ssh_con=None, haproxy=False, since_epoch=None):
    """
    Grep RGW client logs for an ERE pattern (grep -iE).

    Returns list of matching lines. Remote host lines are prefixed with [host].
    If haproxy is False, try local/ssh_con first and fall back to all RGW hosts
    when no matches are found.
    """
    from datetime import datetime

    fsid = utils.get_cluster_fsid()
    log_dir = f"/var/log/ceph/{fsid}"
    lines = []

    def _grep_on_node(node_ssh, host=None):
        found = []
        if not check_log_directory_exists(log_dir, node_ssh):
            return found
        for log_file in get_rgw_log_files(log_dir, node_ssh, host):
            cmd = f"sudo grep -iE '{pattern}' {log_file} 2>/dev/null || true"
            try:
                if node_ssh:
                    _stdin, stdout, _stderr = node_ssh.exec_command(cmd)
                    out = stdout.read().decode()
                else:
                    out = utils.exec_shell_cmd(cmd)
                    if out is False or out is None:
                        out = ""
            except Exception as e:
                log.warning(f"Failed to grep {log_file} on {host}: {e}")
                continue
            if out and out.strip():
                for raw in out.strip().split("\n"):
                    if raw.strip():
                        prefix = f"[{host}] " if host else ""
                        found.append(f"{prefix}{raw.strip()}")
        return found

    search_all = haproxy
    if not search_all:
        lines = _grep_on_node(ssh_con)
        if not lines:
            log.info("No matching RGW log lines on local/ssh node; checking all hosts")
            search_all = True

    if search_all:
        lines = []
        for host in get_all_rgw_hosts():
            try:
                node_ssh = utils.connect_remote(host)
                lines.extend(_grep_on_node(node_ssh, host))
            except Exception as e:
                log.warning(f"Failed to grep RGW logs on {host}: {e}")

    if since_epoch is not None:
        cutoff = since_epoch - 1
        recent = []
        for line in lines:
            raw = re.sub(r"^\[.*?\]\s+", "", line)
            ts_match = re.match(r"^(\S+)\s", raw)
            keep = True
            if ts_match:
                ts = ts_match.group(1)
                if ts.endswith("+0000"):
                    ts = ts[:-5] + "+00:00"
                try:
                    keep = datetime.fromisoformat(ts).timestamp() >= cutoff
                except ValueError:
                    keep = True
            if keep:
                recent.append(line)
        lines = recent

    return lines


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

    try:
        reset_rgw_debug_logging()
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


EMPTY_PAYLOAD_SHA256 = hashlib.sha256(b"").hexdigest()


def make_sigv4_get(
    url,
    access_key,
    secret_key,
    region,
    include_sha256_in_signed_headers=True,
    extra_unsigned_header=None,
):
    """
    Build SigV4 GET wire headers.
    When include_sha256_in_signed_headers is False, x-amz-content-sha256 is
    still sent on the wire but omitted from SignedHeaders (S3-allowed shape).
    Returns:
        tuple: (wire_headers, signed_headers, canonical_request)
    """
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc
    path = parsed.path or "/"
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = EMPTY_PAYLOAD_SHA256

    if include_sha256_in_signed_headers:
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
    else:
        canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-date"

    canonical_request = "\n".join(
        ["GET", path, "", canonical_headers, signed_headers, payload_hash]
    )
    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    k_date = hmac.new(
        ("AWS4" + secret_key).encode("utf-8"),
        date_stamp.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, b"s3", hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(
        k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    wire_headers = {
        "authorization": authorization,
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if extra_unsigned_header:
        wire_headers.update(extra_unsigned_header)
    return wire_headers, signed_headers, canonical_request
