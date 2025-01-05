"""
Reusable methods for curl
"""


import glob
import json
import logging
import os
import random
import re
import string
import sys
import time

import names
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError
from v2.lib.manage_data import io_generator

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

import v2.utils.utils as utils


def install_curl(version="7.88.1"):
    """
    installs curl with the given version
    Args:
        version(str): Version of the curl to install
    """
    existing_version = utils.exec_shell_cmd("curl --version")
    if (
        existing_version
        and f"curl {version}" in existing_version.strip()
        and f"libcurl/{version}" in existing_version.strip()
    ):
        log.info(f"CURL is already installed with the version {version}")
        return True
    try:
        log.info(f"installing curl {version}")
        utils.exec_shell_cmd("sudo rm -rf curl*")
        utils.exec_shell_cmd(f"wget https://curl.se/download/curl-{version}.zip")
        utils.exec_shell_cmd("sudo yum install wget gcc openssl-devel make unzip -y")
        utils.exec_shell_cmd(f"unzip curl-{version}.zip")
        utils.exec_shell_cmd(
            f"cd curl-{version}; ./configure --prefix=/home/cephuser/curl --with-openssl; make; sudo make install"
        )
        if existing_version:
            existing_curl_version = existing_version.strip().split(" ")[1]
            utils.exec_shell_cmd(
                f"sudo mv /usr/bin/curl /usr/bin/curl-{existing_curl_version}.bak"
            )
        utils.exec_shell_cmd("sudo cp curl/bin/curl /usr/bin/")
        utils.exec_shell_cmd("which curl")
        upgraded_version = utils.exec_shell_cmd("curl --version")
        if (
            upgraded_version
            and f"curl {version}" in upgraded_version.strip()
            and f"libcurl/{version}" in upgraded_version.strip()
        ):
            log.info(f"CURL Upgrade to {version} successful")
        else:
            raise Exception(
                f"CURL upgrade to {version} failed, still showing previous version"
            )

        log.info("sleeping for 15 seconds")
        time.sleep(15)
    except:
        raise TestExecError("CURL Installation Failed")
    return True


def create_user(curl_auth, user_name=None):
    """
    create rgw user using curl
    ex: curl -X PUT http://10.0.209.142:80/admin/user?display-name=display_name&uid=user_name
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        user_name(str): Name of the user to be created
    """
    if user_name is None:
        user_name = (
            names.get_first_name().lower()
            + random.choice(string.ascii_lowercase)
            + "."
            + str(random.randint(1, 1000)),
        )
    log.info(f"rgw user to create: {user_name}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        url_suffix=f"admin/user?display-name={user_name}&uid={user_name}",
    )
    user_create_resp = utils.exec_shell_cmd(command)
    if user_create_resp is False:
        raise TestExecError("user creation failed")
    log.info(f"user create response: {user_create_resp}")
    return user_create_resp


def get_user_info(curl_auth, uid):
    """
    get rgw user info using curl
    ex: curl -X GET http://10.0.209.142:80/admin/user?uid=user_name
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        uid(str): uid of the user
    """
    log.info(f"get rgw user info for uid: {uid}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="GET",
        headers=headers,
        url_suffix=f"admin/user?uid={uid}",
    )
    user_get_resp = utils.exec_shell_cmd(command)
    if user_get_resp is False:
        raise TestExecError("get user info failed")
    log.info(f"user get response: {user_get_resp}")
    return user_get_resp


def create_subuser(curl_auth, uid, subuser_name):
    """
    create rgw user using curl
    ex: curl -X PUT http://10.0.209.142:80/admin/user?subuser=subuser_name&uid=user_name
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        uid(str): uid of the user
        subuser_name(str): name of the user to be created
    """
    log.info(f"subuser to create: {subuser_name}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        url_suffix=f"admin/user?subuser={subuser_name}&uid={uid}",
    )
    subuser_create_resp = utils.exec_shell_cmd(command)
    if subuser_create_resp is False:
        raise TestExecError("subuser creation failed")
    log.info(f"subuser create response: {subuser_create_resp}")
    return subuser_create_resp


def create_bucket(curl_auth, bucket_name):
    """
    Creates bucket
    ex: curl -X PUT http://10.0.209.142:80/bkt1
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
    """
    utils.exec_shell_cmd("curl --version")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="PUT", headers=headers, url_suffix=bucket_name
    )
    bucket_creation_status = utils.exec_shell_cmd(command)
    if bucket_creation_status is False:
        raise TestExecError("Bucket Creation Failed")
    log.info(f"Bucket {bucket_name} created")
    return True


def upload_object(
    curl_auth,
    bucket_name,
    s3_object_name,
    TEST_DATA_PATH,
    config,
    append_data=False,
    append_msg=None,
    Transfer_Encoding=None,
    extra_headers={},
    request_options=False,
    presigned_url=None,
):
    """
    upload object using curl
    ex: curl -X PUT http://10.0.209.142:80/bkt1/obj1 -T /home/cephuser/in_file_name
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
        s3_object_name(str): name of the s3 object
        TEST_DATA_PATH(str): test data path where objects created are stored on ceph-qe-scripts local repo
        config(dict): config yaml
        append_data(bool): whether to append data in case of versioning
        append_msg(str): message to append to existing data of an object
        Transfer_Encoding(str): header of the curl command used if the actual size is unknown, value is 'chunked'
    """
    log.info(f"s3 object name: {s3_object_name}")
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info(f"s3 object path: {s3_object_path}")
    s3_object_size = config.obj_size
    if append_data is True:
        data_info = manage_data.io_generator(
            s3_object_path,
            s3_object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    log.info(f"uploading s3 object: {s3_object_path}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    if Transfer_Encoding:
        headers["Transfer-Encoding"] = Transfer_Encoding
    else:
        headers["Content-Length"] = config.obj_size
    headers.update(extra_headers)
    if request_options:
        log.info("testing requests.options before the actual put request")
        headers_options = headers.copy()
        headers_options["Access-Control-Request-Method"] = "PUT"
        command = curl_auth.command(
            http_method="OPTIONS",
            headers=headers_options,
            input_file=s3_object_path,
            # url_suffix=f"{bucket_name}/{s3_object_name}",
            presigned_url=presigned_url,
        )
        upload_object_status = utils.exec_shell_cmd(command)
        if upload_object_status is False:
            raise TestExecError("requests.options failed for PUT")
        log.info(f"object {s3_object_name} uploaded")
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        input_file=s3_object_path,
        url_suffix=f"{bucket_name}/{s3_object_name}",
        presigned_url=presigned_url,
    )
    upload_object_status = utils.exec_shell_cmd(command)
    if upload_object_status is False:
        raise TestExecError("object upload failed")
    log.info(f"object {s3_object_name} uploaded")
    return True


def put_cors_object(
    curl_auth,
    bucket_name,
    s3_object_name,
    TEST_DATA_PATH,
    config,
    cors_origin,
):
    """
    Upload object using cURL PUT command
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
        s3_object_name(str): name of the s3 object
        TEST_DATA_PATH(str): test data path where objects created are stored on ceph-qe-scripts local repo
        config(dict): config yaml
        cors origin: origin header on the cors policy
    """
    log.info(f"s3 object name: {s3_object_name}")
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info(f"s3 object path: {s3_object_path}")
    s3_object_size = config.obj_size
    data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    log.info(f"uploading s3 object: {s3_object_path}")
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD", "Origin": cors_origin}
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        input_file=s3_object_path,
        url_suffix=f"{bucket_name}/{s3_object_name}",
    )
    upload_object_status, err = utils.exec_shell_cmd(command, debug_info=True)
    log.info(upload_object_status)
    if upload_object_status is False:
        raise TestExecError("object upload failed")
    log.info(f"object {s3_object_name} uploaded")
    return upload_object_status


def download_object(
    curl_auth,
    bucket_name,
    s3_object_name,
    TEST_DATA_PATH,
    s3_object_path,
    cors_origin=None,
):
    """
    download object using curl
    ex: curl -X GET http://10.0.209.142:80/bkt1/obj1 -o /home/cephuser/out_file_name
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
        s3_object_name(str): name of the s3 object
        s3_object_path(str): path of the s3 object on the local node
        TEST_DATA_PATH(str): test data path where objects created are stored on ceph-qe-scripts local repo
    """
    log.info(f"s3 object name to download: {s3_object_name}")
    s3_object_download_name = s3_object_name + "." + "download"
    s3_object_download_path = os.path.join(TEST_DATA_PATH, s3_object_download_name)
    if cors_origin:
        headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD", "Origin": cors_origin}
    else:
        headers = {
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        }
    command = curl_auth.command(
        http_method="GET",
        headers=headers,
        output_file=s3_object_download_path,
        url_suffix=f"{bucket_name}/{s3_object_name}",
    )
    upload_object_status = utils.exec_shell_cmd(command)
    if upload_object_status is False:
        raise TestExecError("object download failed")
    log.info(f"object {s3_object_name} downloaded")

    s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
    s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
    log.info(f"s3_object_downloaded_md5: {s3_object_downloaded_md5}")
    log.info(f"s3_object_uploaded_md5: {s3_object_uploaded_md5}")
    if str(s3_object_uploaded_md5) == str(s3_object_downloaded_md5):
        log.info("md5 match")
        utils.exec_shell_cmd(f"rm -rf {s3_object_download_path}")
    else:
        raise TestExecError("md5 mismatch")


def delete_object(curl_auth, bucket_name, s3_object_name, cors_origin=None):
    """
    delete object using curl
    ex: curl -X DELETE http://10.0.209.142:80/bkt1/obj1
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
        s3_object_name(str): name of the s3 object
    """
    log.info(f"s3 object to delete: {s3_object_name}")
    if cors_origin:
        headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD", "Origin": cors_origin}
    else:
        headers = {
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        }
    command = curl_auth.command(
        http_method="DELETE",
        headers=headers,
        url_suffix=f"{bucket_name}/{s3_object_name}",
    )
    delete_object_status = utils.exec_shell_cmd(command)
    if delete_object_status is False:
        raise TestExecError("object deletion failed")
    log.info(f"object {s3_object_name} deleted")
    return True


def delete_bucket(curl_auth, bucket_name):
    """
    delete bucket using curl
    ex: curl -X DELETE http://10.0.209.142:80/bkt1
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
    """
    log.info(f"Bucket to delete: {bucket_name}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="DELETE", headers=headers, url_suffix=f"{bucket_name}"
    )
    delete_bucket_status = utils.exec_shell_cmd(command)
    if delete_bucket_status is False:
        raise TestExecError("bucket deletion failed")
    log.info(f"Bucket {bucket_name} deleted")
    return True


def set_user_quota(curl_auth, user_id, quota_type, quota_json):
    """
    set user/bucket quota to a user
    example for put user quota: curl -X PUT "http://10.0.103.136:80/admin/user?quota=true&quota-type=user&uid=hmaheswa3"
    example for put bucket quota: curl -X PUT "http://10.0.103.136:80/admin/user?quota=true&quota-type=bucket&uid=hmaheswa3"
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        user_id(str): uid of the rgw user
        quota_type(str): user or bucket
        quota_json(dict): JSON representation of the quota settings
                            {
                                "enabled": true,
                                "max_size": 1099511627776,
                                "max_size_kb": 0,
                                "max_objects": 100
                            }
    """
    log.info(f"setting {quota_type} quota")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        url_suffix=f"admin/user?quota=true&quota-type={quota_type}&uid={user_id}",
        raw_data_list=[json.dumps(quota_json)],
    )
    cmd_output = utils.exec_shell_cmd(command)
    log.info(f"set user quota status: {cmd_output}")
    if cmd_output is False:
        raise TestExecError(f"failed to set user quota for quota-type {quota_type}")
    log.info(f"successfully set user quota for quota-type {quota_type}")
    return True


def set_individual_bucket_quota(curl_auth, user_id, bucket_name, quota_json):
    """
    set bucket quota to a specific bucket
    ex: curl -X PUT "http://10.0.103.136:80/admin/bucket?bucket=bkt3&quota=true&uid=hmaheswa3"
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        user_id(str): uid of the rgw user
        bucket_name(str): name of the bucket
        quota_json(dict): JSON representation of the quota settings
                            {
                                "enabled": true,
                                "max_size": 1099511627776,
                                "max_size_kb": 0,
                                "max_objects": 100
                            }
    """
    log.info(f"setting bucket quota to a particular bucket {bucket_name}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        url_suffix=f"admin/bucket?bucket={bucket_name}&quota=true&uid={user_id}",
        raw_data_list=[json.dumps(quota_json)],
    )
    cmd_output = utils.exec_shell_cmd(command)
    log.info(f"bucket quota set status: {cmd_output}")
    if cmd_output is False:
        raise TestExecError(
            f"failed to set bucket quota for bucket {bucket_name} failed"
        )
    log.info(f"successfully set bucket quota for bucket {bucket_name}")
    return True


def verify_user_quota_details(user_id, quota_type, quota_json):
    """
    Verify quota settings present in user info with the expected quota settings
    Args:
        user_id(str): uid of the rgw user
        quota_type(str): user or bucket
        quota_json(dict): JSON representation of the quota settings
                            {
                                "enabled": true,
                                "max_size": 1099511627776,
                                "max_size_kb": 0,
                                "max_objects": 100
                            }
    """
    user_info_op = utils.exec_shell_cmd(f"radosgw-admin user info --uid={user_id}")
    user_info_json = json.loads(user_info_op)
    user_info_quota_json = user_info_json[f"{quota_type}_quota"]
    log.info(f"Verifying quota details in user info with below values:\n{quota_json}")
    if quota_json == user_info_quota_json:
        log.info("quota settings verified successfully")
    else:
        log.error(f"Expected quota details: {quota_json}")
        log.error(f"Actual quota details: {user_info_quota_json}")
        raise TestExecError("Incorrect quota details found in user info")


def verify_individual_bucket_quota_details(curl_auth, bucket_name, quota_json):
    """
    Verify quota settings present in bucket stats with the expected quota settings
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): name of the bucket
        quota_json(dict): JSON representation of the quota settings
                            {
                                "enabled": true,
                                "max_size": 1099511627776,
                                "max_size_kb": 0,
                                "max_objects": 100
                            }
    """
    log.info("Verifying bucket quota settings in bucket stats")
    bucket_stats_op = utils.exec_shell_cmd(
        f"radosgw-admin bucket stats --bucket={bucket_name}"
    )
    bucket_stats_json = json.loads(bucket_stats_op)
    bucket_stats_quota_json = bucket_stats_json[f"bucket_quota"]
    if quota_json == bucket_stats_quota_json:
        log.info("bucket quota settings verified successfully")
    else:
        log.error(f"Expected quota settings: {quota_json}")
        log.error(f"Actual quota settings: {bucket_stats_quota_json}")
        raise TestExecError("Incorrect quota settings found in bucket stats")
    return True


def verify_quota_head_bucket(curl_auth, bucket_name, head_bucket_json):
    """
    Verify quota settings present in head bucket with the expected quota settings
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): name of the bucket
        head_bucket_json(dict): JSON representation of the quota settings
                            {
                                X-RGW-Quota-User-Size: -1
                                X-RGW-Quota-User-Objects: -1
                                X-RGW-Quota-Max-Buckets: 1000
                                X-RGW-Quota-Bucket-Size: 1024000
                                X-RGW-Quota-Bucket-Objects: 100
                            }
    """
    log.info(
        f"Verifying quota settings in head bucket with below values:\n{head_bucket_json}"
    )
    head_bucket_op = head_bucket(curl_auth, bucket_name)
    for key, val in head_bucket_json.items():
        if f"{key}: {val}" not in head_bucket_op:
            raise TestExecError(f"incorrect value found. Expected f'{key}: {val}'")
    log.info("Quota settings in head bucket verified successfully")
    return True


def head_bucket(curl_auth, bucket_name):
    """
    perform head operation on the bucket
    ex: curl -I "http://10.0.103.136:80/bkt1"
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): name of the bucket
    """
    log.info(f"performing head bucket on {bucket_name}")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        headers=headers, url_suffix=f"{bucket_name}", head_request=True
    )
    cmd_output = utils.exec_shell_cmd(command)
    log.info(f"head bucket result: {cmd_output}")
    if cmd_output is False:
        raise TestExecError(
            f"failed to perform head bucket operation on the bucket {bucket_name}"
        )
    return cmd_output


def get_user_quota(curl_auth, user_id, quota_type):
    """
    set user/bucket quota to a user
    example for put user quota: curl -X GET "http://10.0.103.136:80/admin/user?quota=true&quota-type=user&uid=hmaheswa3"
    example for put bucket quota: curl -X GET "http://10.0.103.136:80/admin/user?quota=true&quota-type=bucket&uid=hmaheswa3"
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        user_id(str): uid of the rgw user
        quota_type(str): user or bucket
    """
    log.info(f"get {quota_type} quota")
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    command = curl_auth.command(
        http_method="GET",
        headers=headers,
        url_suffix=f"admin/user?quota=true&quota-type={quota_type}&uid={user_id}",
    )
    cmd_output = utils.exec_shell_cmd(command)
    log.info(f"user quota: {cmd_output}")
    if cmd_output is False:
        raise TestExecError(f"failed to get user quota for quota-type {quota_type}")
    return cmd_output


def create_multipart_upload(curl_auth, bucket_name, s3_object_name):
    """
    Initiate multipart uploads for given object on a given bucket
    Ex: curl -X POST '{endpoint_url}/{bucket_name}/{object_name}?uploads=true'
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
        s3_object_name(str): name of the s3 object
    Return:
        Response of create-multipart-upload
    """
    log.info(f"create multipart upload for object: {s3_object_name}")
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD", "Accept": "application/json"}
    command = curl_auth.command(
        http_method="POST",
        headers=headers,
        url_suffix=f"{bucket_name}/{s3_object_name}?uploads=true",
    )
    create_mpu_output = utils.exec_shell_cmd(command)
    if create_mpu_output is False:
        raise TestExecError(
            f"create multipart upload failed for object {s3_object_name}"
        )
    log.info(f"create multipart upload successful for object {s3_object_name}")
    return create_mpu_output


def upload_part(
    curl_auth,
    bucket_name,
    s3_object_name,
    part_number,
    upload_id,
    body,
    content_length=None,
):
    """
    Upload part to the key in a bucket
    Ex: /usr/local/bin/aws s3api upload-part --bucket <bucket_name> --key <key_name> --part-number <part_number>
        --upload-id <upload_id> --body <body> --endpoint <endpoint_url>
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket
        s3_object_name(str): Name of the object for which part has to be uploaded
        part_number(int): part number
        upload_id(str): upload id fetched during initiating multipart upload
        body(str): part file which needed to be uploaded
    Return:
        Response of uplaod_part i.e., Etag
    """
    log.info(f"upload part {part_number} for object: {s3_object_name}")
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if content_length:
        headers["Content-Length"] = content_length
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        input_file=body,
        url_suffix=f"{bucket_name}/{s3_object_name}?partNumber={part_number}&uploadId={upload_id}",
    )
    upload_part_output, verbose_output = utils.exec_shell_cmd(command, debug_info=True)
    if upload_part_output is False:
        raise TestExecError(f"upload part failed for object {s3_object_name}")
    log.info(f"upload part successful for object {s3_object_name}")

    etag_line = re.findall('< ETag: ".*"', str(verbose_output))
    etag = etag_line[0].split(" ")[-1]
    return etag


def complete_multipart_upload(
    curl_auth, bucket_name, s3_object_name, upload_id, complete_mpu_string
):
    """
    Complete multipart uploads for given object on a given bucket
    Ex: /usr/local/bin/aws s3api complete-multipart-upload --multipart-upload file://<upload_file>
        --bucket <bucket_name> --key <key_name> --upload-id <upload_id> --endpoint <endpoint_url>
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket
        s3_object_name(str): Name of the object for which multipart upload has to be Completed
        upload_id(str): upload id fetched during initiating multipart upload
        complete_mpu_string(str): xml structure in the form of string containing parts of part number and etag
            ex: '<CompleteMultipartUpload>
                    <Part>
                        <PartNumber>1</PartNumber>
                        <ETag>"14d20d18d7f0fed186b420fe6fd31991"</ETag>
                    </Part>
                    <Part>
                        <PartNumber>2</PartNumber>
                        <ETag>"0f86d7c5a6180cf9584c1d21144d85b0"</ETag>
                    </Part>
                </CompleteMultipartUpload>'
    Return:
        Response of complete-multipart-upload
    """
    log.info(f"complete multipart upload for object: {s3_object_name}")
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD", "Accept": "application/json"}
    command = curl_auth.command(
        http_method="POST",
        headers=headers,
        raw_data_list=[complete_mpu_string],
        url_suffix=f"{bucket_name}/{s3_object_name}?uploadId={upload_id}",
    )
    complete_mpu_output = utils.exec_shell_cmd(command)
    if complete_mpu_output is False:
        raise TestExecError(
            f"complete multipart upload failed for object {s3_object_name}"
        )
    log.info(f"complete multipart upload successful for object {s3_object_name}")
    return complete_mpu_output


def upload_multipart_object(
    curl_auth,
    bucket_name,
    s3_object_name,
    TEST_DATA_PATH,
    config,
    append_data=False,
    append_msg=None,
):
    """
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket
        s3_object_name(str): Name of the object
        TEST_DATA_PATH(str): Test data path
        config: configuration used
        append_data(boolean)
        append_msg(str)
    Return:
        Returns True if success else raises an Exception
    """
    log.info("Create multipart upload")
    create_mp_upload_resp = create_multipart_upload(
        curl_auth, bucket_name, s3_object_name
    )
    upload_id = json.loads(create_mp_upload_resp)["UploadId"]

    log.info(f"object name: {s3_object_name}")
    object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
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

    mp_dir = os.path.join(TEST_DATA_PATH, s3_object_name + ".mp.parts")
    log.info(f"mp part dir: {mp_dir}")
    log.info("making multipart object part dir")
    mkdir = utils.exec_shell_cmd(f"sudo mkdir {mp_dir}")
    if mkdir is False:
        raise TestExecError("mkdir failed creating mp_dir_name")
    utils.split_file(object_path, split_size, mp_dir + "/")
    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
    log.info("parts_list: %s" % parts_list)

    part_number = 1
    log.info("no of parts: %s" % len(parts_list))

    complete_mpu_string = "<CompleteMultipartUpload>"
    for each_part in parts_list:
        log.info(f"upload part {part_number} of object: {s3_object_name}")

        etag = upload_part(
            curl_auth, bucket_name, s3_object_name, part_number, upload_id, each_part
        )

        complete_mpu_string = (
            complete_mpu_string
            + f"<Part><PartNumber>{part_number}</PartNumber><ETag>{etag}</ETag></Part>"
        )

        if each_part != parts_list[-1]:
            # increase the part number only if the current part is not the last part
            part_number += 1
        log.info("curr part_number: %s" % part_number)

    complete_mpu_string = complete_mpu_string + "</CompleteMultipartUpload>"

    if config.local_file_delete is True:
        log.info("deleting local file part")
        utils.exec_shell_cmd(f"rm -rf {mp_dir}")

    if len(parts_list) == part_number:
        log.info("all parts upload completed")
        complete_multipart_upload_resp = json.loads(
            complete_multipart_upload(
                curl_auth, bucket_name, s3_object_name, upload_id, complete_mpu_string
            )
        )
        if not complete_multipart_upload_resp["ETag"]:
            raise AssertionError(
                "Etag not generated during complete multipart upload operation"
            )
        return True
