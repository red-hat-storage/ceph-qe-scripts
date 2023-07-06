"""
Reusable methods for curl
"""


import logging
import os
import sys
import time

import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError

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
    command = curl_auth.command(
        http_method="PUT",
        headers=headers,
        input_file=s3_object_path,
        url_suffix=f"{bucket_name}/{s3_object_name}",
    )
    upload_object_status = utils.exec_shell_cmd(command)
    if upload_object_status is False:
        raise TestExecError("object upload failed")
    log.info(f"object {s3_object_name} uploaded")
    return True


def download_object(
    curl_auth, bucket_name, s3_object_name, TEST_DATA_PATH, s3_object_path
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


def delete_object(curl_auth, bucket_name, s3_object_name):
    """
    delete object using curl
    ex: curl -X DELETE http://10.0.209.142:80/bkt1/obj1
    Args:
        curl_auth(CURL): CURL object instantiated with access details and endpoint
        bucket_name(str): Name of the bucket to be created
        s3_object_name(str): name of the s3 object
    """
    log.info(f"s3 object to delete: {s3_object_name}")
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
