import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import argparse
import logging
import socket

import boto3
import botocore
from v2.lib.exceptions import SyncFailedError, TestExecError
from v2.utils import utils
from v2.utils.io_info_config import IoInfoConfig
from v2.utils.log import configure_logging
from v2.utils.utils import FileOps

log = logging.getLogger()


IO_INFO_FNAME = "io_info.yaml"


def check_object_exists(obj, bucket):
    """
    This function verifies if the object exists

    Parameters:
    key(char): key to be verified
    bucket(char): bucket name
    """
    log.info("check if object exists")
    try:
        key_from_s3 = bucket.Object(obj).get()
    except botocore.exceptions.ClientError as ex:
        if ex.response["Error"]["Code"] == "NoSuchKey":
            raise SyncFailedError("object not synced! data sync failure")


def verify_key(each_key, bucket):
    """
    This function verifies data of each key in the bucket

    Parameters:
        key(char): key to be verified
        bucket(char): bucket name
    """
    log.info(f"verifying data for key: {os.path.basename(each_key['name'])}")
    check_object_exists(os.path.basename(each_key["name"]), bucket)
    key_from_s3 = bucket.Object(os.path.basename(each_key["name"]))
    log.info("verifying size")
    log.info(f"size from yaml: {each_key['size']}")
    log.info(f"size from s3: {key_from_s3.content_length}")
    if int(each_key["size"]) != int(key_from_s3.content_length):
        raise TestExecError("Size not matched")
    log.info("verifying md5")
    log.info(f"md5_local: {each_key['md5_local']}")
    key_from_s3.download_file("download.temp")
    downloaded_md5 = utils.get_md5("download.temp")
    log.info(f"md5_from_s3: {downloaded_md5}")
    if each_key["md5_local"] != downloaded_md5:
        raise TestExecError("Md5 not matched")
    utils.exec_shell_cmd("sudo rm -rf download.temp")
    log.info(f"verification complete for the key: {key_from_s3.key}")


def verify_key_with_version(each_key, bucket):
    """
    This function verifies data of each key in a versioned bucket

    Parameters:
        key(char): key to be verified
        bucket(char): name of the versoiined bucket

    Returns:

    """
    log.info(f"verifying data for key: {os.path.basename(each_key['name'])}")
    check_object_exists(os.path.basename(each_key["name"]), bucket)
    key_from_s3 = bucket.Object(os.path.basename(each_key["name"]))
    no_of_versions = len(each_key["versioning_info"])
    log.info(f"no of versions: {no_of_versions}")
    for each_version in each_key["versioning_info"]:
        log.info(f"version_id: {each_version['version_id']}")
        key_from_s3_with_version = key_from_s3.get(VersionId=each_version["version_id"])
        log.info("verifying size")
        log.info(f"size from yaml: {each_version['size']}")
        log.info(f"size from s3 {key_from_s3_with_version['ContentLength']}")
        if int(each_version["size"] != int(key_from_s3_with_version["ContentLength"])):
            raise TestExecError("Size not matched")
        log.info("verifying md5")
        log.info(f"md5_local: {each_version['md5_local']}")
        key_from_s3.download_file(
            "download.temp", ExtraArgs={"VersionId": each_version["version_id"]}
        )
        downloaded_md5 = utils.get_md5("download.temp")
        log.info(f"md5_from_s3: {downloaded_md5}")
        if each_version["md5_local"] != downloaded_md5:
            raise TestExecError("Md5 not matched")
        utils.exec_shell_cmd("sudo rm -rf download.temp")
        log.info(
            f"verification complete for the key: {key_from_s3.key} ---> version_id: {each_version['version_id']}"
        )


class ReadIOInfo(object):
    def __init__(self, yaml_fname=IO_INFO_FNAME):
        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type="yaml")

    def verify_io(self):
        """
        This function to verify the data of buckets owned by a user

        Data verification happens to all the buckets of a particular user for both versioned and normal buckets
        Parameters:

        Returns:

        """
        log.info("***************Starting Verification*****************")
        data = self.file_op.get_data()
        users = data["users"]
        is_secure = True if utils.is_rgw_secure() else False
        host = socket.gethostbyname(socket.gethostname())

        endpoint_proto = "https" if is_secure else "http"
        endpoint_port = utils.get_radosgw_port_no()
        endpoint_url = f"{endpoint_proto}://{host}:{endpoint_port}"

        for each_user in users:
            if each_user["deleted"] is False:
                log.info("verifying data for the user: \n")
                log.info(f"user_id: {each_user['user_id']}")
                log.info(f"access_key: {each_user['access_key']}")
                log.info(f"secret_key: {each_user['secret_key']}")
                conn = boto3.resource(
                    "s3",
                    aws_access_key_id=each_user["access_key"],
                    aws_secret_access_key=each_user["secret_key"],
                    endpoint_url=endpoint_url,
                    use_ssl=is_secure,
                    verify=False,
                )

                for each_bucket in each_user["bucket"]:
                    if each_bucket["deleted"] is False:
                        log.info(f"verifying data for bucket: {each_bucket['name']}")
                        bucket_from_s3 = conn.Bucket(each_bucket["name"])
                        curr_versioning_status = each_bucket["curr_versioning_status"]
                        log.info(f"curr_versioning_status: {curr_versioning_status}")
                        if not each_bucket["keys"]:
                            log.info("keys are not created")
                        else:
                            no_of_keys = len(each_bucket["keys"])
                            log.info(f"no_of_keys: {no_of_keys}")
                            for each_key in each_bucket["keys"]:
                                if each_key["deleted"] is False:
                                    versioned_keys = len(each_key["versioning_info"])
                                    log.info(f"versioned_keys: {versioned_keys}")
                                    if not each_key["versioning_info"]:
                                        log.info("not versioned key")
                                        verify_key(each_key, bucket_from_s3)
                                    else:
                                        log.info("versioned key")
                                        verify_key_with_version(
                                            each_key, bucket_from_s3
                                        )
                                else:
                                    key_name = each_key["name"]
                                    log.info(
                                        f"Verification of deleted key '{key_name}' starts"
                                    )
                                    try:
                                        key_from_s3 = bucket_from_s3.Object(
                                            os.path.basename(key_name)
                                        )
                                        log.info(key_from_s3.get())
                                        raise AssertionError(
                                            f"Verification of deleted object '{key_name}' failed"
                                        )
                                    except botocore.exceptions.ClientError as e:
                                        log.info(
                                            f"Verification of deleted object '{key_name}' successful"
                                        )
                    else:
                        bucket_name = each_bucket["name"]
                        log.info(
                            f"Verification of deleted bucket '{bucket_name}' starts"
                        )
                        try:
                            conn.meta.client.head_bucket(Bucket=bucket_name)
                            raise AssertionError(
                                f"Verification of deleted bucket '{bucket_name}' failed"
                            )
                        except botocore.exceptions.ClientError as e:
                            error_code = int(e.response["Error"]["Code"])
                            if error_code == 404:
                                log.info(
                                    f"Verification of deleted bucket '{bucket_name}' successful"
                                )
                            else:
                                raise AssertionError(
                                    f"Verification of deleted bucket '{bucket_name}' failed"
                                )
            else:
                user_id = each_user["user_id"]
                log.info(f"Verification of deleted user '{user_id}' starts")
                cmd = f"radosgw-admin user list"
                out = utils.exec_shell_cmd(cmd)
                if user_id not in out:
                    log.info(f"Verification of deleted user '{user_id}' successful")
                else:
                    raise AssertionError(
                        f"Verification of deleted user '{user_id}' failed"
                    )
        log.info("verification of data completed")


if __name__ == "__main__":
    log_f_name = os.path.basename(os.path.splitext(__file__)[0])
    configure_logging(f_name=log_f_name)
    parser = argparse.ArgumentParser(description="RGW S3 Automation")
    parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
    args = parser.parse_args()
    yaml_file = args.config
    IO_INFO_FNAME = f"io_info_{os.path.basename(yaml_file)}"
    IoInfoConfig(io_info_fname=IO_INFO_FNAME)
    read_io_info = ReadIOInfo()
    read_io_info.verify_io()
