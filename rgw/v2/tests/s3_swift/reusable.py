import base64
import glob
import json
import os
import random
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import logging
import math
import time
import timeit
from threading import Thread

import configobj
import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import DefaultDatalogBackingError, MFAVersionError, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.lib.sync_status import sync_status
from v2.tests.s3_swift.reusables import server_side_encryption_s3 as sse_s3
from v2.utils.utils import HttpResponseParser, RGWService

rgw_service = RGWService()

log = logging.getLogger()


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format string
    raise TypeError(f"Type {type(obj)} not serializable")


def run_command(command):
    """Runs a shell command and returns JSON output."""
    process = subprocess.run(command, capture_output=True, text=True, shell=True)
    if process.returncode != 0 or not process.stdout.strip():
        return None  # Handle cases where the command fails
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError:
        return process.stdout.strip()  # Return raw output if JSON decoding fails


def create_rgw_account_with_iam_user(
    config,
    tenant_name,
    region="shared",
):
    """
    Automates the creation of an RGW tenanted account, root user, IAM user, and grants full S3 access.

    Returns:
        dict: IAM user details, including access/secret keys and RGW IAM user info.
    """
    rgw_ip_primary_zone = utils.get_rgw_ip_zone("primary")
    rgw_port_primary_zone = utils.get_radosgw_port_no()
    endpoint_url = f"http://{rgw_ip_primary_zone}:{rgw_port_primary_zone}"
    # Step 1: Check if RGW account exists using account ID
    existing_accounts = run_command("radosgw-admin account list")
    account_id = None
    for account in existing_accounts:
        account_info = run_command(f"radosgw-admin account get --account-id {account}")
        if account_info.get("tenant") == tenant_name:
            logging.info(f"Reusing existing account: {account}")
            account_id = account
            break
    if not account_id:
        account_id = f"RGW{random.randint(10**16, 10**17 - 1)}"
        account_name = f"account-{random.randint(1000, 9999)}"
        account_email = f"{account_name}@email.com"
        new_account = run_command(
            f"radosgw-admin account create --account-name {account_name} "
            f"--tenant {tenant_name} --email {account_email} --account-id {account_id}"
        )
        if not new_account:
            raise RuntimeError("Failed to create account.")
        logging.info(f"Created new account: {account_id}")

    # Step 2: Check for existing users under this account
    user_list = run_command(f"radosgw-admin user list --account-id {account_id}")
    root_user = None
    iam_user_uid = None
    if user_list:
        for user in user_list:
            if "root" in user:  # Identify root user
                root_user = user
            elif user != root_user:  # Identify IAM user (non-root with long UID)
                iam_user_uid = user

    if root_user:
        log.info(f"Found existing root user: {root_user}. Fetching credentials...")
        root_user_info = run_command(
            f"radosgw-admin user info --uid {root_user.split('$')[-1]} --tenant {tenant_name}"
        )
        access_key = root_user_info["keys"][0]["access_key"]
        secret_key = root_user_info["keys"][0]["secret_key"]
    else:
        # Step 4: Create RGW root user if it does not exist
        root_user_name = f"{account_name}root-user"
        root_user_info = run_command(
            f"radosgw-admin user create --uid {root_user_name} --display-name {root_user_name} --tenant {tenant_name} --account-id {account_id} --account-root --gen-secret --gen-access-key"
        )
        if not root_user_info:
            raise RuntimeError(f"Failed to create RGW root user: {root_user_name}")
        access_key = root_user_info["keys"][0]["access_key"]
        secret_key = root_user_info["keys"][0]["secret_key"]
        log.info(f"Created RGW root user: {root_user_name}")

    # Step 5: Establish IAM session using root user's credentials
    rgw_session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )

    # Step 6: Create IAM client
    iam_client = rgw_session.client("iam", endpoint_url=endpoint_url)

    if iam_user_uid:
        log.info(f"Found existing IAM user UID: {iam_user_uid}. Fetching details...")
        iam_user_rgw_info = run_command(
            f"radosgw-admin user info --uid {iam_user_uid.split('$')[-1]} --tenant {tenant_name}"
        )
        access_key_data = None  # No need to create new IAM user
    else:
        # Step 7: Create IAM user if it does not exist
        iam_user_name = f"{account_name}iam-user"
        try:
            iam_client.create_user(UserName=iam_user_name)
            access_key_data = iam_client.create_access_key(UserName=iam_user_name)
            iam_client.attach_user_policy(
                UserName=iam_user_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            )
            log.info(f"Created IAM user: {iam_user_name} with full S3 access")
        except iam_client.exceptions.EntityAlreadyExistsException:
            log.info(f"IAM user '{iam_user_name}' already exists.")
            access_key_data = None  # Skip key creation if user exists

        # Step 8: Get IAM user info
        user_info = iam_client.get_user(UserName=iam_user_name)
        log.info(f"Retrieved IAM user info: {user_info}")

        # Step 9: Fetch IAM user details from RGW
        user_list = run_command(f"radosgw-admin user list --account-id {account_id}")
        iam_user_uid = next(uid for uid in user_list if uid != root_user_name)
        iam_user_rgw_info = run_command(
            f"radosgw-admin user info --uid {iam_user_uid.split('$')[-1]} --tenant {tenant_name}"
        )
        log.info(f"Display the iam_user_rgw_info {iam_user_rgw_info}")
    iam_user_details = [
        {
            "user_id": iam_user_rgw_info["user_id"],
            "display_name": iam_user_rgw_info["display_name"],
            "access_key": iam_user_rgw_info["keys"][0]["access_key"],
            "secret_key": iam_user_rgw_info["keys"][0]["secret_key"],
        }
    ]
    write_user_info = AddUserInfo()
    basic_io_structure = BasicIOInfoStructure()
    user_info = basic_io_structure.user(
        **{
            "user_id": iam_user_rgw_info["user_id"],
            "access_key": iam_user_rgw_info["keys"][0]["access_key"],
            "secret_key": iam_user_rgw_info["keys"][0]["secret_key"],
        }
    )
    write_user_info.add_user_info(user_info)
    user_detail_file = s3lib.get_writable_user_details_file()
    with open(user_detail_file, "w") as fout:
        json.dump(iam_user_details, fout)
    return iam_user_details


def create_bucket(
    bucket_name, rgw, user_info, endpoint=None, location=None, retries=3, wait_time=5
):

    if endpoint is not None:
        # Retry until endpoint is reachable or max retries reached
        for attempt in range(1, retries + 1):
            output = utils.exec_shell_cmd(f"curl -k --connect-timeout 10 {endpoint}")
            if output:
                log.info(f"Endpoint {endpoint} is reachable on attempt {attempt}.")
                break
            else:
                log.warning(
                    f"Attempt {attempt}: Endpoint {endpoint} not reachable, retrying in {wait_time}s..."
                )
                time.sleep(wait_time)
        else:
            log.error(f"Endpoint {endpoint} is not reachable after {retries} attempts.")
            return

    log.info("creating bucket with name: %s" % bucket_name)
    # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)
    bucket = s3lib.resource_op(
        {"obj": rgw, "resource": "Bucket", "args": [bucket_name]}
    )
    kw_args = None
    if location is not None:
        kw_args = dict(CreateBucketConfiguration={"LocationConstraint": location})
    created = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "create",
            "args": None,
            "kwargs": kw_args,
            "extra_info": {"access_key": user_info["access_key"]},
        }
    )
    log.info(f"bucket creation data: {created}")
    if created is False:
        raise TestExecError("Resource execution failed: bucket creation failed")
    if created is not None:
        response = HttpResponseParser(created)
        if response.status_code == 200:
            log.info("bucket created")
        else:
            raise TestExecError("bucket creation failed")
    else:
        raise TestExecError("bucket creation failed")

    is_multisite = utils.is_cluster_multisite()
    if is_multisite:
        log.info("Cluster is multisite")
        remote_site_ssh_con = get_remote_conn_in_multisite()

        log.info("Check sync status in local site")
        sync_status()

        log.info("Check sync status in remote site")
        sync_status(ssh_con=remote_site_ssh_con)
    return bucket


def create_bucket_sync_init(bucket_name, rgw, user_info, location=None):
    log.info("creating bucket with name: %s" % bucket_name)
    bucket = s3lib.resource_op(
        {"obj": rgw, "resource": "Bucket", "args": [bucket_name]}
    )
    kw_args = None
    if location is not None:
        kw_args = dict(CreateBucketConfiguration={"LocationConstraint": location})
    created = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "create",
            "args": None,
            "kwargs": kw_args,
            "extra_info": {"access_key": user_info["access_key"]},
        }
    )
    log.info(f"bucket creation data: {created}")
    if created is False:
        raise TestExecError("Resource execution failed: bucket creation failed")
    if created is not None:
        response = HttpResponseParser(created)
        if response.status_code == 200:
            log.info("bucket created")
        else:
            raise TestExecError("bucket creation failed")
    else:
        raise TestExecError("bucket creation failed")

    return bucket


def get_remote_conn_in_multisite():
    """
    Method to fetch remote ip incase of multisite setup
    :return: ssh connection
    """
    primary = utils.is_cluster_primary()
    if primary:
        remote_zone_name = "secondary"
    else:
        remote_zone_name = "primary"

    remote_rgw_ip = utils.get_rgw_ip_zone(remote_zone_name)
    log.info(f"remote_ip : {remote_rgw_ip}")
    remote_site_ssh_con = utils.connect_remote(remote_rgw_ip)
    log.info(f"remote_site_ssh_con : {remote_site_ssh_con}")
    return remote_site_ssh_con


def create_bucket_readonly(bucket_name, rgw, user_info):
    log.info("creating bucket with name: %s" % bucket_name)
    bucket = s3lib.resource_op(
        {"obj": rgw, "resource": "Bucket", "args": [bucket_name]}
    )
    kw_args = None
    created = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "create",
            "args": None,
            "kwargs": kw_args,
            "extra_info": {"access_key": user_info["access_key"]},
        }
    )
    log.info(f"bucket creation data: {created}")
    if created is not False:
        raise TestExecError("Resource execution failed: bucket creation worked")
    else:
        log.info("Bucket creation failed as expected")


def set_get_object_acl(s3_object_name, bucket_name, rgw_conn2, acl="private"):
    """
    put object acl as private for a given object
    """
    log.info("Set object acl on s3 object name: %s" % s3_object_name)
    put_obj_acl = rgw_conn2.put_object_acl(
        ACL=acl, Bucket=bucket_name, Key=s3_object_name
    )
    if put_obj_acl:
        get_obj_acl = rgw_conn2.get_object_acl(Bucket=bucket_name, Key=s3_object_name)
        get_obj_acl_json = json.dumps(get_obj_acl, indent=2)
        log.info(f"object acl set for object: {s3_object_name} is{get_obj_acl_json}")
    else:
        raise TestExecError("put object acl failed")


def retain_bucket_policy(rgw_conn2, bucket_name_to_create, config):
    """
    put bucket policy and retain it at archive site
    """
    log.info(f"Set bucket policy on {bucket_name_to_create}")
    put_bucket_pol = rgw_conn2.put_bucket_policy(
        Bucket=bucket_name_to_create,
        Policy='{"Version": "2012-10-17", "Statement": [{ "Sid": "id-1","Effect": "Allow","Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": [ "s3:PutObject","s3:PutObjectAcl"], "Resource": ["arn:aws:s3:::acl3/*" ] } ]}',
    )
    if not put_bucket_pol:
        raise TestExecError("put bucket pol failed")


def sync_test_0_shards(config):
    """
    This function sets the bucket_index_max_shards to 0 at the zonegroup
    """
    log.info("Test multisite replication with 0 shards")
    utils.exec_shell_cmd(f"radosgw-admin zonegroup modify --bucket_index_max_shards 0")
    utils.exec_shell_cmd(f"radosgw-admin period update --commit")
    utils.exec_shell_cmd(f"radosgw-admin period get")


def upload_object(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    append_data=False,
    append_msg=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
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
    log.info("uploading s3 object: %s" % s3_object_path)
    upload_info = dict({"access_key": user_info["access_key"]}, **data_info)
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )

    args = [s3_object_path]
    if config.test_ops.get("sse_s3_per_object") is True:
        if config.encryption_keys == "s3":
            log.info("SSE S3 AES256 encryption method applied")
            extra_args = {"ServerSideEncryption": "AES256"}
            args.append(extra_args)
        elif config.encryption_keys == "kms":
            log.info("SSE KMS encryption method applied with vault backend")
            extra_args = {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": config.test_ops.get("encrypt_decrypt_key", "testKey01"),
            }
            args.append(extra_args)
    if config.test_ops.get("test_checksum") is True:
        checksum_algorithm = config.test_ops.get("checksum_algorithm")
        log.info(f"ChecksumAlgorithm used is {checksum_algorithm}")
        extra_args = {"ChecksumAlgorithm": checksum_algorithm}
        args.append(extra_args)
    object_uploaded_status = s3lib.resource_op(
        {
            "obj": s3_obj,
            "resource": "upload_file",
            "args": args,
            "extra_info": upload_info,
        }
    )
    if object_uploaded_status is False:
        raise TestExecError("Resource execution failed: object upload failed")
    if object_uploaded_status is None:
        log.info("object uploaded")


def failed_upload_object(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    append_data=False,
    append_msg=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
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
    log.info("uploading s3 object: %s" % s3_object_path)
    upload_info = dict({"access_key": user_info["access_key"]}, **data_info)
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )
    object_uploaded_status = s3lib.resource_op(
        {
            "obj": s3_obj,
            "resource": "upload_file",
            "args": [s3_object_path],
            "extra_info": upload_info,
        }
    )
    if object_uploaded_status is None:
        raise TestExecError("Resource execution failed: object upload failed")
    if object_uploaded_status is False:
        log.info("failed to uploaded the object as access is denied")


def upload_version_object(
    config, user_info, rgw_conn, s3_object_name, object_size, bucket, TEST_DATA_PATH
):
    # versioning upload
    log.info("versioning count: %s" % config.version_count)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    original_data_info = manage_data.io_generator(s3_object_path, object_size)
    if original_data_info is False:
        TestExecError("data creation failed")
    created_versions_count = 0
    for vc in range(config.version_count):
        log.info("version count for %s is %s" % (s3_object_name, str(vc)))
        log.info("modifying data: %s" % s3_object_name)
        modified_data_info = manage_data.io_generator(
            s3_object_path,
            object_size,
            op="append",
            **{"message": "\nhello for version: %s\n" % str(vc)},
        )
        if modified_data_info is False:
            TestExecError("data modification failed")
        log.info("uploading s3 object: %s" % s3_object_path)
        upload_info = dict(
            {
                "access_key": user_info["access_key"],
                "versioning_status": "enabled",
                "version_count_no": vc,
            },
            **modified_data_info,
        )
        s3_obj = s3lib.resource_op(
            {
                "obj": bucket,
                "resource": "Object",
                "args": [s3_object_name],
                "extra_info": upload_info,
            }
        )
        object_uploaded_status = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "upload_file",
                "args": [modified_data_info["name"]],
                "extra_info": upload_info,
            }
        )
        if object_uploaded_status is False:
            raise TestExecError("Resource execution failed: object upload failed")
        if object_uploaded_status is None:
            log.info("object uploaded")
            s3_obj = rgw_conn.Object(bucket.name, s3_object_name)
            log.info("current_version_id: %s" % s3_obj.version_id)
            basic_io_structure = BasicIOInfoStructure()
            key_version_info = basic_io_structure.version_info(
                **{
                    "version_id": s3_obj.version_id,
                    "md5_local": upload_info["md5"],
                    "count_no": vc,
                    "size": upload_info["size"],
                }
            )
            log.info("key_version_info: %s" % key_version_info)
            write_key_io_info = KeyIoInfo()
            write_key_io_info.add_versioning_info(
                user_info["access_key"], bucket.name, s3_object_path, key_version_info
            )
            created_versions_count += 1
            log.info("created_versions_count: %s" % created_versions_count)
            log.info("adding metadata")
            metadata1 = {"m_data1": "this is the meta1 for this obj"}
            s3_obj.metadata.update(metadata1)
            metadata2 = {"m_data2": "this is the meta2 for this obj"}
            s3_obj.metadata.update(metadata2)
            log.info("metadata for this object: %s" % s3_obj.metadata)
            log.info("metadata count for object: %s" % (len(s3_obj.metadata)))
            if not s3_obj.metadata:
                raise TestExecError("metadata not created even adding metadata")
            versions = bucket.object_versions.filter(Prefix=s3_object_name)
            created_versions_count_from_s3 = len([v.version_id for v in versions])
            log.info(
                "created versions count on s3: %s" % created_versions_count_from_s3
            )
            if created_versions_count is created_versions_count_from_s3:
                log.info("no new versions are created when added metadata")
            else:
                raise TestExecError(
                    "version count mismatch, "
                    "possible creation of version on adding metadata"
                )
        s3_object_download_path = os.path.join(
            TEST_DATA_PATH, s3_object_name + ".download"
        )
        object_downloaded_status = s3lib.resource_op(
            {
                "obj": bucket,
                "resource": "download_file",
                "args": [s3_object_name, s3_object_download_path],
            }
        )
        if object_downloaded_status is False:
            raise TestExecError("Resource execution failed: object download failed")
        if object_downloaded_status is None:
            log.info("object downloaded")
        # checking md5 of the downloaded file
        s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
        log.info("downloaded_md5: %s" % s3_object_downloaded_md5)
        log.info("uploaded_md5: %s" % modified_data_info["md5"])
        log.info("deleting downloaded version file")
        utils.exec_shell_cmd("sudo rm -rf %s" % s3_object_download_path)
    log.info("all versions for the object: %s\n" % s3_object_name)


def download_object(s3_object_name, bucket, TEST_DATA_PATH, s3_object_path, config):
    log.info("s3 object name to download: %s" % s3_object_name)
    s3_object_download_name = s3_object_name + "." + "download"
    s3_object_download_path = os.path.join(TEST_DATA_PATH, s3_object_download_name)
    object_downloaded_status = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "download_file",
            "args": [s3_object_name, s3_object_download_path],
        }
    )
    if object_downloaded_status is False:
        raise TestExecError("Resource execution failed: object download failed")
    if object_downloaded_status is None:
        log.info("object downloaded")

    s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
    s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
    log.info("s3_object_downloaded_md5: %s" % s3_object_downloaded_md5)
    log.info("s3_object_uploaded_md5: %s" % s3_object_uploaded_md5)
    if str(s3_object_uploaded_md5) == str(s3_object_downloaded_md5):
        log.info("md5 match")
        utils.exec_shell_cmd("rm -rf %s" % s3_object_download_path)
    else:
        raise TestExecError("md5 mismatch")
    if config.local_file_delete is True:
        log.info("deleting local file created after the upload")
        utils.exec_shell_cmd("rm -rf %s" % s3_object_path)


def upload_object_with_tagging(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    obj_tag,
    append_data=False,
    append_msg=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
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
    log.info("uploading s3 object with object tagging enabled: %s" % s3_object_path)
    upload_info = dict({"access_key": user_info["access_key"]}, **data_info)

    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )
    with open(s3_object_path, "rb") as fptr:
        object_uploaded_status = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "put",
                "kwargs": dict(Body=fptr, Tagging=obj_tag),
                "extra_info": upload_info,
            }
        )

    if object_uploaded_status is False:
        raise TestExecError("Resource execution failed: object upload failed")
    if object_uploaded_status is None:
        log.info("object uploaded")


def upload_mutipart_object(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    append_data=False,
    append_msg=None,
    abort_multipart=False,
    complete_abort_race=False,
    obj_tag=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    split_size = config.split_size if hasattr(config, "split_size") else 5
    log.info("split size: %s" % split_size)
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
    mp_dir = os.path.join(TEST_DATA_PATH, s3_object_name + ".mp.parts")
    log.info("mp part dir: %s" % mp_dir)
    log.info("making multipart object part dir")
    mkdir = utils.exec_shell_cmd("sudo mkdir %s" % mp_dir)
    if mkdir is False:
        raise TestExecError("mkdir failed creating mp_dir_name")
    utils.split_file(s3_object_path, split_size, mp_dir + "/")
    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
    log.info("parts_list: %s" % parts_list)
    log.info("uploading s3 object: %s" % s3_object_path)
    upload_info = dict(
        {"access_key": user_info["access_key"], "upload_type": "multipart"}, **data_info
    )
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )
    log.info("initiating multipart upload")
    mpu_dict = {
        "obj": s3_obj,
        "resource": "initiate_multipart_upload",
        "args": None,
        "extra_info": upload_info,
    }
    if obj_tag:
        mpu_dict.update({"kwargs": {"Tagging": obj_tag}})

    mpu = s3lib.resource_op(mpu_dict)
    part_number = 1
    parts_info = {"Parts": []}
    if config.test_ops.get("test_get_object_attributes"):
        object_parts_info = {"TotalPartsCount": len(parts_list), "Parts": []}
    log.info("no of parts: %s" % len(parts_list))
    abort_part_no = random.randint(1, len(parts_list) - 1)
    """if randomly selected abort-part-no is less than 1 then we will increment it by 1 to make sure atleast one part is uploaded
    before aborting multipart(to avoid some corner case)"""
    if abort_part_no <= 1:
        abort_part_no = abort_part_no + 1
    log.info(f"abort part no is: {abort_part_no}")
    for each_part in parts_list:
        log.info("trying to upload part: %s" % each_part)
        part = mpu.Part(part_number)
        # part_upload_response = part.upload(Body=open(each_part))
        part_upload_response = s3lib.resource_op(
            {
                "obj": part,
                "resource": "upload",
                "kwargs": dict(Body=open(each_part, mode="rb")),
            }
        )
        if part_upload_response is not False:
            response = HttpResponseParser(part_upload_response)
            if response.status_code == 200:
                log.info("part uploaded")
            else:
                raise TestExecError("part uploading failed")
        part_info = {"PartNumber": part_number, "ETag": part_upload_response["ETag"]}
        parts_info["Parts"].append(part_info)
        if each_part != parts_list[-1]:
            # increase the part number only if the current part is not the last part
            part_number += 1
        log.info("curr part_number: %s" % part_number)

        if abort_multipart and part_number == abort_part_no:
            log.info(f"aborting multi part {part_number}")
            return
        if config.test_ops.get("test_get_object_attributes"):
            part_info_get_obj_attr = part_info.copy()
            part_info_get_obj_attr["Size"] = os.stat(each_part).st_size
            object_parts_info["Parts"].append(part_info_get_obj_attr)

    if config.local_file_delete is True:
        log.info("deleting local file part")
        utils.exec_shell_cmd(f"rm -rf {mp_dir}")
    # log.info('parts_info so far: %s'% parts_info)
    if len(parts_list) == part_number:
        log.info("all parts upload completed")
        if complete_abort_race:
            log.info("triggering complete and abort multipart upload at the same time")
            t1 = Thread(
                target=mpu.complete,
                kwargs={"MultipartUpload": parts_info},
            )
            t2 = Thread(target=mpu.abort, kwargs={})

            t1.start()
            time.sleep(0.01)
            t2.start()

            t1.join()
            t2.join()
        else:
            mpu.complete(MultipartUpload=parts_info)
        log.info("multipart upload complete for key: %s" % s3_object_name)
    if config.test_ops.get("test_get_object_attributes"):
        return object_parts_info


def upload_multipart_with_break(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    break_at_part_no=0,
):
    """
    Upload multipart object with option to break at specific part number
    break_at_part_no=0 means complete the upload
    break_at_part_no>0 means abort at that part number

    Parameters:
        s3_object_name (str): Name of the S3 object
        bucket: S3 bucket resource
        TEST_DATA_PATH (str): Path to test data directory
        config: Config object with obj_size, split_size, local_file_delete
        user_info (dict): User information dictionary
        break_at_part_no (int): Part number at which to abort (0 = complete upload)

    Returns:
        None: Returns None after aborting or completing upload
    """
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    split_size = config.split_size if hasattr(config, "split_size") else 5
    log.info("split size: %s" % split_size)

    # Generate test data
    data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        raise TestExecError("data creation failed")

    # Create multipart parts directory
    mp_dir = os.path.join(TEST_DATA_PATH, s3_object_name + ".mp.parts")
    log.info("mp part dir: %s" % mp_dir)
    log.info("making multipart object part dir")
    mkdir = utils.exec_shell_cmd("sudo mkdir -p %s" % mp_dir)
    if mkdir is False:
        raise TestExecError("mkdir failed creating mp_dir_name")

    # Split file into parts
    utils.split_file(s3_object_path, split_size, mp_dir + "/")
    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
    log.info("parts_list: %s" % parts_list)
    log.info("uploading s3 object: %s" % s3_object_path)

    upload_info = dict(
        {"access_key": user_info["access_key"], "upload_type": "multipart"}, **data_info
    )

    # Create S3 object resource
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )

    log.info("initiating multipart upload")
    mpu_dict = {
        "obj": s3_obj,
        "resource": "initiate_multipart_upload",
        "args": None,
        "extra_info": upload_info,
    }

    mpu = s3lib.resource_op(mpu_dict)
    part_number = 1
    parts_info = {"Parts": []}
    log.info("no of parts: %s" % len(parts_list))

    if break_at_part_no > 0:
        log.info("starting at part no: %s" % break_at_part_no)
        log.info("--------------------------------------------------")

    # Upload parts
    for each_part in parts_list:
        log.info("trying to upload part: %s" % each_part)
        part = mpu.Part(part_number)
        part_upload_response = s3lib.resource_op(
            {
                "obj": part,
                "resource": "upload",
                "kwargs": dict(Body=open(each_part, mode="rb")),
            }
        )
        if part_upload_response is not False:
            response = HttpResponseParser(part_upload_response)
            if response.status_code == 200:
                log.info("part uploaded")
            else:
                raise TestExecError("part uploading failed")

        part_info = {"PartNumber": part_number, "ETag": part_upload_response["ETag"]}
        parts_info["Parts"].append(part_info)

        # Check if we should abort at this part
        if break_at_part_no > 0 and part_number == break_at_part_no:
            log.info(f"aborting multipart upload at part {part_number}")
            # Abort the multipart upload
            abort_response = s3lib.resource_op(
                {
                    "obj": mpu,
                    "resource": "abort",
                    "args": None,
                }
            )
            log.info(f"multipart upload aborted: {abort_response}")
            return

        if each_part != parts_list[-1]:
            # increase the part number only if the current part is not the last part
            part_number += 1
        log.info("curr part_number: %s" % part_number)

    # Complete multipart upload if not aborted
    if len(parts_list) == part_number:
        log.info("all parts upload completed")
        complete_response = mpu.complete(MultipartUpload=parts_info)
        log.info("multipart upload complete for key: %s" % s3_object_name)
        log.info(f"complete response: {complete_response}")

    # Cleanup local parts
    if config.local_file_delete is True:
        log.info("deleting local file part")
        utils.exec_shell_cmd(f"rm -rf {mp_dir}")


def upload_part(
    rgw_client,
    s3_object_name,
    bucket_name,
    mpu,
    part_number,
    body,
    content_length,
    parts_info,
):
    try:
        part_upload_response = rgw_client.upload_part(
            Bucket=bucket_name,
            Key=s3_object_name,
            PartNumber=part_number,
            UploadId=mpu["UploadId"],
            Body=body,
            ContentLength=content_length,
        )
        log.info(f"part uploaded response {part_upload_response}")
    except Exception as e:
        log.info(e)
        return
    part_info = {"PartNumber": part_number, "ETag": part_upload_response["ETag"]}
    parts_info["Parts"].append(part_info)


def test_multipart_upload_failed_parts(
    rgw_client, s3_object_name, bucket_name, part1_path, part2_path
):
    parts_info = {"Parts": []}
    log.info("no of parts: 2")

    log.info("initiating multipart upload")
    mpu = rgw_client.create_multipart_upload(Bucket=bucket_name, Key=s3_object_name)

    part_number = 1
    log.info(f"trying to upload part {part_number}")
    part_upload_response = rgw_client.upload_part(
        Bucket=bucket_name,
        Key=s3_object_name,
        PartNumber=part_number,
        UploadId=mpu["UploadId"],
        Body=open(part1_path, mode="rb"),
    )
    log.info(f"part uploaded response {part_upload_response}")
    part_info = {
        "PartNumber": part_number,
        "ETag": part_upload_response["ETag"],
    }
    parts_info["Parts"].append(part_info)

    part_number = 2
    log.info(
        f"trying to upload part {part_number} with three clients parallely out of which only one is success"
    )
    t1 = Thread(
        target=upload_part,
        args=(
            rgw_client,
            s3_object_name,
            bucket_name,
            mpu,
            part_number,
            open("/tmp/obj20MB", mode="rb"),
            12582912,
            parts_info,
        ),
    )
    t2 = Thread(
        target=upload_part,
        args=(
            rgw_client,
            s3_object_name,
            bucket_name,
            mpu,
            part_number,
            open("/tmp/obj30MB", mode="rb"),
            12582912,
            parts_info,
        ),
    )
    t3 = Thread(
        target=upload_part,
        args=(
            rgw_client,
            s3_object_name,
            bucket_name,
            mpu,
            part_number,
            open(part2_path, mode="rb"),
            os.stat(part2_path).st_size,
            parts_info,
        ),
    )

    t1.start()
    t2.start()
    t3.start()

    t3.join()
    t1.join()
    t2.join()

    if len(parts_info["Parts"]) == part_number:
        log.info("all parts upload completed")
        response = rgw_client.complete_multipart_upload(
            Bucket=bucket_name,
            Key=s3_object_name,
            UploadId=mpu["UploadId"],
            MultipartUpload=parts_info,
        )
        log.info(f"complete multipart upload: {response}")
        log.info(f"multipart upload complete for key: {s3_object_name}")
    else:
        raise Exception("Multipart upload for part2 failed")


def enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info):
    log.info("bucket versioning test on bucket: %s" % bucket.name)
    # bucket_versioning = s3_ops.resource_op(rgw_conn, 'BucketVersioning', bucket.name)
    bucket_versioning = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "BucketVersioning", "args": [bucket.name]}
    )
    # checking the versioning status
    # version_status = s3_ops.resource_op(bucket_versioning, 'status')
    version_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "status", "args": None}
    )
    if version_status is None:
        log.info("bucket versioning still not enabled")
    # enabling bucket versioning
    # version_enable_status = s3_ops.resource_op(bucket_versioning, 'enable')
    version_enable_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "enable", "args": None}
    )
    response = HttpResponseParser(version_enable_status)
    if response.status_code == 200:
        log.info("version enabled")
        write_bucket_io_info.add_versioning_status(
            user_info["access_key"], bucket.name, "enabled"
        )
    else:
        raise TestExecError("version enable failed")


def suspend_versioning(bucket, rgw_conn, user_info, write_bucket_io_info):
    """
    Method to perform suspend versioning operation
    bucket: Name of teh bucket
    rgw_conn: rgw connection
    user_info: user info
    """
    bucket_versioning = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "BucketVersioning", "args": [bucket.name]}
    )
    version_suspended_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "suspend", "args": None}
    )
    suspended_response = HttpResponseParser(version_suspended_status)
    if suspended_response.status_code == 200:
        log.info("version Suspended Successfully")
        write_bucket_io_info.add_versioning_status(
            user_info["access_key"], bucket.name, "suspended"
        )
    else:
        raise TestExecError("Suspending versioning is failed")


def generate_totp(seed):
    cmd = "oathtool -d6 --totp %s" % seed
    totp_token = utils.exec_shell_cmd(cmd)
    return totp_token.rstrip("\n")


def enable_mfa_versioning(
    bucket, rgw_conn, SEED, serial, user_info, write_bucket_io_info
):
    log.info("bucket MFA and versioning test on bucket: %s" % bucket.name)
    bucket_versioning = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "BucketVersioning", "args": [bucket.name]}
    )
    # checking the versioning status
    version_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "status", "args": None}
    )
    if version_status is None:
        log.info("bucket mfa and versioning still not enabled")

    # generate MFA token to authenticate
    token = generate_totp(SEED)
    mfa_token = serial + " " + token

    # put mfa and bucket versioning
    mfa_version_put = s3lib.resource_op(
        {
            "obj": bucket_versioning,
            "resource": "put",
            "kwargs": dict(
                MFA=(mfa_token),
                VersioningConfiguration={"MFADelete": "Enabled", "Status": "Enabled"},
                ExpectedBucketOwner=user_info["user_id"],
            ),
        }
    )
    log.info(f"mfa_version_put: {mfa_version_put}")
    return token, mfa_version_put


def put_get_bucket_lifecycle_test(
    bucket,
    rgw_conn,
    rgw_conn2,
    life_cycle_rule,
    config,
    upload_start_time=None,
    upload_end_time=None,
):
    bucket_life_cycle = s3lib.resource_op(
        {
            "obj": rgw_conn,
            "resource": "BucketLifecycleConfiguration",
            "args": [bucket.name],
        }
    )
    put_bucket_life_cycle = s3lib.resource_op(
        {
            "obj": bucket_life_cycle,
            "resource": "put",
            "kwargs": dict(LifecycleConfiguration=life_cycle_rule),
        }
    )
    log.info("put bucket life cycle:\n%s" % put_bucket_life_cycle)
    if put_bucket_life_cycle is False:
        if config.test_ops.get("lc_same_rule_id_diff_rules"):
            log.info(
                "put bucket lifecycle failed as expected as lc has same rule id but different rules"
            )
            return
        raise TestExecError("Resource execution failed: put bucket lifecycle failed")
    if config.test_ops.get("lc_same_rule_id_diff_rules"):
        raise TestExecError(
            "put bucket lifecycle expected to fail but it succeded in spite of lc having same rule id but different rules."
        )
    if put_bucket_life_cycle is not None:
        response = HttpResponseParser(put_bucket_life_cycle)
        if response.status_code == 200:
            log.info("bucket life cycle added")
        else:
            raise TestExecError("bucket lifecycle addition failed")
    log.info("trying to retrieve bucket lifecycle config")
    get_bucket_life_cycle_config = s3lib.resource_op(
        {
            "obj": rgw_conn2,
            "resource": "get_bucket_lifecycle_configuration",
            "kwargs": dict(Bucket=bucket.name),
        }
    )
    if get_bucket_life_cycle_config is False:
        raise TestExecError("bucket lifecycle config retrieval failed")
    if get_bucket_life_cycle_config is not None:
        response = HttpResponseParser(get_bucket_life_cycle_config)
        if response.status_code == 200:
            log.info("bucket life cycle retrieved")
        else:
            raise TestExecError("bucket lifecycle config retrieval failed")
    else:
        raise TestExecError("bucket life cycle retrieved")
    if config.test_ops.get("reuse_account_bucket", False) is True:
        max_retries = 1500
        sleep_interval = 30
        bucket_stats_output = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket tenant1/{bucket.name}"
        )
        bucket_stats_json = json.loads(bucket_stats_output)
        objects_before_transition = bucket_stats_json["usage"]["rgw.main"][
            "num_objects"
        ]
        lc_transition_start_time = time.time()
        for retry in range(max_retries + 2):
            if retry == 0:
                time.sleep(
                    max_retries
                )  # since value of max_retries is same as rgw_lc_debug_interval

            bucket_stats_output = utils.exec_shell_cmd(
                f"radosgw-admin bucket stats --bucket tenant1/{bucket.name}"
            )
            log.info(f"bucket stats output for {bucket.name}: {bucket_stats_output}")
            bucket_stats_json = json.loads(bucket_stats_output)

            if (
                bucket_stats_json["usage"]["rgw.cloudtiered"]["num_objects"]
                >= objects_before_transition
                and bucket_stats_json["usage"]["rgw.usage"]["num_objects"] == 0
            ):
                log.info(
                    f" all the objects for bucket successfully cloud transitioned to IBM"
                )
                break
            else:
                log.info(
                    f"Cloud transition still in progress after {retry} retry, sleep for {sleep_interval} and retry"
                )
                time.sleep(sleep_interval)
        if retry > max_retries:
            raise AssertionError(
                f"LC transition to cloud for {objects_before_transition} failed"
            )
    else:
        objs_total = (config.test_ops["version_count"]) * (config.objects_count)
        if not upload_start_time:
            upload_start_time = time.time()
        if not upload_end_time:
            upload_end_time = time.time()
        time_diff = math.ceil(upload_end_time - upload_start_time)
        time_limit = upload_start_time + (
            config.rgw_lc_debug_interval * config.test_ops.get("actual_lc_days", 20)
        )
        for rule in config.lifecycle_conf:
            if rule.get("Expiration", {}).get("Date", False):
                # todo: need to get the interval value from yaml file
                log.info("wait for 60 seconds")
                time.sleep(60)
            else:
                while time.time() < time_limit:
                    bucket_stats_op = utils.exec_shell_cmd(
                        "radosgw-admin bucket stats --bucket=%s" % bucket.name
                    )
                    json_doc1 = json.loads(bucket_stats_op)
                    obj_pre_lc = json_doc1["usage"]["rgw.main"]["num_objects"]
                    if obj_pre_lc == objs_total or config.test_lc_transition:
                        time.sleep(config.rgw_lc_debug_interval)
                    else:
                        raise TestExecError("Objects expired before the expected days")
        log.info(
            f"sleeping for {time_diff + 90} seconds so that all objects gets expired/transitioned"
        )
        time.sleep(time_diff + 90)

    if config.test_ops.get("conflict_exp_days"):
        bucket_stats_op = utils.exec_shell_cmd(
            "radosgw-admin bucket stats --bucket=%s" % bucket.name
        )
        json_doc1 = json.loads(bucket_stats_op)
        obj_post_lc = json_doc1["usage"]["rgw.main"]["num_objects"]
        if obj_post_lc == objs_total:
            raise TestExecError(
                "S3 Lifecycle should choose the path that is least expensive. "
                + "But lc expiration is takin more time than least expiration days "
                + "when conflict between expiration days exist"
            )

    log.info("testing if lc is applied via the radosgw-admin cli")
    op = utils.exec_shell_cmd("radosgw-admin lc list")
    json_doc = json.loads(op)
    for i, entry in enumerate(json_doc):
        print(i)
        print(entry["status"])
        if bucket.name in entry["bucket"]:
            if entry["status"] == "COMPLETE" or entry["status"] == "PROCESSING":
                log.info("LC is applied on the bucket")
            else:
                raise TestExecError("LC is not applied")
            break
    else:
        raise TestExecError("bucket not listed in lc list")
    if config.test_ops.get("tenant_name"):
        tenant_name = config.test_ops.get("tenant_name")
        op_lc_get = utils.exec_shell_cmd(
            f"radosgw-admin lc get --bucket {tenant_name}/{bucket.name}"
        )

    else:
        op_lc_get = utils.exec_shell_cmd(f"radosgw-admin lc get --bucket {bucket.name}")
    json_doc = json.loads(op_lc_get)
    rule_map = json_doc["rule_map"][0]["rule"]
    if not rule_map:
        raise TestExecError(
            f"radosgw-admin lc get is not applied on bucket {bucket.name}"
        )


def remove_user(user_info, cluster_name="ceph", tenant=False):
    log.info("Removing user")
    if tenant:
        cmd = "radosgw-admin user rm --purge-keys --purge-data --uid=%s --tenant=%s" % (
            user_info["user_id"],
            tenant,
        )
    else:
        cmd = "radosgw-admin user rm --purge-keys --purge-data --uid=%s" % (
            user_info["user_id"]
        )
    out = utils.exec_shell_cmd(cmd)
    if out is not False:
        write_user_data = AddUserInfo()
        write_user_data.set_user_deleted(user_info["access_key"])
    return out


def rename_user(old_username, new_username, tenant=False):
    """"""
    if tenant:
        cmd = "radosgw-admin user rename --uid=%s --new-uid=%s --tenant=%s" % (
            old_username,
            new_username,
            tenant,
        )
    else:
        cmd = "radosgw-admin user rename --uid=%s --new-uid=%s" % (
            old_username,
            new_username,
        )
    out = utils.exec_shell_cmd(cmd)
    log.info("Renamed user %s to %s" % (old_username, new_username))
    return out


def rename_bucket(old_bucket, new_bucket, userid, tenant=False):
    """"""
    validate = "radosgw-admin bucket list"
    if tenant:
        old_bucket = str(tenant) + "/" + old_bucket
        new_bucket = str(tenant) + "/" + new_bucket
        cmd = (
            f"radosgw-admin bucket link --bucket={old_bucket} "
            f"--bucket-new-name={new_bucket} --uid={userid} --tenant={tenant}"
        )
    else:
        cmd = "radosgw-admin bucket link --bucket=%s --bucket-new-name=%s --uid=%s" % (
            "/" + old_bucket,
            new_bucket,
            userid,
        )
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW Bucket rename error")
    response = utils.exec_shell_cmd(validate)
    if old_bucket in json.loads(response):
        raise TestExecError("RGW Bucket rename validation error")
    log.info("Renamed bucket %s to %s" % (old_bucket, new_bucket))
    return out


def object_unlink(bucket, object):
    """
    radosgw-admin command to unlink object from BI
    """
    log.info("Check for num_shards 0 in the object shard command")
    cmd = f"radosgw-admin bucket object shard --bucket {bucket} --object {object} --num-shards 0"
    try:
        out = utils.exec_shell_cmd(cmd)
    except Exception as e:
        if "ERROR: non-positive value" not in str(e):
            raise TestExecError("RGW Object shard command hitting divide by zero error")
    log.info(f"Unlink object {object} from {bucket}")
    cmd = f"radosgw-admin object unlink --bucket {bucket} --object {object}"
    out1 = utils.exec_shell_cmd(cmd)
    if out1 is False:
        raise TestExecError("RGW Object unlink error")
    log.info("BI list for the object shoud return empty")
    cmd = f"radosgw-admin bi list --bucket {bucket} --object {object}"
    out2 = utils.exec_shell_cmd(cmd)
    if out is False:
        log.info("Object unlinked from the BI as expected")
    return out1


def get_multisite_info():
    cmd = "radosgw-admin period get"
    period_list = utils.exec_shell_cmd(cmd)
    period_list = json.loads(period_list)
    zone_names = ""
    for i in range(len(period_list.get("period_map")["zonegroups"][0]["zones"])):
        zone_name = period_list.get("period_map")["zonegroups"][0]["zones"][i]["name"]
        zone_names = zone_names + zone_name
        if i != len(period_list.get("period_map")["zonegroups"][0]["zones"]) - 1:
            zone_names = zone_names + ","
    op = utils.exec_shell_cmd("radosgw-admin sync status")
    lines = list(op.split("\n"))
    for line in lines:
        if "realm" in line:
            realm_name = line[line.find("(") + 1 : line.find(")")]
    return zone_names, realm_name


def period_update_commit(validate_policy=False, pipe_op=None):
    _, realm_name = get_multisite_info()
    cmd_realm = f"radosgw-admin period update --rgw-realm={realm_name} --commit"
    op = utils.exec_shell_cmd(cmd_realm)
    json_doc = json.loads(op)
    if validate_policy:
        sync_policy = json_doc["period_map"]["zonegroups"][0]["sync_policy"]["groups"]
        if pipe_op == "create" and len(sync_policy) == 0:
            raise TestExecError(
                "Failed to set policy as period update does not contain details of policy"
            )
        else:
            utils.exec_shell_cmd("radosgw-admin sync policy get")


def unlink_bucket(curr_uid, bucket, tenant=False):
    """"""
    if tenant:
        cmd = "radosgw-admin bucket unlink --bucket=%s --uid=%s --tenant=%s" % (
            bucket,
            curr_uid,
            tenant,
        )
    else:
        cmd = "radosgw-admin bucket unlink --bucket=%s --uid=%s" % (bucket, curr_uid)
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW Bucket unlink error")
    return out


def link_chown_to_tenanted(new_uid, bucket, tenant):
    """"""
    cmd = "radosgw-admin bucket link --bucket=%s --uid=%s --tenant=%s" % (
        "/" + bucket,
        new_uid,
        tenant,
    )
    out1 = utils.exec_shell_cmd(cmd)
    if out1 is False:
        raise TestExecError("RGW Bucket link error")
    log.info("output :%s" % out1)
    cmd1 = "radosgw-admin bucket chown --bucket=%s --uid=%s --tenant=%s" % (
        bucket,
        new_uid,
        tenant,
    )
    out2 = utils.exec_shell_cmd(cmd1)
    if out2 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info("output :%s" % out2)
    return


def link_chown_to_nontenanted(new_uid, bucket, tenant):
    """"""
    cmd2 = "radosgw-admin bucket link --bucket=%s --uid=%s" % (
        tenant + "/" + bucket,
        new_uid,
    )
    out3 = utils.exec_shell_cmd(cmd2)
    if out3 is False:
        raise TestExecError("RGW Bucket link error")
    log.info("output :%s" % out3)
    cmd3 = "radosgw-admin bucket chown --bucket=%s --uid=%s" % (bucket, new_uid)
    out4 = utils.exec_shell_cmd(cmd3)
    if out4 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info("output :%s" % out4)
    return


def link_chown_nontenant_to_nontenant(new_uid, bucket):
    """"""
    cmd2 = "radosgw-admin bucket link --bucket=%s --uid=%s" % (bucket, new_uid)
    out3 = utils.exec_shell_cmd(cmd2)
    if out3 is False:
        raise TestExecError("RGW Bucket link error")
    log.info("output :%s" % out3)
    cmd3 = "radosgw-admin bucket chown --bucket=%s --uid=%s" % (bucket, new_uid)
    out4 = utils.exec_shell_cmd(cmd3)
    if out4 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info("output :%s" % out4)
    return


def delete_objects(bucket, gc_verification=True):
    """
    deletes the objects in a given bucket
    :param bucket: S3Bucket object
    """
    log.info("listing all objects in bucket: %s" % bucket.name)
    objects = s3lib.resource_op({"obj": bucket, "resource": "objects", "args": None})
    log.info("objects :%s" % objects)
    all_objects = s3lib.resource_op({"obj": objects, "resource": "all", "args": None})
    log.info("all objects: %s" % all_objects)
    for obj in all_objects:
        log.info("object_name: %s" % obj.key)
        log.info("object_size: %s" % obj.size)
        gc_verify_list = []
        if obj.size < 4194304:
            gc_verify_list.append("No")
            if "No" in gc_verify_list:
                gc_verification = False
    log.info("deleting all objects in bucket")
    objects_deleted = s3lib.resource_op(
        {"obj": objects, "resource": "delete", "args": None}
    )
    log.info("objects_deleted: %s" % objects_deleted)
    if objects_deleted is False:
        raise TestExecError("Resource execution failed: Object deletion failed")
    if objects_deleted is not None:
        response = HttpResponseParser(objects_deleted[0])
        if response.status_code == 200:
            log.info("objects deleted ")
            write_key_info = KeyIoInfo()
            for obj in all_objects:
                log.info(f"writing log for delete object {obj.key}")
                write_key_info.set_key_deleted(obj.bucket_name, obj.key)
            if gc_verification:
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

        else:
            raise TestExecError("objects deletion failed")
    else:
        raise TestExecError("objects deletion failed")


def list_objects(bucket):
    """
    list the objects in a given bucket
    :param bucket: S3Bucket object
    """
    log.info("listing all objects in bucket: %s" % bucket.name)
    objects = s3lib.resource_op({"obj": bucket, "resource": "objects", "args": None})
    log.info("objects :%s" % objects)
    all_objects = s3lib.resource_op({"obj": objects, "resource": "all", "args": None})
    log.info("all objects: %s" % all_objects)
    for obj in all_objects:
        log.info("object_name: %s" % obj.key)


def list_versioned_objects(bucket, s3_object_name, s3_object_path=None, rgw_conn=None):
    """
    list all versions of the objects in a given bucket
    :param bucket: S3Bucket object
    """
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    log.info(f"listing all the versions of objects {s3_object_name}")
    for version in versions:
        log.info(f"key_name: {version.object_key} --> version_id: {version.version_id}")


def delete_version_object(
    bucket,
    s3_object_name,
    s3_object_path,
    rgw_conn,
    user_info,
):
    """
    deletes single object and its versions
    :param bucket: S3bucket object
    :param s3_object_name: s3 object name
    :param s3_object_path: path of the object created in the client
    :param rgw_conn: rgw connection
    :param user_info: user info dict containing access_key, secret_key and user_id
    """
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    log.info("deleting s3_obj keys and its versions")
    s3_obj = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "Object", "args": [bucket.name, s3_object_name]}
    )
    log.info("deleting versions for s3 obj: %s" % s3_object_name)
    for version in versions:
        log.info("trying to delete obj version: %s" % version.version_id)
        del_obj_version = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "delete",
                "kwargs": dict(VersionId=version.version_id),
            }
        )
        log.info("response:\n%s" % del_obj_version)
        if del_obj_version is not None:
            response = HttpResponseParser(del_obj_version)
            if response.status_code == 204:
                log.info("version deleted ")
                write_key_io_info = KeyIoInfo()
                write_key_io_info.delete_version_info(
                    user_info["access_key"],
                    bucket.name,
                    s3_object_path,
                    version.version_id,
                )
            else:
                raise TestExecError("version  deletion failed")
        else:
            raise TestExecError("version deletion failed")
    log.info("available versions for the object")
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    for version in versions:
        log.info(
            "key_name: %s --> version_id: %s" % (version.object_key, version.version_id)
        )


def delete_versioned_object(
    bucket,
    s3_object_name,
    rgw_conn,
    s3_object_path=None,
    user_info=None,
    return_status=False,
):
    """
    deletes single object and its versions
    :param bucket: S3bucket object
    :param s3_object_name: s3 object name
    :param s3_object_path: path of the object created in the client
    :param rgw_conn: rgw connection
    :param user_info: user info dict containing access_key, secret_key and user_id
    """
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    log.info("deleting s3_obj keys and its versions")
    not_deleted = False
    s3_obj = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "Object", "args": [bucket.name, s3_object_name]}
    )
    log.info("deleting versions for s3 obj: %s" % s3_object_name)
    for version in versions:
        log.info("trying to delete obj version: %s" % version.version_id)
        del_obj_version = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "delete",
                "kwargs": dict(VersionId=version.version_id),
            }
        )
        log.info("response:\n%s" % del_obj_version)
        if (del_obj_version is not None) and (del_obj_version != False):
            response = HttpResponseParser(del_obj_version)
            if return_status:
                return response
            if response.status_code == 204:
                log.info("version deleted ")
            else:
                raise TestExecError("version  deletion failed")
        else:
            not_deleted = True
            if return_status:
                return not_deleted
            raise TestExecError("version deletion failed")
    log.info("available versions for the object")
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    for version in versions:
        log.info(
            "key_name: %s --> version_id: %s" % (version.object_key, version.version_id)
        )


def delete_bucket(bucket):
    """
    deletes a given bucket
    :param bucket: s3Bucket object
    """
    for retry_count in range(4):
        log.info("listing objects if any")
        objs = bucket.objects.all()
        count = sum(1 for _ in bucket.objects.all())
        if count > 0:
            log.info(f"objects not deleted, count is:{count}")
            for ob in objs:
                log.info(f"object: {ob.key}")
        else:
            log.info("No objects in bucket")
            break
        time.sleep(10)
    log.info("deleting bucket: %s" % bucket.name)
    bucket_deleted_response = s3lib.resource_op(
        {"obj": bucket, "resource": "delete", "args": None}
    )
    log.info("bucket_deleted_status: %s" % bucket_deleted_response)
    if bucket_deleted_response is not None and isinstance(
        bucket_deleted_response, dict
    ):
        response = HttpResponseParser(bucket_deleted_response)
        log.info(bucket_deleted_response)
        if response.status_code == 204:
            log.info("bucket deleted ")
            write_bucket_info = BucketIoInfo()
            log.info("adding io info of delete bucket")
            write_bucket_info.set_bucket_deleted(bucket.name)
        else:
            raise TestExecError(
                f"bucket deletion failed with status code {response.status_code}"
            )
    else:
        raise TestExecError("bucket deletion failed")


def set_gc_conf(ceph_conf, conf):
    log.info("making changes to ceph.conf")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.bluestore_block_size,
        str(conf.get("bluestore_block_size", 1549267441664)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_max_queue_size,
        str(conf.get("rgw_gc_max_queue_size", 367788)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_processor_max_time,
        str(conf.get("rgw_gc_processor_max_time", 3600)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_max_concurrent_io,
        str(conf.get("rgw_gc_max_concurrent_io", 10)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_objexp_gc_interval,
        str(conf.get("rgw_objexp_gc_interval", 10)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_max_trim_chunk,
        str(conf.get("rgw_gc_max_trim_chunk", 32)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_obj_min_wait,
        str(conf.get("rgw_gc_obj_min_wait", 10)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_processor_period,
        str(conf.get("rgw_gc_processor_period", 10)),
    )
    log.info("trying to restart services")
    srv_restarted = rgw_service.restart()
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")
    # Delete gc queue
    pool_name = utils.exec_shell_cmd("ceph df |awk '{ print $1 }'| grep rgw.log")
    pool_name = pool_name.replace("\n", "")
    for i in range(0, 32):
        utils.exec_shell_cmd("rados rm gc.%d -p %s -N gc" % (i, pool_name))


def restart_and_wait_until_daemons_up(ssh_con):
    log.info("trying to restart services")
    srv_restarted = rgw_service.restart(ssh_con)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")
    rgw_serv = json.loads(
        utils.exec_shell_cmd("ceph orch ls --service_type=rgw --format json-pretty")
    )

    if int(rgw_serv[0]["status"]["running"]) != (rgw_serv[0]["status"]["size"]):
        for retry_count in range(12):
            time.sleep(5)
            re_rgw_serv = json.loads(
                utils.exec_shell_cmd("ceph orch ls --service_type=rgw --format json")
            )
            if re_rgw_serv[0]["status"]["running"] != re_rgw_serv[0]["status"]["size"]:
                log.info("wait for 5 sec until all daemon are up and running")
            else:
                log.info("RGW daemons are up and running")
                break
    else:
        log.info("RGW daemons are up and running")


def verify_gc():
    op = utils.exec_shell_cmd("radosgw-admin gc list")
    # op variable will capture command output such as entire gc list or error like ERROR: failed to list objs: (22) Invalid argument
    final_op = op.find("ERROR") or op.find("Invalid argument")
    return final_op


def check_for_crash():
    """
    check for crash on cluster
    """
    ceph_version_id, ceph_version_name = utils.get_ceph_version()
    if ceph_version_name != "luminous":
        log.info("check for any new crashes on the ceph cluster ")
        ceph_crash = utils.exec_shell_cmd("ceph crash ls-new")
        if ceph_crash:
            ceph_crash_all = ceph_crash.split()
            no_of_crashes = len(ceph_crash_all)
            for i in range(3, no_of_crashes):
                if i % 3 == 0:
                    ceph_crash_id, ceph_crash_entity = (
                        ceph_crash_all[i],
                        ceph_crash_all[i + 1],
                    )
                    log.info(f"ceph daemon {ceph_crash_entity} crashed!")
                    crash_info = utils.exec_shell_cmd(
                        "ceph crash info %s" % ceph_crash_id
                    )
            log.info(
                "archiving the crashes to silence health warnings! to view the crashes use the command: ceph crash ls"
            )
            utils.exec_shell_cmd("ceph crash archive-all")
        else:
            log.info("No ceph daemon crash found")
        return ceph_crash


def time_taken_to_execute_command(cmd):
    """
    Time taken to list via radosgw-admin command.
    :param cmd: cmd
    """
    output = json.loads(utils.exec_shell_cmd(cmd))
    for op in output:
        op.update({"exists": str(op["exists"])})
        op["meta"].update({"appendable": str(op["meta"]["appendable"])})
    return str(output)


def time_to_list_via_radosgw(bucket_name, listing):
    """
    Time taken to list via radosgw-admin command.
    :param bucket: s3Bucket object
    :param listing: ordered or unordered listing
    """
    if listing == "ordered":
        log.info("listing via radosgw-admin bucket list --max-entries=.. --bucket <>")
        cmd = "radosgw-admin bucket list --max-entries=100000 --bucket=%s " % (
            bucket_name
        )
        listing_start_time = time.time()
        utils.exec_shell_cmd(cmd)
        listing_end_time = time.time()
        return listing_end_time - listing_start_time

    if listing == "unordered":
        log.info(
            "listing via radosgw-admin bucket list --max-entries=.. --bucket <> --allow-unordered"
        )
        cmd = (
            "radosgw-admin bucket list --max-entries=100000 --bucket=%s --allow-unordered"
            % (bucket_name)
        )
        listing_start_time = time.time()
        utils.exec_shell_cmd(cmd)
        listing_end_time = time.time()
        return listing_end_time - listing_start_time


def time_to_list_via_boto(bucket_name, rgw):
    """
    Time taken to list via boto
    :param bucket: s3Bucket object
    """
    bucket = s3lib.resource_op(
        {"obj": rgw, "resource": "Bucket", "args": [bucket_name]}
    )

    log.info("listing all objects in bucket: %s" % bucket)
    objects = s3lib.resource_op({"obj": bucket, "resource": "objects", "args": None})
    time_taken = timeit.timeit(lambda: bucket.objects.all(), globals=globals())
    return time_taken


def check_sync_status(retry=25, delay=60, return_while_sync_inprogress=False):
    """
    Check sync status if its a multisite cluster
    """
    is_multisite = utils.is_cluster_multisite()
    if is_multisite:
        if return_while_sync_inprogress:
            out = sync_status(
                retry, delay, return_while_sync_inprogress=return_while_sync_inprogress
            )
            return out
        sync_status(
            retry, delay, return_while_sync_inprogress=return_while_sync_inprogress
        )


def check_bucket_sync_status(bkt=None):
    bucket_sync_status = utils.exec_shell_cmd(
        f"radosgw-admin bucket sync status --bucket {bkt}"
    )
    return bucket_sync_status


def get_default_datalog_type():
    """
    get the default datalog type i.e. omap or fifo
    """
    cmd = "ceph config get mon.* rgw_default_data_log_backing"
    default_datalog_type = utils.exec_shell_cmd(cmd)
    if default_datalog_type is False:
        raise DefaultDatalogBackingError(
            "Error in getting the default datalog backing type"
        )
    return default_datalog_type


def check_datalog_list():
    """
    check datalog list
    """
    cmd = "radosgw-admin datalog list"
    datalog_list = utils.exec_shell_cmd(cmd)
    if "ERROR" in datalog_list or "failed" in datalog_list:
        return True
    else:
        return False


def get_datalog_marker():
    """
    check the datalog marker
    """
    # changing the value of rgw_data_log_num_shards is not supported. Ref: https://bugzilla.redhat.com/show_bug.cgi?id=1938105#c7
    log.info("get the value of rgw_data_log_num_shards")
    cmd = "ceph config get mon.* rgw_data_log_num_shards"
    datalog_num_shards = utils.exec_shell_cmd(cmd)
    log.info(f"datalog_num_shards: {datalog_num_shards}")

    # check for marker in datalog status
    cmd = "radosgw-admin datalog status"
    datalog_status_cmd = utils.exec_shell_cmd(cmd)
    datalog_status = json.loads(datalog_status_cmd)

    # fetch the first occurance of marker
    get_datalog_marker = ""
    shard_id = -1
    datalog_num_shards = int(datalog_num_shards) - 1
    for i in range(datalog_num_shards):
        if datalog_status[i]["marker"] == "":
            continue
        else:
            get_datalog_marker = datalog_status[i]["marker"]
            shard_id = i
            break

    # return shard_id and datalog_mark, Ref BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1981860
    return shard_id, get_datalog_marker


def check_datalog_marker():
    """
    check the datalog marker
    """
    _, marker = get_datalog_marker()
    if "1_" in marker:
        return "omap"
    if ":" in marker:
        return "fifo"
    raise TestExecError(f"No known identifiers found in datalog marker \n {marker}")


def put_bucket_lifecycle(
    bucket, rgw_conn, rgw_conn2, life_cycle_rule, put_lc=True, get_lc=True
):
    """
    Set/Put lifecycle to provided bucket
    """
    if put_lc:
        bucket_life_cycle = s3lib.resource_op(
            {
                "obj": rgw_conn,
                "resource": "BucketLifecycleConfiguration",
                "args": [bucket.name],
            }
        )
        put_bucket_life_cycle = s3lib.resource_op(
            {
                "obj": bucket_life_cycle,
                "resource": "put",
                "kwargs": dict(LifecycleConfiguration=life_cycle_rule),
            }
        )
        log.info(f"put bucket life cycle:\n{put_bucket_life_cycle}")
        if not put_bucket_life_cycle:
            raise TestExecError(
                "Resource execution failed: put bucket lifecycle failed"
            )
        if put_bucket_life_cycle:
            response = HttpResponseParser(put_bucket_life_cycle)
            if response.status_code == 200:
                log.info("bucket life cycle added")
            else:
                raise TestExecError("bucket lifecycle addition failed")
    if get_lc:
        log.info("trying to retrieve bucket lifecycle config")
        get_bucket_life_cycle_config = s3lib.resource_op(
            {
                "obj": rgw_conn2,
                "resource": "get_bucket_lifecycle_configuration",
                "kwargs": dict(Bucket=bucket.name),
            }
        )
        if not get_bucket_life_cycle_config:
            raise TestExecError("bucket lifecycle config retrieval failed")
        if get_bucket_life_cycle_config:
            response = HttpResponseParser(get_bucket_life_cycle_config)
            if response.status_code == 200:
                log.info("bucket life cycle retrieved")
            else:
                raise TestExecError("bucket lifecycle config retrieval failed")
        else:
            raise TestExecError("bucket life cycle retrieved")
    lc_data = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
    log.info(f"lc data is {lc_data}")


def get_radoslist():
    """
    get radoslist of all buckets
    """
    cmd = "radosgw-admin bucket radoslist | grep -i ERROR"
    _, err = subprocess.getstatusoutput(cmd)
    if err:
        log.error(f"ERROR in radoslist command! {err}")
        get_bucket_stats()
    else:
        return True


def get_bucket_stats():
    """
    get bucket stats of all buckets
    """
    log.info("check bucket stats of all the buckets in the cluster")
    cmd = "radosgw-admin bucket stats| egrep -i 'error|ret=-'"
    _, err = subprocess.getstatusoutput(cmd)
    if err:
        raise TestExecError(f"bucket stats on all buckets failed! {err}")
    else:
        return True


def get_s3_client(access_key, secret_key, endpoint):
    """
    Returns s3 client
    """
    s3_conn_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url=endpoint,
    )
    return s3_conn_client


def is_bucket_exists(bucket_name, s3_conn_client):
    """
    Returns true if bucket exists in endpoint
    """
    bucket_resp = s3_conn_client.list_buckets()
    log.info(bucket_resp["Buckets"])
    bucket_list = [di["Name"] for di in bucket_resp["Buckets"]]
    return bucket_name in bucket_list


def get_object_list(bucket_name, s3_conn_client, prefix=None):
    """
    Returns object list for the given bucket
    """
    object_resp = s3_conn_client.list_objects(Bucket=bucket_name)
    log.info(object_resp)
    if "Contents" not in object_resp.keys():
        log.info("Objects do not exist in the bucket")
        return []
    object_list = [di["Key"] for di in object_resp["Contents"]]
    if prefix is not None:
        object_list_with_prefix = []
        for obj in object_list:
            if obj.startswith(prefix):
                object_list_with_prefix.append(obj)
        return object_list_with_prefix
    return object_list


def get_object_list_etag(bucket_name, s3_conn_client):
    """
    Returns object Key,Etag for the given bucket
    """
    object_resp = s3_conn_client.list_objects(Bucket=bucket_name)
    if "Contents" not in object_resp.keys():
        log.info("Objects do not exist in the bucket")
        return []
    object_dict = {}
    for di in object_resp["Contents"]:
        object_dict.update({di["Key"]: di["ETag"]})
    log.info(object_dict)
    return object_dict


def add_zonegroup_placement(
    storage_class=None,
    tier_type=None,
    rgw_zonegroup="default",
    placement_id="default-placement",
):
    """
    Adds zonegroup placement
    """
    command = (
        f"radosgw-admin zonegroup placement add --rgw-zonegroup={rgw_zonegroup}"
        f"--placement-id={placement_id} "
    )
    if storage_class:
        command += f"--storage-class={storage_class} "
    if tier_type:
        command += f"--tier-type={tier_type}"
    log.info("Executing command: %s" % command)
    utils.exec_shell_cmd(command)


def modify_zonegroup_placement(
    rgw_zonegroup="default",
    placement_id="default-placement",
    storage_class=None,
    tier_type=None,
    tier_config=None,
):
    """
    Modifies zonegroup placement
    """
    command = (
        f"radosgw-admin zonegroup placement modify --rgw-zonegroup={rgw_zonegroup}"
        f"--placement-id={placement_id} "
    )
    if storage_class:
        command += f"--storage-class={storage_class} "
    if tier_type:
        command += f"--tier-type={tier_type}"
    if tier_config:
        command += f"--tier-type={tier_config}"
    log.info("Executing command: %s" % command)
    utils.exec_shell_cmd(command)


def get_zg_endpoint_creds():
    """
    Returns zonegroup endpoint credentials
    """
    endpoint_details = {}
    command = "radosgw-admin zonegroup get"
    zg_details = json.loads(utils.exec_shell_cmd(command))
    s3_details = zg_details["placement_targets"][0]["tier_targets"][0]["val"]["s3"]
    log.info(s3_details)
    log.info(type(s3_details))
    endpoint_details["access_key"] = s3_details["access_key"]
    endpoint_details["secret_key"] = s3_details["secret"]
    endpoint_details["endpoint"] = s3_details["endpoint"]
    endpoint_details["bucket_name"] = s3_details["target_path"]
    return endpoint_details


def get_object_upload_type(s3_object_name, bucket, TEST_DATA_PATH, config, user_info):
    """
    choose or select type of object upload normal or multipart for an object.
    """
    log.info("get the object upload type: multipart or normal")
    if config.test_ops.get("upload_type") == "multipart":
        log.info("upload type: multipart")
        upload_mutipart_object(
            s3_object_name,
            bucket,
            TEST_DATA_PATH,
            config,
            user_info,
        )
    else:
        log.info("upload type: normal")
        upload_object(
            s3_object_name,
            bucket,
            TEST_DATA_PATH,
            config,
            user_info,
        )


def prepare_for_bucket_lc_transition(config):
    """
    This function is to set the prereqs for LC transiton testing

    Parameters:
        config(list): config
    """
    pool_name = config.pool_name
    storage_class = config.storage_class
    ec_pool_name = config.ec_pool_name
    ec_storage_class = config.ec_storage_class
    is_multisite = utils.is_cluster_multisite()
    is_primary = utils.is_cluster_primary()
    if is_multisite:
        zonegroup = "shared"
        if is_primary:
            zone = "primary"
        else:
            zone = "secondary"
    else:
        zone = zonegroup = "default"
    if config.test_ops.get("test_pool_transition", True):
        if config.ec_pool_transition:
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class {ec_storage_class}"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin zone placement add --rgw-zone {zone} --placement-id default-placement --storage-class {ec_storage_class} --data-pool {ec_pool_name}"
            )
            utils.exec_shell_cmd(
                "ceph osd erasure-code-profile set rgwec01 k=4 m=2 crush-failure-domain=osd crush-device-class=hdd"
            )
            utils.exec_shell_cmd(
                f"ceph osd pool create {ec_pool_name} 32 32 erasure rgwec01"
            )
            utils.exec_shell_cmd(f"ceph osd pool application enable {ec_pool_name} rgw")
        else:
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class {storage_class}"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin zone placement add --rgw-zone {zone} --placement-id default-placement --storage-class {storage_class} --data-pool {pool_name}"
            )
            utils.exec_shell_cmd(f"ceph osd pool create {pool_name}")
            utils.exec_shell_cmd(f"ceph osd pool application enable {pool_name} rgw")
            if config.multiple_transitions:
                second_pool_name = config.second_pool_name
                second_storage_class = config.second_storage_class
                utils.exec_shell_cmd(f"ceph osd pool create {second_pool_name}")
                utils.exec_shell_cmd(
                    f"ceph osd pool application enable {second_pool_name} rgw"
                )
                utils.exec_shell_cmd(
                    f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class {second_storage_class}"
                )
                utils.exec_shell_cmd(
                    f"radosgw-admin zone placement add --rgw-zone {zone} --placement-id default-placement --storage-class {second_storage_class} --data-pool {second_pool_name}"
                )
    else:
        if config.test_ops.get("test_ibm_cloud_transition", False):
            wget_cmd = "curl -o ibm_cloud.env http://magna002.ceph.redhat.com/cephci-jenkins/ibm_cloud_file"
            utils.exec_shell_cmd(cmd=f"{wget_cmd}")
            ibm_config = configobj.ConfigObj("ibm_cloud.env")
            target_path = ibm_config["TARGET"]
            access = ibm_config["ACCESS"]
            secret = ibm_config["SECRET"]
            endpoint = ibm_config["ENDPOINT"]
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class CLOUDIBM --tier-type=cloud-s3"
            )
            if config.test_ops.get("test_retain_head", False):
                utils.exec_shell_cmd(
                    f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class CLOUDIBM --tier-type=cloud-s3 --tier-config=endpoint={endpoint},access_key={access},secret={secret},target_path={target_path},multipart_sync_threshold=44432,multipart_min_part_size=44432,retain_head_object=true,region=au-syd"
                )
            else:
                utils.exec_shell_cmd(
                    f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class CLOUDIBM --tier-type=cloud-s3 --tier-config=endpoint={endpoint},access_key={access},secret={secret},target_path={target_path},multipart_sync_threshold=44432,multipart_min_part_size=44432,retain_head_object=false,region=au-syd"
                )
        else:
            wget_cmd = "curl -o aws_cloud.env http://magna002.ceph.redhat.com/cephci-jenkins/aws_cloud_file"
            utils.exec_shell_cmd(cmd=f"{wget_cmd}")
            aws_config = configobj.ConfigObj("aws_cloud.env")
            target_path = aws_config["TARGET"]
            access = aws_config["ACCESS"]
            secret = aws_config["SECRET"]
            endpoint = aws_config["ENDPOINT"]
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class=CLOUDAWS --tier-type=cloud-s3"
            )
            if config.test_ops.get("test_retain_head", False):
                utils.exec_shell_cmd(
                    f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup}   --placement-id default-placement --storage-class CLOUDAWS --tier-type=cloud-s3 --tier-config=endpoint={endpoint},access_key={access},secret={secret},target_path={target_path},multipart_sync_threshold=44432,multipart_min_part_size=44432,retain_head_object=true,region=us-east-1"
                )
            else:
                utils.exec_shell_cmd(
                    f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup}   --placement-id default-placement --storage-class CLOUDAWS --tier-type=cloud-s3 --tier-config=endpoint={endpoint},access_key={access},secret={secret},target_path={target_path},multipart_sync_threshold=44432,multipart_min_part_size=44432,retain_head_object=false,region=us-east-1"
                )
    if is_multisite:
        utils.exec_shell_cmd("radosgw-admin period update --commit")
        time.sleep(70)
        if config.test_ops.get("test_ibm_cloud_transition", False):
            # CEPH-83581977, test cloud transition of encrypted and compressed objects
            utils.exec_shell_cmd(
                "radosgw-admin zone placement modify --rgw-zone primary --placement-id default-placement  --compression zlib"
            )
            utils.exec_shell_cmd(
                "ceph config set client.rgw.shared.pri rgw_crypt_default_encryption_key 4YSmvJtBv0aZ7geVgAsdpRnLBEwWSWlMIGnRS8a9TSA="
            )
            utils.exec_shell_cmd("ceph orch restart rgw.shared.pri")
            remote_site_ssh_con = get_remote_conn_in_multisite()
            remote_site_ssh_con.exec_command(
                "radosgw-admin zone placement modify --rgw-zone primary --placement-id default-placement  --compression zlib"
            )
            remote_site_ssh_con.exec_command(
                "ceph config set client.rgw.shared.sec rgw_crypt_default_encryption_key 4YSmvJtBv0aZ7geVgAsdpRnLBEwWSWlMIGnRS8a9TSA="
            )
            remote_site_ssh_con.exec_command("ceph orch restart rgw.shared.sec")


def bucket_reshard_manual(bucket, config):
    cmd = utils.exec_shell_cmd(
        f"radosgw-admin bucket reshard --bucket {bucket.name} --num-shards {config.shards}"
    )
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    shards = json_doc["num_shards"]
    if shards == config.shards:
        log.info(f"num_shards for bucket {bucket.name} after reshard are {shards}")
    else:
        raise TestExecError(f"Bucket {bucket.name} not resharded to {config.shards}")
    verify_attrs_after_resharding(bucket)


def test_log_trimming(bucket, config):
    log.info("Choose the type of log trimming to test.")
    if config.log_trimming == "mdlog":
        period_op = json.loads(utils.exec_shell_cmd(f"radosgw-admin period get"))
        period_id = period_op["id"]
        cmd = f"radosgw-admin mdlog list --period {period_id}"
    elif config.log_trimming == "datalog":
        for i in range(0, 128):
            shard_id = i
            cmd = f"radosgw-admin datalog list --shard-id {shard_id}"
            output1 = json.loads(utils.exec_shell_cmd(cmd))
            if len(output1) > 0:
                break
    else:
        cmd = f"radosgw-admin bilog list --bucket {bucket.name}"

    output1 = json.loads(utils.exec_shell_cmd(cmd))
    if len(output1) > 0:
        log.info(f"{config.log_trimming} log is not empty")
    else:
        raise TestExecError(f"{config.log_trimming} log is empty")
    if config.remote_zone == "archive":
        zone_name = config.remote_zone
        log.info(f"test no bilogs are generated in {zone_name}, bug-2169298")
        remote_ip = utils.get_rgw_ip_zone(zone_name)
        remote_site_ssh_con = utils.connect_remote(remote_ip)
        log.info(f"perform bilog list on the {zone_name} bucket")
        stdin, stdout, stderr = remote_site_ssh_con.exec_command(cmd)
        cmd_output = stdout.read().decode()
        bilog_list = json.loads(cmd_output)
        log.info(f"The bilog_list for archive zone is : {bilog_list}")
        if not bilog_list:
            log.info(f"{config.log_trimming} is empty, test pass.")
        else:
            raise TestExecError(
                f"{config.log_trimming} log is not empty, test failure."
            )
    else:
        log.info("Sleep for log_trim_interval of 20mins")
        time.sleep(1260)
        output2 = json.loads(utils.exec_shell_cmd(cmd))
        if len(output2) == 0:
            log.info(f"{config.log_trimming} log is empty after the interval")
        else:
            if config.log_trimming == "mdlog":
                retry = 25
                delay = 60
                for retry_count in range(retry):
                    time.sleep(delay)
                    output2 = json.loads(utils.exec_shell_cmd(cmd))
                    if len(output2) == 0:
                        log.info(f"{config.log_trimming} log is empty")
                        break
                time.sleep(delay)
                output2 = json.loads(utils.exec_shell_cmd(cmd))
                if retry_count > retry and len(output2) != 0:
                    raise TestExecError(
                        f"{config.log_trimming} log is not empty even after waiting extra 25min interval"
                    )
            else:
                raise TestExecError(
                    f"{config.log_trimming} log is not empty after the interval"
                )
        if config.test_bilog_trim_on_non_existent_bucket:
            utils.exec_shell_cmd(
                f"radosgw-admin bucket rm --purge-objects --bucket {bucket.name}"
            )
            cmd = "radosgw-admin bilog trim --bucket {bucket.name} | egrep -i 'error|ret=-'"
            _, err = subprocess.getstatusoutput(cmd)
            if not err:
                raise TestExecError(
                    f"Test failure, bilog trim should fail for a non-existent bucket with no such file or directory"
                )
            else:
                log.info(f"Bilog trim for a non-existent bucket fails with {err}")


def set_dynamic_reshard_ceph_conf(config, ssh_con):
    ceph_conf = CephConfOp(ssh_con)
    log.info("sharding type is dynamic. setting ceph conf parameters")
    time.sleep(15)
    log.info("making changes to ceph.conf")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_max_objs_per_shard,
        str(config.max_objects_per_shard),
        ssh_con,
    )

    ceph_conf.set_to_ceph_conf(
        "global", ConfigOpts.rgw_dynamic_resharding, "True", ssh_con
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_max_dynamic_shards,
        str(config.max_rgw_dynamic_shards),
        ssh_con,
    )

    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_reshard_thread_interval,
        str(config.rgw_reshard_thread_interval),
        ssh_con,
    )


def bucket_reshard_dynamic(bucket, config):
    # for dynamic,
    # the number of shards  should be greater than   [ (no of objects)/(max objects per shard) ]
    # example: objects = 500 ; max object per shard = 10
    # then no of shards should be at least 50 or more
    resharding_sleep_time = config.rgw_reshard_thread_interval
    log.info(
        "verification of dynamic resharding starts after waiting for reshard_thread_interval:"
        + f"{resharding_sleep_time} seconds"
    )
    time.sleep(resharding_sleep_time)
    bucket_name = f"{bucket.name}"
    if config.test_ops.get("tenant_name"):
        tenant_name = config.test_ops.get("tenant_name")
        bucket_name = f"{tenant_name}/{bucket.name}"
    num_shards_expected = config.objects_count / config.max_objects_per_shard
    log.info("num_shards_expected: %s" % num_shards_expected)
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket %s" % bucket_name)
    json_doc = json.loads(op)
    bucket_id = json_doc["id"]
    num_shards_created = json_doc["num_shards"]
    log.info("no_of_shards_created: %s" % num_shards_created)
    log.info("Verify if resharding list is empty")
    reshard_list_op = json.loads(utils.exec_shell_cmd("radosgw-admin reshard list"))
    if not reshard_list_op:
        log.info(
            "for dynamic number of shards created should be greater than or equal to number of expected shards"
        )
        log.info("no_of_shards_expected: %s" % num_shards_expected)
        if int(num_shards_created) >= int(num_shards_expected):
            log.info("Expected number of shards created")
        else:
            raise TestExecError("Expected number of shards not created")
    else:
        raise TestExecError("reshard list is still not empty")
    verify_attrs_after_resharding(bucket)


def verify_attrs_after_resharding(bucket):
    log.info("Test ACLs are preserved after a resharding operation.")

    # Determine if the bucket has a tenant
    if "tenant" in bucket.name:
        tenant_name, bucket_short_name = bucket.name.split(".", 1)
        bucket_stats_name = f"{tenant_name}/{bucket.name}"
    else:
        bucket_stats_name = bucket.name

    log.info(f"Fetching stats for bucket: {bucket_stats_name}")

    # Get bucket stats
    op = utils.exec_shell_cmd(
        f"radosgw-admin bucket stats --bucket={bucket_stats_name}"
    )
    json_doc = json.loads(op)
    bucket_id = json_doc["id"]

    # Fetch metadata for the bucket instance
    cmd = utils.exec_shell_cmd(
        f"radosgw-admin metadata get bucket.instance:{bucket_stats_name}:{bucket_id}"
    )
    json_doc = json.loads(cmd)

    log.info("The attrs field should not be empty.")
    attrs = json_doc["data"].get("attrs", [])

    if not attrs or not attrs[0].get("key"):
        raise TestExecError("ACLs lost after bucket resharding, test failure.")

    return True


def group_operation(group_id, group_op, group_status="enabled", bucket_name=None):
    if bucket_name is not None:
        bkt = f" --bucket={bucket_name}"
    else:
        bkt = ""
    cmd = (
        f"radosgw-admin sync group {group_op} --group-id={group_id} --status={group_status}"
        + bkt
    )
    utils.exec_shell_cmd(cmd)


def get_sync_policy(bucket_name=None):
    if bucket_name is not None:
        bkt = f" --bucket={bucket_name}"
    else:
        bkt = ""
    sync_policy_resp = json.loads(
        utils.exec_shell_cmd(f"radosgw-admin sync policy get" + bkt)
    )
    return sync_policy_resp


def verify_bucket_sync_on_other_site(rgw_ssh_con, bucket):
    log.info(f"verify Bucket {bucket.name} exist on another site")
    _, stdout, _ = rgw_ssh_con.exec_command("radosgw-admin bucket list")
    cmd_output = json.loads(stdout.read().decode())
    log.info(f"bucket list response on another site is: {cmd_output}")
    if bucket.name not in cmd_output:
        log.info(f"bucket {bucket.name} did not sync another site, sleep 60s and retry")
        for retry_count in range(20):
            time.sleep(60)
            _, re_stdout, _ = rgw_ssh_con.exec_command("radosgw-admin bucket list")
            re_cmd_output = json.loads(re_stdout.read().decode())
            if bucket.name not in re_cmd_output:
                log.info(
                    f"bucket {bucket.name} not synced to other site after 60s: {re_cmd_output}, retry {retry_count}"
                )
            else:
                log.info(f"bucket {bucket.name} found on other site")
                break
        if (retry_count > 20) and (bucket.name not in re_cmd_output):
            raise TestExecError(
                f"bucket {bucket.name} did not sync to other site even after 20m"
            )


def verify_bucket_sync_policy_on_other_site(rgw_ssh_con, bucket):
    log.info(f"Verify bucket sync policy exist on other site for bucket {bucket.name}")
    _, stdout, stderr = rgw_ssh_con.exec_command(
        f"radosgw-admin sync policy get --bucket {bucket.name}"
    )
    sync_policy_error = stderr.read().decode()
    sync_policy_error_list = sync_policy_error.split("\n")
    if sync_policy_error_list[0] != "":
        raise TestExecError(
            f"Get sync policy on bucket {bucket.name} another site failled :{sync_policy_error_list}"
        )
    cmd_output = json.loads(stdout.read().decode())
    log.info(f"sync policy get from other site: {cmd_output} for bucket {bucket.name}")
    if len(cmd_output["groups"]) == 0:
        log.info(
            f"bucket sync policy for {bucket.name} not synced to another site, sleep 60s and retry"
        )
        for retry_count in range(20):
            time.sleep(60)
            _, re_stdout, _ = rgw_ssh_con.exec_command(
                f"radosgw-admin sync policy get --bucket {bucket.name}"
            )
            re_cmd_output = json.loads(re_stdout.read().decode())
            log.info(
                f"sync policy get from other site after 60s: {re_cmd_output} for bucket {bucket.name}"
            )
            if len(re_cmd_output["groups"]) == 0:
                log.info(
                    f"bucket sync policy for {bucket.name} not synced to another site, so retry {retry_count}"
                )
            else:
                log.info(f"bucket sync policy synced to another site for {bucket.name}")
                break

        if (retry_count > 20) and (len(re_cmd_output["groups"]) == 0):
            raise TestExecError(
                f"bucket sync policy for {bucket.name} not synced to another site even after 20m"
            )


def verify_object_sync_on_other_site(rgw_ssh_con, bucket, config, bucket_object=None):
    log.info(f"Verify object sync on same site for bucket {bucket.name}")
    bucket_stats = json.loads(
        utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket.name}")
    )

    if bucket_object is None:
        bkt_objects = bucket_stats["usage"]["rgw.main"]["num_objects"]
        if bkt_objects != config.objects_count:
            raise TestExecError(
                f"Did not find {config.objects_count} in bucket {bucket.name}, but found {bkt_objects}"
            )
    else:
        if (
            "rgw.main" in bucket_stats["usage"].keys()
            and bucket_stats["usage"]["rgw.main"]["num_objects"] == bucket_object
        ):
            raise TestExecError(f"object synced to bucket {bucket.name}")
        else:
            log.info(
                f"object did not sync to bucket {bucket.name} on same site as expected"
            )
        bkt_objects = bucket_object

    log.info(f"Verify object sync on other site for bucket {bucket.name}")
    _, stdout, _ = rgw_ssh_con.exec_command(
        f"radosgw-admin bucket stats --bucket {bucket.name}"
    )
    cmd_output = json.loads(stdout.read().decode())
    if "rgw.main" not in cmd_output["usage"].keys():
        for retry_count in range(25):
            time.sleep(60)
            _, re_stdout, _ = rgw_ssh_con.exec_command(
                f"radosgw-admin bucket stats --bucket {bucket.name}"
            )
            re_cmd_output = json.loads(re_stdout.read().decode())
            log.info(
                f"check bucket stats on other site after 60s: {re_cmd_output} for bucket {bucket.name}"
            )
            if "rgw.main" not in re_cmd_output["usage"].keys():
                log.info(
                    f"bucket stats not synced: for bucket {bucket.name}, so retry {retry_count}"
                )
            else:
                log.info(f"bucket stats synced for bucket {bucket.name}")
                break

        if (retry_count > 25) and ("rgw.main" not in re_cmd_output["usage"].keys()):
            raise TestExecError(
                f"object not synced on bucket {bucket.name} in another site even after 25m"
            )
        cmd_output = re_cmd_output

    site_bkt_objects = cmd_output["usage"]["rgw.main"]["num_objects"]
    if bkt_objects != site_bkt_objects:
        log.info(
            f"object count mismatch found for bucket {bucket.name} : {site_bkt_objects} expected {bkt_objects}"
        )
        log.info("Check after 180s")
        time.sleep(180)
        _, output, _ = rgw_ssh_con.exec_command(
            f"radosgw-admin bucket stats --bucket {bucket.name}"
        )
        command_output = json.loads(output.read().decode())
        bucket_objects = command_output["usage"]["rgw.main"]["num_objects"]
        if bkt_objects != bucket_objects:
            raise TestExecError(
                f"object count mismatch found in another site for bucket {bucket.name} : {bucket_objects} expected {bkt_objects}"
            )
        cmd_output = command_output
    log.info(f"object synced on another site for bucket {bucket.name} : {cmd_output}")


def flow_operation(
    group_id,
    flow_op,
    flow_type="symmetrical",
    bucket_name=None,
    source_zone=None,
    dest_zone=None,
):
    flow_id = group_id + "flow"
    bkt = ""
    if bucket_name is not None:
        bkt = f" --bucket={bucket_name}"
    zone_names, _ = get_multisite_info()
    cmd = f"radosgw-admin sync group flow {flow_op} --group-id={group_id} --flow-id={flow_id} --flow-type={flow_type}"
    if flow_type == "directional":
        cmd += f" --source-zone={source_zone} --dest-zone={dest_zone}" + bkt
    else:
        cmd += f" --zones={zone_names}" + bkt
    utils.exec_shell_cmd(cmd)
    return zone_names


def pipe_operation(
    group_id,
    pipe_op,
    zone_names=None,
    bucket_name=None,
    policy_detail=None,
    source_zones=None,
    dest_zones=None,
    pipe_id=None,
):
    pipe_id = pipe_id if pipe_id is not None else group_id + "pipe"
    if zone_names is not None:
        zone_name = zone_names.split(",")
        zn = f" --source-zones='{zone_name[0]}','{zone_name[1]}' --dest-zones='{zone_name[0]}','{zone_name[1]}'"
    if source_zones is not None:
        zn = f" --source-zones={source_zones}"
        if dest_zones is not None:
            zn += f" --dest-zones={dest_zones}"
        else:
            zn += " --dest-zones='*'"
    else:
        zn = " --source-zones='*'"
        if dest_zones is not None:
            zn += f" --dest-zones={dest_zones}"
        else:
            zn += " --dest-zones='*'"
    if bucket_name is not None:
        bkt = f" --bucket={bucket_name}"
    else:
        bkt = ""

    cmd = (
        f"radosgw-admin sync group pipe {pipe_op} --group-id={group_id} --pipe-id={pipe_id}"
        + zn
        + bkt
    )
    if policy_detail is not None:
        cmd = cmd + " " + policy_detail

    utils.exec_shell_cmd(cmd)
    if bucket_name is None:
        period_update_commit(True, pipe_op)

    return pipe_id


def object_put_hold(client, body, bucket, key, LegalHold):
    # boto3 put object with object legal hold ON or OFF
    client.put_object(
        Body=body,
        Bucket=bucket,
        Key=key,
        ObjectLockLegalHoldStatus=LegalHold,
    )


def object_lock_retention(client, bucket, key, body, lock_mode, retain_until):
    # boto3 put object with retention policy set at object level
    client.put_object(
        Body=body,
        Bucket=bucket,
        Key=key,
        ObjectLockMode=lock_mode,
        ObjectLockRetainUntilDate=retain_until,
    )


def object_lock_put(client, bucket, lock_configuration):
    # boto3 put object lock configuration on bucket
    client.put_object_lock_configuration(
        Bucket=bucket, ObjectLockConfiguration=lock_configuration
    )


def change_lock_retention(
    client, bucket, key, retention, versionID, BypassGovernanceRetention=True
):
    # boto3 put object lock retention on a object
    client.put_object_retention(
        Bucket=bucket,
        Key=key,
        Retention=retention,
        VersionId=versionID,
    )


def get_lock_configuration(client, bucket, key):
    # rturn the object lock configuration dict
    lock_config = client.get_object_retention(
        Bucket=bucket,
        Key=key,
    )
    return lock_config


def resharding_enable_disable_in_zonegroup(enable=True):
    log.info("method for enabling or disabling resharding feature in zonegroup!")
    zonegroup_get_cmd = "radosgw-admin zonegroup get"
    zonegroups = json.loads(utils.exec_shell_cmd(zonegroup_get_cmd))
    zonegroup = zonegroups.get("name")
    log.info(f"zone group is {zonegroup}")
    if not enable:
        cmd1 = f"radosgw-admin zonegroup modify --rgw-zonegroup={zonegroup} --disable-feature=resharding"
    else:
        cmd1 = f"radosgw-admin zonegroup modify --rgw-zonegroup={zonegroup} --enable-feature=resharding"
    utils.exec_shell_cmd(cmd1)
    cmd2 = "radosgw-admin period update --commit"
    utils.exec_shell_cmd(cmd2)
    zonegroup = json.loads(utils.exec_shell_cmd(zonegroup_get_cmd))
    zonegroup_feature = zonegroup.get("enabled_features")
    if not enable and "resharding" in zonegroup_feature:
        raise AssertionError("Resharding feature is not disabled in zonegroup")
    elif enable and "resharding" not in zonegroup_feature:
        raise AssertionError("Resharding feature is not enabled in zonegroup")
    else:
        log.info("Resharding feature is successfully modified in zonegroup")


def resharding_disable_in_zone(zone_name, disable=True):
    """
    Method to disable/re-enable resharding feature in the zone
    zone_name: specific rgw service name based on zone
    disable: True if we want to disable dbr feature, False to renable
    """
    if disable:
        log.info("method for disabling resharding feature in zone!")
        utils.exec_shell_cmd(
            f"ceph config set client.{zone_name} rgw_dynamic_resharding false"
        )
        rgw_service_name = utils.exec_shell_cmd("ceph orch ls | grep rgw").split(" ")[0]
        utils.exec_shell_cmd(f"ceph orch restart {rgw_service_name}")
    else:
        log.info("method for re-enabling resharding feature in zone!")
        utils.exec_shell_cmd(
            f"ceph config set client.{zone_name} rgw_dynamic_resharding true"
        )
        rgw_service_name = utils.exec_shell_cmd("ceph orch ls | grep rgw").split(" ")[0]
        utils.exec_shell_cmd(f"ceph orch restart {rgw_service_name}")
    time.sleep(60)


def fetch_bucket_gen(bucket):
    log.info(f"fetch bucket gen for the bucket {bucket}")
    json_doc = json.loads(
        utils.exec_shell_cmd(f"radosgw-admin bucket layout --bucket {bucket}")
    )
    bucket_gen = json_doc["layout"]["current_index"]["gen"]
    log.info(f"Generation of bucket {bucket} is :{bucket_gen}")
    return bucket_gen


def verify_acl_preserved(bkt_name, bkt_id):
    json_doc = json.loads(
        utils.exec_shell_cmd(
            f"radosgw-admin metadata get bucket.instance:{bkt_name}:{bkt_id}"
        )
    )
    log.info("The attrs field should not be empty.")
    attrs = json_doc["data"]["attrs"][0]
    if not attrs["key"]:
        raise TestExecError("Acls lost after bucket resharding, test failure.")


def create_container_using_swift(container_name, rgw, user_info):
    """
    This function is to create container swift user

    Parameters:
        container_name(str): Name of the container
        rgw(class_obj): authentication obj
        user_info(dict): user information

    Returns:
    """
    log.info(f"creating container: {container_name} with user {user_info['user_id']}")
    container = s3lib.resource_op(
        {
            "obj": rgw,
            "resource": "put_container",
            "kwargs": dict(container=container_name),
        }
    )
    if container is False:
        raise TestExecError(
            f"container {container_name} creation failed with user {user_info['user_id']}"
        )


def test_bucket_stats_across_sites(bucket_name_to_create, config):
    """
    test bucket stats across all the sites is consistent for a bucket
    """
    is_multisite = utils.is_cluster_multisite()
    if is_multisite:
        log.info(
            f"Test sync is consistent via bucket stats for {bucket_name_to_create}"
        )
        is_primary = utils.is_cluster_primary()
        if is_primary:
            zone_name = "secondary"
        else:
            zone_name = "primary"
        if config.remote_zone == "archive":
            zone_name = config.remote_zone

        # Try bucket stats at local site with fallback
        cmd_bucket_stats = (
            f"radosgw-admin bucket stats --bucket {bucket_name_to_create}"
        )
        log.info(f"Collecting bucket stats for {bucket_name_to_create} at local site")
        try:
            local_output = utils.exec_shell_cmd(cmd_bucket_stats)
            local_bucket_stats = json.loads(local_output)
        except Exception as e:
            log.warning(
                f"Bucket stats failed for {bucket_name_to_create}, trying with tenant0 prefix"
            )
            cmd_bucket_stats = (
                f"radosgw-admin bucket stats --bucket tenant0/{bucket_name_to_create}"
            )
            local_output = utils.exec_shell_cmd(cmd_bucket_stats)
            local_bucket_stats = json.loads(local_output)

        local_num_objects = local_bucket_stats["usage"]["rgw.main"]["num_objects"]
        local_size = local_bucket_stats["usage"]["rgw.main"]["size"]

        log.info(f"Remote zone is {zone_name}")
        remote_ip = utils.get_rgw_ip_zone(zone_name)
        remote_site_ssh_con = utils.connect_remote(remote_ip)

        log.info(
            f"Collecting bucket stats for {bucket_name_to_create} at remote site {zone_name}"
        )
        if config.test_ops.get("download_object_at_remote_site", False):
            log.info("We have already waited for the sync lease period")
        else:
            log.info("We have to wait for sync lease period")
            time.sleep(1200)

        # Try bucket stats at remote site with fallback
        stdin, stdout, stderr = remote_site_ssh_con.exec_command(
            f"radosgw-admin bucket stats --bucket {bucket_name_to_create}"
        )
        cmd_output = stdout.read().decode()
        err_output = stderr.read().decode()
        if cmd_output.strip():
            stats_remote = json.loads(cmd_output)
        elif "failure: (2002) Unknown error 2002:" in err_output:
            log.warning(
                f"Bucket stats failed for {bucket_name_to_create} at remote, trying with tenant0 prefix"
            )
            stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                f"radosgw-admin bucket stats --bucket tenant0/{bucket_name_to_create}"
            )
            cmd_output = stdout.read().decode()
            err_output = stderr.read().decode()
            if cmd_output.strip():
                stats_remote = json.loads(cmd_output)
            else:
                raise TestExecError(
                    f"Bucket stats failed for {bucket_name_to_create} at remote site {zone_name}: {err_output}"
                )
        else:
            raise TestExecError(
                f"Bucket stats failed for {bucket_name_to_create} at remote site {zone_name}: {err_output}"
            )

        log.info(
            f"Bucket stats at remote site {zone_name} for {bucket_name_to_create} is {stats_remote}"
        )
        log.info(
            "Verify num_objects and size is consistent across local and remote site"
        )
        remote_num_objects = stats_remote["usage"]["rgw.main"]["num_objects"]
        remote_size = stats_remote["usage"]["rgw.main"]["size"]
        if remote_size == local_size and remote_num_objects == local_num_objects:
            log.info(f"Data is consistent for bucket {bucket_name_to_create}")
        else:
            raise TestExecError(
                f"Data is inconsistent for {bucket_name_to_create} across sites"
            )


def test_object_download_at_replicated_site(
    bucket_name, s3_object_name, each_user, config
):
    """
    testobject download at the remote site
    """
    is_multisite = utils.is_cluster_multisite()
    if is_multisite:
        log.info(f"Test multipart and encrypted object download for {s3_object_name}")
        is_primary = utils.is_cluster_primary()
        if is_primary:
            zone_name = "secondary"
        else:
            zone_name = "primary"
        log.info(f"remote zone is {zone_name}")
        if config.remote_zone == "archive":
            zone_name = "archive"
        log.info(
            f"Download object {s3_object_name} via boto3 at remote site {zone_name}"
        )
        # Download objects from remote site using boto3 rgw client
        remote_ip = utils.get_rgw_ip_zone(zone_name)
        remote_site_ssh_conn = utils.connect_remote(remote_ip)
        remote_site_auth = get_auth(
            each_user, remote_site_ssh_conn, config.ssl, config.haproxy
        )
        remote_s3_client = remote_site_auth.do_auth_using_client()
        if zone_name == "archive":
            log.info(f"It is a {zone_name} zone, hence objects are always versioned.")
        time.sleep(20)
        response_versions = remote_s3_client.list_object_versions(
            Bucket=bucket_name, Prefix=s3_object_name
        )
        log.info(f"print the response {response_versions}")
        response_versions = response_versions["Versions"]
        log.info(f"print the response {response_versions}")
        for response_ver_id in response_versions:
            version_id = response_ver_id["VersionId"]
            log.info(
                f"Download object for key {s3_object_name} and version_id {version_id}"
            )
            response = remote_s3_client.get_object(
                Bucket=bucket_name, Key=s3_object_name, VersionId=version_id
            )
            if response is False:
                raise TestExecError(
                    "md5sum signature mismatch, detected corruption on download"
                )


def validate_incomplete_multipart(bucket_name, rgw_conn):
    """
    Validating incomplete multipart objects in a bucket
    returns True if incomplete multipart found otherwise returns False

    Parameters:
    bucket_name(str): Name of the bucket

    Returns:
        True: If incomplete multipart found
        False: If incomplete multipart not found
    """
    incomplete_multipart = False
    bkt_stat_output = json.loads(
        utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket_name}")
    )
    if bkt_stat_output["usage"]["rgw.multimeta"]["num_objects"] != 0:
        log.info(f"Incomplete multipart found!")
        incomplete_multipart = True

    multipart_objects = rgw_conn.list_multipart_uploads(Bucket=bucket_name)
    log.info(f"multipart objects {multipart_objects}")
    if "Uploads" in multipart_objects.keys():
        log.info(f"Incomplete multipart found!")
        incomplete_multipart = True

    return incomplete_multipart


def put_bucket_website(rgw_conn, bucket_name):
    """
    Perform put bucket website on given bucket

    Parameters:
    param rgw_conn: rgw connection
    param bucket_name(str): Name of the bucket
    """
    log.info(f"perform put website on bucket: {bucket_name}\n")
    website_conf = {
        "ErrorDocument": {"Key": "error.html"},
        "IndexDocument": {"Suffix": "index.html"},
    }
    put_bucket_website = rgw_conn.put_bucket_website(
        Bucket=bucket_name, WebsiteConfiguration=website_conf
    )
    log.info(f"put_bucket_website response {put_bucket_website}")
    if put_bucket_website is False:
        raise TestExecError(f"Set bucket website failed with {put_bucket_website}")
    if put_bucket_website is not None:
        response = HttpResponseParser(put_bucket_website)
        if response.status_code != 200:
            raise TestExecError(f"put bucket website failed for {bucket_name}")
    else:
        raise TestExecError(f"put bucket website operation failed for {bucket_name}")


def get_bucket_website(rgw_conn, bucket_name):
    """
    Perform get bucket website on given bucket

    Parameters:
    param rgw_conn: rgw connection
    param bucket_name(str): Name of the bucket
    """
    get_bucket_website = rgw_conn.get_bucket_website(Bucket=bucket_name)
    log.info(f"get_bucket_website response {get_bucket_website}")
    if get_bucket_website is False:
        raise TestExecError(f"Get bucket website failed with {get_bucket_website}")
    if get_bucket_website is not None:
        response = HttpResponseParser(get_bucket_website)
        if response.status_code != 200:
            raise TestExecError(f"get bucket website failed for {bucket_name}")
    else:
        raise TestExecError(f"get bucket website operation failed for {bucket_name}")


def test_bucket_stats_colocated_archive_zone(bucket_name_to_create, each_user, config):
    """
    verify the bucket stats on primary and archive zone on the same cluster
    """
    log.info("Perform bucket stats on the primary zone")
    cmd1 = f"radosgw-admin bucket stats --bucket {bucket_name_to_create}"
    cmd2 = " --rgw-zone archive"
    pri_bkt_stat_output = json.loads(utils.exec_shell_cmd(cmd1))
    arc_bkt_stat_output = json.loads(utils.exec_shell_cmd(cmd1 + cmd2))
    pri_bucket_versioning = pri_bkt_stat_output["versioning"]
    arc_bucket_versioning = arc_bkt_stat_output["versioning"]
    if arc_bucket_versioning == "off":
        raise TestExecError(
            f" bucket versioning is not enabled for archive zone when colocated with active zone for {bucket_name_to_create}"
        )
    else:
        log.info(
            "Bucket versioning is enabled in archive zone when  colocated with primary zone"
        )


def put_get_bucket_encryption(rgw_s3_client, bucket_name, config):
    log.info(f"Encryption type is per-bucket, enable it on bucket : {bucket_name}")
    # Choose the encryption_method sse-s3 or sse-kms
    encryption_method = config.encryption_keys
    log.info(f"Encryption method is : {encryption_method}")
    sse_s3.put_bucket_encryption(rgw_s3_client, bucket_name, encryption_method)
    # get bucket encryption
    log.info(f"get bucket encryption for bucket : {bucket_name}")
    sse_s3.get_bucket_encryption(rgw_s3_client, bucket_name)


def create_storage_class_in_all_zones(current_zone, rgw_ssh_con, config):
    """
    This function is to set the prereqs for object sync with bucket granular sync policy
    """
    _, stdout, _ = rgw_ssh_con.exec_command("radosgw-admin bucket list")
    pool_name = config.pool_name
    storage_class = config.storage_class
    zone_names, _ = get_multisite_info()
    log.info(f"zones available are: {zone_names}")
    op = utils.exec_shell_cmd("radosgw-admin sync status")
    lines = list(op.split("\n"))
    for line in lines:
        if "zonegroup" in line:
            zonegroup = line[line.find("(") + 1 : line.find(")")]
            break

    for zone in zone_names:
        if zone == current_zone:
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class {storage_class}"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin zone placement add --rgw-zone {zone} --placement-id default-placement --storage-class {storage_class} --data-pool {pool_name}"
            )
            utils.exec_shell_cmd(f"ceph osd pool create {pool_name}")
            utils.exec_shell_cmd(f"ceph osd pool application enable {pool_name} rgw")
            utils.exec_shell_cmd("radosgw-admin period update --commit")
        else:
            rgw_ssh_con.exec_command(
                f"radosgw-admin zonegroup placement add  --rgw-zonegroup {zonegroup} --placement-id default-placement --storage-class {storage_class}"
            )
            rgw_ssh_con.exec_command(
                f"radosgw-admin zone placement add --rgw-zone {zone} --placement-id default-placement --storage-class {storage_class} --data-pool {pool_name}"
            )
            rgw_ssh_con.exec_command(f"ceph osd pool create {pool_name}")
            rgw_ssh_con.exec_command(
                f"ceph osd pool application enable {pool_name} rgw"
            )
            rgw_ssh_con.exec_command("radosgw-admin period update --commit")


def validate_default_placement_and_storageclass_for_user(
    uid, placement_id, storage_class
):
    """
    This function is to validate default_placement and storageclass set to user
    uid: uid of the user
    placement_id: placement_id set to the user
    storage_class: storage_class set to the user
    """
    out = json.loads(utils.exec_shell_cmd(f"radosgw-admin user info --uid={uid}"))
    if out["default_placement"] != str(placement_id):
        raise AssertionError(f"default Placement set for user: {uid} is failed")
    if out["default_storage_class"] != str(storage_class):
        raise AssertionError(f"default storage class set for user: {uid} is failed")


def get_placement_and_storageclass_from_cluster():
    """
    This function is to fetch placement_id and storage_class from the cluster.
    """
    cmd = "radosgw-admin zone get"
    out = json.loads(utils.exec_shell_cmd(cmd))
    placement_id = out["placement_pools"][0]["key"]
    storage_classes = out["placement_pools"][0]["val"]["storage_classes"]
    storage_class_list = list(storage_classes.keys())
    return placement_id, storage_class_list


def get_object_attributes(
    rgw_s3_client,
    bucket_name,
    s3_object_name,
    object_attributes=None,
    object_parts_info=None,
):
    log.info("Verifying GetObjectAttributes")
    if object_attributes is None:
        object_attributes = [
            "ETag",
            "StorageClass",
            "ObjectSize",
            "ObjectParts",
            "Checksum",
        ]
    get_obj_attr_resp = rgw_s3_client.get_object_attributes(
        Bucket=bucket_name, Key=s3_object_name, ObjectAttributes=object_attributes
    )
    log.info(f"get_object_attributes resp: {get_obj_attr_resp}")

    if "Checksum" in object_attributes:
        log.info("Verifying Checksum")
        out = utils.exec_shell_cmd(
            f"radosgw-admin object stat --bucket {bucket_name} --object {s3_object_name}"
        )
        obj_stat = json.loads(out)
        checksum_expected = {}
        for key, val in obj_stat["attrs"].items():
            if key.startswith("user.rgw.x-amz-checksum-"):
                checksum_key = f"Checksum{key.split('-')[-1].upper()}"
                checksum_expected[checksum_key] = val
                if (
                    checksum_key == "ChecksumSHA256" or checksum_key == "ChecksumSHA1"
                ) and object_parts_info:
                    # checksum_type is COMPOSITE only for multipart objects uploaded with SHA1 or SHA256 algo by default
                    checksum_expected["ChecksumType"] = "COMPOSITE"
                else:
                    checksum_expected["ChecksumType"] = "FULL_OBJECT"

        log.info(f"checksum expected: {checksum_expected}")
        if checksum_expected != get_obj_attr_resp["Checksum"]:
            raise TestExecError(f"incorrect Checksum in GetObjectAttributes")
        else:
            log.info("Checksum verified successfully")
        object_attributes.remove("Checksum")

    if "ObjectParts" in object_attributes:
        if object_parts_info is not None:
            log.info("Verifying ObjectParts")
            log.info(f"expected ObjectParts: {object_parts_info}")
            object_parts_info_actual = get_obj_attr_resp["ObjectParts"]
            if (
                object_parts_info["TotalPartsCount"]
                != object_parts_info_actual["TotalPartsCount"]
            ):
                raise TestExecError(
                    f"incorrect data for TotalPartsCount in ObjectParts"
                )
            parts_actual = object_parts_info_actual["Parts"]
            parts_expected = object_parts_info["Parts"]
            for index in range(0, len(parts_actual)):
                if (
                    parts_expected[index]["PartNumber"]
                    != parts_actual[index]["PartNumber"]
                ):
                    raise TestExecError(f"incorrect data for PartNumber in part{index}")
                if parts_expected[index]["Size"] != parts_actual[index]["Size"]:
                    raise TestExecError(f"incorrect data for Size in part{index}")
            log.info("ObjectParts verified successfully")
        object_attributes.remove("ObjectParts")

    out = utils.exec_shell_cmd(f"radosgw-admin bucket list --bucket {bucket_name}")
    bkt_list = json.loads(out)
    object_dict = {}
    for dict in bkt_list:
        if dict["name"] == s3_object_name:
            object_dict = dict
            break
    for attr in object_attributes:
        if attr == "StorageClass":
            expected = object_dict["meta"]["storage_class"]
            if expected == "":
                expected = "STANDARD"
        if attr == "ObjectSize":
            expected = object_dict["meta"]["size"]
        if attr == "ETag":
            expected = object_dict["meta"]["etag"]
        actual = get_obj_attr_resp[attr]
        if expected != actual:
            raise TestExecError(
                f"incorrect data for {attr} in GetObjectAttributes. expected {expected}, but returned {actual}"
            )
        else:
            log.info(f"{attr} verified successfully")
    log.info("GetObjectAttributes verified successfully")


def generate_presigned_url(rgw_s3_client, client_method, http_method, params):
    log.info(
        f"generating presigned url for client_method {client_method}, http_method {http_method} with params {params}"
    )
    presigned_url = rgw_s3_client.generate_presigned_url(
        ClientMethod=client_method, HttpMethod=http_method, Params=params
    )
    log.info(f"presigned_url: {presigned_url}")
    return presigned_url


def put_get_public_access_block(rgw_s3_client, bucket_name, public_access_block_config):
    log.info(
        f"setting public access block for bucket {bucket_name} with config {public_access_block_config}"
    )
    put_response = rgw_s3_client.put_public_access_block(
        Bucket=bucket_name, PublicAccessBlockConfiguration=public_access_block_config
    )
    log.info(f"put response: {put_response}")
    get_response = rgw_s3_client.get_public_access_block(Bucket=bucket_name)
    log.info(f"get response: {get_response}")
    return True


def put_get_bucket_acl(rgw_client, bucket_name, acl):
    """
    put bucket acl for a given object
    """
    log.info(f"Set bucket acl on bucket : {bucket_name}")
    put_bkt_acl = rgw_client.put_bucket_acl(ACL=acl, Bucket=bucket_name)
    log.info(f"put bucket acl resp: {put_bkt_acl}")

    get_bkt_acl = rgw_client.get_bucket_acl(Bucket=bucket_name)
    get_bkt_acl_json = json.dumps(get_bkt_acl, indent=2)
    log.info(f"get bucket acl response: {get_bkt_acl_json}")


def get_user_canonical_id(
    user_info, rgw_conn, rgw_conn_c, ssh_con=None, ssl=False, haproxy=False
):
    """
    Get canonical ID of a user by creating a temporary bucket and reading its ACL

    Parameters:
        user_info (dict): User information dictionary with user_id, access_key, secret_key
        rgw_conn: S3 resource connection for the user
        rgw_conn_c: S3 client connection for the user
        ssh_con: SSH connection (optional, for remote connections)
        ssl: Whether to use SSL (optional)
        haproxy: Whether to use haproxy (optional)

    Returns:
        str: Canonical ID of the user
    """
    # Create a temporary bucket to get canonical ID
    temp_bucket_name = utils.gen_bucket_name_from_userid(
        user_info["user_id"], rand_no=999
    )
    temp_bucket = create_bucket(temp_bucket_name, rgw_conn, user_info)
    acl_response = rgw_conn_c.get_bucket_acl(Bucket=temp_bucket_name)
    canonical_id = acl_response["Owner"]["ID"]
    log.info("canonical id of user %s: %s" % (user_info["user_id"], canonical_id))

    # Delete temporary bucket
    delete_bucket(temp_bucket)

    return canonical_id


def set_bucket_acl_with_grants(
    rgw_conn_c, bucket_name, grants_list, preserve_owner=True
):
    """
    Set bucket ACL with grants (AccessControlPolicy format)

    Parameters:
        rgw_conn_c: S3 client connection
        bucket_name (str): Name of the bucket
        grants_list (list): List of grant dictionaries, each with:
            - "Grantee": {"ID": canonical_id, "Type": "CanonicalUser"}
            - "Permission": "READ", "WRITE", "FULL_CONTROL", etc.
        preserve_owner (bool): If True, preserves the owner's FULL_CONTROL grant

    Returns:
        dict: Response from put_bucket_acl
    """
    # Get current ACL to preserve owner information
    current_acl = rgw_conn_c.get_bucket_acl(Bucket=bucket_name)
    owner = current_acl["Owner"]

    # Build grants list
    grants = []

    # Always include owner's FULL_CONTROL if preserve_owner is True
    if preserve_owner:
        grants.append(
            {
                "Grantee": {
                    "ID": owner["ID"],
                    "Type": "CanonicalUser",
                },
                "Permission": "FULL_CONTROL",
            }
        )

    # Add user-specified grants
    grants.extend(grants_list)

    # Build AccessControlPolicy
    access_control_policy = {
        "Grants": grants,
        "Owner": owner,
    }

    # Set bucket ACL
    put_acl_response = rgw_conn_c.put_bucket_acl(
        Bucket=bucket_name, AccessControlPolicy=access_control_policy
    )
    log.info("put bucket acl response: %s" % put_acl_response)

    return put_acl_response


def reboot_rgw_nodes(rgw_service_name):
    """
    Method to fetch all the rgw nodes to proceed with reboot
    """
    host_ips = utils.exec_shell_cmd("cut -f 1 /etc/hosts | cut -d ' ' -f 3")
    host_ips = host_ips.splitlines()
    log.info(f"hosts_ips: {host_ips}")
    for ip in host_ips:
        if ip.startswith("10."):
            log.info(f"ip is {ip}")
            ssh_con = utils.connect_remote(ip)
            stdin, stdout, stderr = ssh_con.exec_command(
                "sudo netstat -nltp | grep radosgw"
            )
            netstst_op = stdout.readline().strip()
            log.info(f"netstat op on node {ip} is:{netstst_op}")
            if netstst_op:
                log.info("Entering RGW node")
                stdin, stdout, stderrt = ssh_con.exec_command("hostname")
                host = stdout.readline().strip()
                log.info(f"hostname is {host}")
                cmd = f"ceph orch ps|grep rgw|grep {host}"
                out = utils.exec_shell_cmd(cmd)
                service_name = out.split()[0]
                log.info(f"service name is {service_name}")
                if rgw_service_name in service_name:
                    log.info(f"Performing reboot of the node :{ip}")
                    node_reboot(ssh_con, service_name=out.split()[0])


def node_reboot(node, service_name=None, retry=15, delay=60):
    """
    Method to reboot single RGW node
    Node: ssh connection for the node
    service_name: RGW service name
    retry: retry to wait foe node/service to come up post reboot
    delay: sleep time of 1 min between each try
    """
    log.info(f"Peforming reboot of the node : {node}")
    node.exec_command("sudo reboot")
    time.sleep(120)
    log.info(f"checking ceph status")
    utils.exec_shell_cmd(f"ceph -s")
    cmd = "ceph orch ps --format json-pretty"
    out = json.loads(utils.exec_shell_cmd(cmd))
    for entry in out:
        if service_name == entry["daemon_name"]:
            status = entry["status_desc"]
    if str(status) != "running":
        for retry_count in range(retry):
            log.info(f"try {retry_count}")
            out = json.loads(utils.exec_shell_cmd(cmd))
            for entry in out:
                if service_name == entry["daemon_name"]:
                    status = entry["status_desc"]
            log.info(f"status is {status}")
            if str(status) != "running":
                log.info(f"Node is not in expected state, waiting for {delay} seconds")
                time.sleep(delay)
            else:
                log.info("Node is in expected state")
                break
        if retry_count + 1 == retry:
            raise AssertionError("Node is not in expected state post 15min!!")


def bring_down_all_rgws_in_the_site(rgw_service_name, retry=10, delay=10):
    """
    Method to bring down rgw services in all the nodes
    rgw_service_name: RGW service name
    """
    cmd = f"ceph orch stop {rgw_service_name}"
    utils.exec_shell_cmd(cmd)
    cmd = "ceph orch ps --format json-pretty"
    out = json.loads(utils.exec_shell_cmd(cmd))
    for entry in out:
        daemon = entry["daemon_name"].split(".")[0]
        log.info(f"daemon type is {daemon}")
        if daemon == "rgw":
            service_name = entry["daemon_name"]
            log.info(f"daemon is {service_name}")
            if rgw_service_name in service_name:
                status = entry["status_desc"]
                if str(status) == "running":
                    log.info(f"enter loop of retry")
                    for retry_count in range(retry):
                        log.info(f"try {retry_count}")
                        out = json.loads(utils.exec_shell_cmd(cmd))
                        for entry in out:
                            if service_name == entry["daemon_name"]:
                                status = entry["status_desc"]
                        log.info(f"status is {status}")
                        if str(status) == "running":
                            log.info(
                                f"Node is not in expected state, waiting for {delay} seconds"
                            )
                            time.sleep(delay)
                        else:
                            log.info(f"Node {service_name} is in expected state")
                            break
                    if retry_count + 1 == retry:
                        raise AssertionError("Node is not in expected state!!")


def bring_up_all_rgws_in_the_site(rgw_service_name, retry=10, delay=10):
    """
    Method to bring up rgw services in all the nodes
    """
    cmd = f"ceph orch start {rgw_service_name}"
    utils.exec_shell_cmd(cmd)
    cmd = "ceph orch ps --format json-pretty"
    out = json.loads(utils.exec_shell_cmd(cmd))
    for entry in out:
        daemon = entry["daemon_name"].split(".")[0]
        log.info(f"daemon type is {daemon}")
        if daemon == "rgw":
            service_name = entry["daemon_name"]
            log.info(f"daemon is {service_name}")
            if rgw_service_name in service_name:
                status = entry["status_desc"]
                if str(status) != "running":
                    log.info(f"enter loop of retry")
                    for retry_count in range(retry):
                        log.info(f"try {retry_count}")
                        out = json.loads(utils.exec_shell_cmd(cmd))
                        for entry in out:
                            if service_name == entry["daemon_name"]:
                                status = entry["status_desc"]
                        log.info(f"status is {status}")
                        if str(status) != "running":
                            log.info(
                                f"Node is not in expected state, waiting for {delay} seconds"
                            )
                            time.sleep(delay)
                        else:
                            log.info(f"Node {service_name} is in expected state")
                            break
                    if retry_count + 1 == retry:
                        raise AssertionError("Node is not in expected state!!")


def configure_rgw_lc_settings():
    """
    Retrieves RGW services using 'ceph orch ls | grep rgw' and sets LC debug configs.
    """
    log.info("Retrieving RGW service names...")

    # Fetch RGW services
    rgw_services_output = utils.exec_shell_cmd("ceph orch ls | grep rgw")

    if not rgw_services_output:
        log.error("No RGW services found or failed to retrieve.")
        return

    # Extract service names from output
    rgw_services = []
    for line in rgw_services_output.split("\n"):
        line = line.strip()
        if line:  # Ignore empty lines
            columns = line.split()
            if columns:  # Ensure there are columns before accessing
                rgw_services.append(columns[0])

    if not rgw_services:
        log.warning("No valid RGW services extracted.")
        return

    log.info(f"Found RGW services: {rgw_services}")

    # Set LC debug interval for each RGW service
    for service in rgw_services:
        lc_config_cmd1 = f"ceph config set client.{service} rgw_lc_debug_interval 600"
        log.info(f"Setting LC config for {service}: {lc_config_cmd1}")
        utils.exec_shell_cmd(lc_config_cmd1)
        lc_config_cmd2 = "ceph config set client.{service} rgw_lc_max_worker 10"
        log.info(f"Setting LC config for {service}: {lc_config_cmd2}")
        utils.exec_shell_cmd(lc_config_cmd2)
        ceph_restart_cmd = f"ceph orch restart {service}"
        utils.exec_shell_cmd(ceph_restart_cmd)

    log.info("RGW LC debug interval settings updated successfully.")


def get_rgw_service_port():
    log.info("checking rgw service")
    rgw_serv = json.loads(
        utils.exec_shell_cmd("ceph orch ls --service_type=rgw --format json")
    )
    rgw_serv_port = rgw_serv[0]["status"]["ports"][0]
    return rgw_serv_port


def get_auth(user_info, ssh_con, ssl, haproxy):
    rgw_service_port = get_rgw_service_port()
    haproxy = False if rgw_service_port == 443 else haproxy
    return Auth(user_info, ssh_con, ssl=ssl, haproxy=haproxy)


def verify_object_accessibility(s3_client, bucket_name, object_key):
    """
    Verify if the object can be accessed from the bucket.
    """
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            log.info(f"Object {object_key} is accessible post reshard.")
        else:
            log.error(
                f"Object {object_key} not accessible. Status: {response['ResponseMetadata']['HTTPStatusCode']}"
            )
    except Exception as e:
        log.error(f"Failed to access object {object_key}: {e}")
        raise


def list_bucket_objects(rgw_s3_client, bucket_name):
    """
    returns all of the objects in the bucket
    """
    resp = rgw_s3_client.list_objects(Bucket=bucket_name)
    log.info(f"list bucket objects response: {resp}")
    return resp["Contents"]


def delete_indexless_bucket(bucket):
    """
    Deletes an indexless bucket.
    This function directly deletes the bucket without listing objects,
    since indexless buckets do not maintain object indexes.
    """
    log.info(f"Deleting indexless bucket: {bucket.name}")
    try:
        bucket_deleted_response = s3lib.resource_op(
            {"obj": bucket, "resource": "delete", "args": None}
        )
        log.info(f"bucket_deleted_status: {bucket_deleted_response}")

        # Handle boto3 or dict response
        if isinstance(bucket_deleted_response, dict):
            response = HttpResponseParser(bucket_deleted_response)
            if response.status_code == 204:
                log.info(f"Indexless bucket '{bucket.name}' deleted successfully")
            else:
                log.warning(
                    f"Bucket '{bucket.name}' deletion returned status code {response.status_code}"
                )
        else:
            log.warning(f"bucket '{bucket.name}', already deleted")

    except Exception as e:
        # Ignore NoSuchKey explicitly
        if "NoSuchKey" in str(e):
            log.warning(
                f"Bucket '{bucket.name}' may already be deleted or not found ({err_msg})"
            )
        else:
            raise TestExecError(f"Bucket deletion failed: {err_msg}")


def install_ibm_cloud_cli(version="2.34.0", install_dir="/tmp/ibmcloud_install"):
    """
    Install IBM Cloud CLI if not already installed

    Args:
        version (str): Version of IBM Cloud CLI to install (default: 2.34.0)
        install_dir (str): Temporary directory for installation

    Returns:
        bool: True if installation successful or already installed
    """
    if shutil.which("ibmcloud"):
        try:
            existing_version = utils.exec_shell_cmd("ibmcloud --version")
            if existing_version and version in existing_version:
                log.info(f"IBM Cloud CLI {version} already installed")
                return True
            log.info(f"IBM Cloud CLI version mismatch: {existing_version}")
        except Exception:
            pass

    try:
        log.info(f"Installing IBM Cloud CLI {version}")
        os.makedirs(install_dir, exist_ok=True)
        tar_file = os.path.join(install_dir, f"IBM_Cloud_CLI_{version}_amd64.tar.gz")
        download_url = f"https://download.clis.cloud.ibm.com/ibm-cloud-cli/{version}/IBM_Cloud_CLI_{version}_amd64.tar.gz"
        log.info(f"Downloading IBM Cloud CLI from {download_url}")
        utils.exec_shell_cmd(f"curl -L {download_url} -o {tar_file}")
        log.info("Extracting IBM Cloud CLI")
        utils.exec_shell_cmd(f"cd {install_dir} && tar -xvf {tar_file}")
        log.info("Installing IBM Cloud CLI")
        install_script = os.path.join(install_dir, "Bluemix_CLI", "install")
        if os.path.exists(install_script):
            utils.exec_shell_cmd(f"bash {install_script}")
        else:
            install_script = os.path.join(install_dir, "install")
            if os.path.exists(install_script):
                utils.exec_shell_cmd(f"bash {install_script}")
            else:
                raise TestExecError("IBM Cloud CLI install script not found")

        if shutil.which("ibmcloud"):
            log.info("IBM Cloud CLI installed successfully")
            return True

        # Check default installation location
        default_install_path = "/usr/local/ibmcloud/bin/ibmcloud"
        if os.path.exists(default_install_path) and os.access(
            default_install_path, os.X_OK
        ):
            # Add to PATH for current process
            current_path = os.environ.get("PATH", "")
            ibmcloud_bin_dir = os.path.dirname(default_install_path)
            if ibmcloud_bin_dir not in current_path:
                os.environ["PATH"] = f"{ibmcloud_bin_dir}:{current_path}"
            log.info("IBM Cloud CLI installed successfully")
            return True

        # Check alternative locations
        alternative_paths = [
            "/usr/local/bin/ibmcloud",
            os.path.expanduser("~/ibmcloud/bin/ibmcloud"),
        ]
        for alt_path in alternative_paths:
            if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                alt_bin_dir = os.path.dirname(alt_path)
                current_path = os.environ.get("PATH", "")
                if alt_bin_dir not in current_path:
                    os.environ["PATH"] = f"{alt_bin_dir}:{current_path}"
                log.info("IBM Cloud CLI installed successfully")
                return True

        raise TestExecError(
            "IBM Cloud CLI installation failed - command not found in PATH or default locations"
        )

    except Exception as e:
        raise TestExecError(f"Failed to install IBM Cloud CLI: {e}")
    finally:
        try:
            if os.path.exists(install_dir):
                utils.exec_shell_cmd(f"rm -rf {install_dir}")
        except Exception:
            pass


def create_ibm_cloud_apikey(
    name, description=None, ibm_cloud_cli_path=None, output_format="json"
):
    """
    Create a new IBM Cloud API key.

    Args:
        name (str): Name for the API key
        description (str): Optional description for the API key
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        output_format (str): Output format (json or text, default: json)

    Returns:
        dict: API key information including the API key value
    """
    log.info(f"Creating IBM Cloud API key: {name}")
    try:
        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [
            base_cmd,
            "iam",
            "api-key-create",
            name,
            "--output",
            output_format,
        ]
        if description:
            cmd_args.extend(["--description", description])

        log.info("Executing API key creation command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr if stderr else stdout
            raise TestExecError(
                f"Failed to create API key. Return code: {process.returncode}, Error: {error_msg}"
            )

        if output_format == "json":
            try:
                api_key_data = json.loads(stdout)
                log.info(f"API key created successfully: {name}")
                return api_key_data
            except json.JSONDecodeError:
                raise TestExecError(
                    f"Failed to parse API key creation output: {stdout}"
                )
        else:
            log.info(f"API key created successfully: {name}")
            return {"output": stdout}

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error creating IBM Cloud API key: {e}")


def list_ibm_cloud_apikeys(ibm_cloud_cli_path=None, output_format="json"):
    """
    List all IBM Cloud API keys for the current user.

    Args:
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        output_format (str): Output format (json or text, default: json)

    Returns:
        list: List of API key information dictionaries
    """
    log.info("Listing IBM Cloud API keys")
    try:
        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [base_cmd, "iam", "api-keys", "--output", output_format]

        log.info("Executing API key list command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr if stderr else stdout
            raise TestExecError(
                f"Failed to list API keys. Return code: {process.returncode}, Error: {error_msg}"
            )

        if output_format == "json":
            try:
                api_keys_data = json.loads(stdout)
                if isinstance(api_keys_data, list):
                    log.info(f"Found {len(api_keys_data)} API key(s)")
                    return api_keys_data
                elif isinstance(api_keys_data, dict) and "apikeys" in api_keys_data:
                    api_keys = api_keys_data["apikeys"]
                    log.info(f"Found {len(api_keys)} API key(s)")
                    return api_keys
                else:
                    log.warning("Unexpected API key list format")
                    return []
            except json.JSONDecodeError:
                raise TestExecError(f"Failed to parse API key list output: {stdout}")
        else:
            log.info("API keys listed successfully")
            return {"output": stdout}

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error listing IBM Cloud API keys: {e}")


def delete_ibm_cloud_apikey(api_key_id, ibm_cloud_cli_path=None, force=False):
    """
    Delete an IBM Cloud API key.

    Args:
        api_key_id (str): API key ID or name to delete
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        force (bool): If True, force deletion without confirmation

    Returns:
        bool: True if deletion successful
    """
    log.info(f"Deleting IBM Cloud API key: {api_key_id}")
    try:
        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [base_cmd, "iam", "api-key-delete", api_key_id]
        if force:
            cmd_args.append("--force")

        log.info("Executing API key deletion command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr if stderr else stdout
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                log.warning(f"API key {api_key_id} not found (may already be deleted)")
                return False
            raise TestExecError(
                f"Failed to delete API key. Return code: {process.returncode}, Error: {error_msg}"
            )

        log.info(f"API key {api_key_id} deleted successfully")
        return True

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error deleting IBM Cloud API key: {e}")


def rotate_ibm_cloud_apikey(
    old_api_key_id=None,
    new_name=None,
    description=None,
    ibm_cloud_cli_path=None,
    delete_old=True,
):
    """
    Rotate IBM Cloud API key by creating a new one and optionally deleting the old one.

    Args:
        old_api_key_id (str): ID or name of the old API key to delete (optional)
        new_name (str): Name for the new API key (default: auto-generated with timestamp)
        description (str): Optional description for the new API key
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        delete_old (bool): If True, delete the old API key after creating new one

    Returns:
        dict: New API key information including the API key value
    """
    log.info("Rotating IBM Cloud API key")
    try:
        if not new_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_name = f"rotated_apikey_{timestamp}"

        # Create new API key
        new_api_key_data = create_ibm_cloud_apikey(
            new_name, description, ibm_cloud_cli_path
        )

        # Extract the API key value from the response
        api_key_value = None
        if isinstance(new_api_key_data, dict):
            # Try different possible keys for the API key value
            api_key_value = (
                new_api_key_data.get("apikey")
                or new_api_key_data.get("apiKey")
                or new_api_key_data.get("value")
                or new_api_key_data.get("apikey_value")
            )
            if not api_key_value and "output" in new_api_key_data:
                # If output is text, try to extract from it
                output = new_api_key_data["output"]
                # Look for patterns like "API key: xxxxx" or similar
                for line in output.split("\n"):
                    if "apikey" in line.lower() or "api key" in line.lower():
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if len(part) > 40:  # API keys are typically long
                                api_key_value = part.strip()
                                break
                        if api_key_value:
                            break

        if not api_key_value:
            log.warning(
                "Could not extract API key value from creation response. "
                "You may need to retrieve it manually."
            )

        # Optionally delete old API key
        if delete_old and old_api_key_id:
            try:
                delete_ibm_cloud_apikey(old_api_key_id, ibm_cloud_cli_path, force=True)
                log.info(f"Old API key {old_api_key_id} deleted successfully")
            except Exception as delete_e:
                log.warning(
                    f"Failed to delete old API key {old_api_key_id}: {delete_e}. "
                    "New API key created successfully."
                )

        result = {
            "name": new_name,
            "api_key_value": api_key_value,
            "api_key_data": new_api_key_data,
        }
        log.info(f"API key rotation completed. New API key name: {new_name}")
        return result

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error rotating IBM Cloud API key: {e}")


def load_and_set_api_key():
    """
    Load IBM Cloud API key from environment variable.
    The API key must be set via IBM_CLOUD_API_KEY environment variable.

    Returns:
        str: API key if found in environment, None otherwise
    """
    api_key = os.getenv("IBM_CLOUD_API_KEY")
    if api_key:
        is_ci = os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true"
        if is_ci:
            log.info("IBM_CLOUD_API_KEY found in environment (GitHub Actions secret)")
        else:
            log.info("IBM_CLOUD_API_KEY found in environment")
        return api_key

    log.warning("IBM_CLOUD_API_KEY not found in environment variable")
    return None


def login_ibmcloud_with_apikey(api_key, region=None, ibm_cloud_cli_path=None):
    """
    Login to IBM Cloud CLI using API key.
    For security, use API key rotation (rotate_ibm_cloud_apikey) to manage API keys.

    Args:
        api_key (str): IBM Cloud API key (plain text)
        region (str): Region to target (e.g., 'in-che', 'us-south')
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary

    Returns:
        bool: True if login successful
    """
    log.info("Logging in to IBM Cloud CLI using API key")
    try:
        if not api_key:
            raise ValueError("API key cannot be empty")
        plain_api_key = api_key.strip()

        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [base_cmd, "login", "--apikey", plain_api_key, "-a", "cloud.ibm.com"]
        if region:
            cmd_args.extend(["-r", region])

        log.info("Executing login command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()
        output = stdout or ""

        if process.returncode != 0:
            detail = (stderr or stdout or "").strip()
            log.error(
                "Login command failed with return code %s. stderr/stdout: %s",
                process.returncode,
                detail[:500] if detail else "(none)",
            )
            raise TestExecError(
                "IBM Cloud login failed (check API key and network). "
                f"returncode={process.returncode}; output: {detail[:300] or '(none)'}"
            )

        if output and (
            "OK" in output
            or "Authenticating..." in output
            or "Targeted account" in output
            or "Targeted region" in output
        ):
            time.sleep(2)
            verify_cmd = [base_cmd, "target"]
            verify_process = subprocess.Popen(
                verify_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                universal_newlines=True,
            )
            verify_stdout, verify_stderr = verify_process.communicate()
            if verify_stdout and (
                "Account:" in verify_stdout or "User:" in verify_stdout
            ):
                log.info("Login verified immediately after login command")
                return True
            else:
                log.warning("Login succeeded but verification failed")
                return True
        else:
            detail = (stderr or output or "").strip()
            log.error(
                "Login output missing success indicators. stdout: %s",
                (output or "(none)")[:500],
            )
            raise TestExecError(
                "IBM Cloud login failed - CLI output did not indicate success. "
                f"output: {(detail or output or '(none)')[:300]}"
            )
    except Exception as e:
        raise TestExecError(f"Error during IBM Cloud login with API key: {e}")


def get_ibm_iam_jwt_token(
    ibm_cloud_cli_path=None,
    api_key=None,
    region=None,
):
    """
    Get IBM IAM JWT token using IBM Cloud CLI

    Args:
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        api_key (str): IBM Cloud API key for auto-login (required)
        region (str): Region to target for auto-login (e.g., 'in-che', 'us-south')

    Returns:
        str: JWT token (without Bearer prefix)
    """
    log.info("Getting IBM IAM JWT token")
    try:
        if ibm_cloud_cli_path:
            cli_cmd = ibm_cloud_cli_path
            if not os.path.exists(cli_cmd) or not os.access(cli_cmd, os.X_OK):
                if shutil.which("ibmcloud"):
                    log.info("IBM Cloud CLI already exists in PATH, skipping installation")
                    cli_cmd = "ibmcloud"
                else:
                    log.info("Attempting to auto-install IBM Cloud CLI")
                    install_ibm_cloud_cli()
                    cli_cmd = "ibmcloud"
        else:
            cli_cmd = "ibmcloud"
            cli_path = shutil.which(cli_cmd)
            if not cli_path:
                default_install_path = "/usr/local/ibmcloud/bin/ibmcloud"
                if os.path.exists(default_install_path) and os.access(default_install_path, os.X_OK):
                    log.info("IBM Cloud CLI found at default location, skipping installation")
                    current_path = os.environ.get("PATH", "")
                    ibmcloud_bin_dir = os.path.dirname(default_install_path)
                    if ibmcloud_bin_dir not in current_path:
                        os.environ["PATH"] = f"{ibmcloud_bin_dir}:{current_path}"
                    cli_path = default_install_path
                else:
                    log.info("Auto-installing IBM Cloud CLI")
                    install_ibm_cloud_cli()
                    cli_path = shutil.which(cli_cmd)
                    if not cli_path:
                        if os.path.exists(default_install_path) and os.access(default_install_path, os.X_OK):
                            current_path = os.environ.get("PATH", "")
                            ibmcloud_bin_dir = os.path.dirname(default_install_path)
                            if ibmcloud_bin_dir not in current_path:
                                os.environ["PATH"] = f"{ibmcloud_bin_dir}:{current_path}"
                            cli_path = default_install_path
                        if not cli_path:
                            raise TestExecError("IBM Cloud CLI auto-installation failed")

        if not api_key:
            raise TestExecError(
                "Unable to find API key. Set IBM_CLOUD_API_KEY environment variable"
            )
        # Endpoint is set by ibmcloud login --apikey -a cloud.ibm.com (no separate "ibmcloud api" call).
        log.info("API key found for auto-login, Checking login status")
        try:
            check_cmd = f"{cli_cmd} target"
            check_output = utils.exec_shell_cmd(check_cmd)
            is_logged_in = check_output and (
                "Account:" in check_output or "User:" in check_output
            )

            if is_logged_in:
                log.info("Already logged in")

            if not is_logged_in:
                log.info("Attempting auto-login")
                if api_key:
                    login_success = login_ibmcloud_with_apikey(
                        api_key, region, cli_cmd
                    )
                    if not login_success:
                        raise TestExecError("Failed to login with API key")
                    time.sleep(3)
                else:
                    raise TestExecError("API key required for login")

            time.sleep(2)
            verify_cmd = [cli_cmd, "target"]
            verify_process = subprocess.Popen(
                verify_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            verify_stdout, verify_stderr = verify_process.communicate()
            verify_output = verify_stdout
            if not verify_output or (
                "Account:" not in verify_output and "User:" not in verify_output
            ):
                if "Not logged in" in verify_output:
                    raise TestExecError(
                        f"Login verification failed - login may not have persisted. Output: {verify_output}"
                    )
                else:
                    raise TestExecError(
                        f"Login verification failed. Output: {verify_output}"
                    )

            log.info("Login verified successfully")
        except Exception as e:
            if isinstance(e, TestExecError):
                raise
            log.warning(
                f"Error checking/login status: {e}. Continuing to try getting token..."
            )

        if ibm_cloud_cli_path:
            cmd = f"{ibm_cloud_cli_path} iam oauth-tokens --output json"
        else:
            cmd = "ibmcloud iam oauth-tokens --output json"

        try:
            output = utils.exec_shell_cmd(cmd)
            if not output or output is False:
                raise TestExecError(
                    "Failed to get IBM IAM oauth tokens - command returned no output"
                )
        except Exception as e:
            error_msg = str(e)
            if "No API endpoint set" in error_msg or "api endpoint" in error_msg.lower():
                raise TestExecError(
                    "IBM Cloud API endpoint not set. Login with API key sets it automatically; "
                    "if you see this, re-run the test or run: ibmcloud login --apikey <key> -a cloud.ibm.com. "
                    f"Error: {error_msg}"
                )
            raise TestExecError(f"Failed to get oauth tokens. Error: {error_msg}")

        token_data = json.loads(output)
        iam_token = token_data.get("iam_token", "")

        if not iam_token:
            raise TestExecError("IAM token not found. Ensure logged in")
        if iam_token.startswith("Bearer "):
            iam_token = iam_token[7:]
        log.info("JWT token obtained successfully")
        return iam_token
    except TestExecError:
        raise
    except json.JSONDecodeError as e:
        raise TestExecError(f"Failed to parse CLI output as JSON: {e}")
    except Exception as e:
        raise TestExecError(f"Failed to get JWT token: {e}")


def get_ibm_iam_thumbprint(region="us-south"):
    """
    Get IBM IAM certificate thumbprint

    Args:
        region (str): IBM Cloud region (default: us-south)

    Returns:
        str: Certificate thumbprint (without colons)
    """
    log.info(f"Getting certificate thumbprint for region: {region}")
    oidc_config_url = (
        "https://iam.cloud.ibm.com/identity/.well-known/openid-configuration"
    )
    try:
        with urllib.request.urlopen(oidc_config_url) as response:
            oidc_config = json.loads(response.read().decode())

        jwks_uri = oidc_config.get("jwks_uri", "")
        if not jwks_uri:
            raise TestExecError("jwks_uri not found in OIDC configuration")

        parsed_uri = urlparse(jwks_uri)
        server_name = parsed_uri.hostname
        if not server_name:
            raise TestExecError(f"Could not extract hostname from jwks_uri: {jwks_uri}")
    except Exception as e:
        raise TestExecError(f"Failed to get jwks_uri from OIDC configuration: {e}")

    try:
        cert_file = "/tmp/ibm_cert.crt"
        temp_all_certs = "/tmp/ibm_all_certs.crt"
        cmd_get_all = f"openssl s_client -servername {server_name} -showcerts -connect {server_name}:443 < /dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > {temp_all_certs}"
        utils.exec_shell_cmd(cmd_get_all)
        if not os.path.exists(temp_all_certs) or os.path.getsize(temp_all_certs) == 0:
            raise TestExecError(f"Failed to retrieve certificates from {server_name}")

        last_begin_cmd = (
            f"grep -n 'BEGIN CERTIFICATE' {temp_all_certs} | tail -1 | cut -d: -f1"
        )
        last_begin_output = utils.exec_shell_cmd(last_begin_cmd)
        last_begin_line = last_begin_output.strip() if last_begin_output else ""
        if not last_begin_line or not last_begin_line.isdigit():
            error_msg = f"Could not find BEGIN CERTIFICATE in {temp_all_certs}"
            if os.path.exists(temp_all_certs):
                error_msg += f". File size: {os.path.getsize(temp_all_certs)} bytes"
            raise TestExecError(error_msg)

        cmd_extract_last = f"sed -n '{last_begin_line},/END CERTIFICATE/p' {temp_all_certs} > {cert_file}"
        utils.exec_shell_cmd(cmd_extract_last)
        utils.exec_shell_cmd(f"rm -f {temp_all_certs}")
        if not os.path.exists(cert_file) or os.path.getsize(cert_file) == 0:
            raise TestExecError(
                f"Failed to extract certificate. File {cert_file} is empty or missing"
            )

        cmd = f"openssl x509 -in {cert_file} -fingerprint -sha1 -noout"
        output = utils.exec_shell_cmd(cmd)
        if not output:
            raise TestExecError("Failed to get certificate thumbprint")

        thumbprint = output.split("=")[1].strip().replace(":", "")
        log.info(f"Successfully obtained thumbprint: {thumbprint}")
        utils.exec_shell_cmd(f"rm -f {cert_file}")
        return thumbprint

    except Exception as e:
        if os.path.exists(cert_file):
            utils.exec_shell_cmd(f"rm -f {cert_file}")
        if os.path.exists("/tmp/ibm_all_certs.crt"):
            utils.exec_shell_cmd(f"rm -f /tmp/ibm_all_certs.crt")
        raise TestExecError(f"Error getting thumbprint: {e}")


def get_jwt_client_id(jwt_token):
    """
    Extract client_id from JWT token

    Args:
        jwt_token (str): JWT token

    Returns:
        str: Client ID from JWT
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            raise TestExecError("Invalid JWT token format")

        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        payload_json = json.loads(decoded)
        client_id = payload_json.get("client_id", "")
        log.info(f"Extracted client_id: {client_id}")
        return client_id
    except Exception as e:
        raise TestExecError(f"Failed to extract client_id: {e}")


def create_oidc_provider_ibm_iam(iam_client, oidc_url, client_id, thumbprint):
    """
    Create OIDC provider for IBM IAM

    Args:
        iam_client: IAM client object
        oidc_url (str): OIDC provider URL
        client_id (str): Client ID from JWT
        thumbprint (str): Certificate thumbprint

    Returns:
        dict: OIDC provider response
    """
    log.info(f"Creating OIDC provider: {oidc_url}")

    try:
        oidc_response = iam_client.create_open_id_connect_provider(
            Url=oidc_url,
            ClientIDList=[client_id],
            ThumbprintList=[thumbprint],
        )
        log.info("OIDC provider created")
        return oidc_response

    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            log.info("OIDC provider already exists, deleting and recreating...")
            try:
                provider_arn = f"arn:aws:iam:::oidc-provider/{oidc_url.replace('https://', '').replace('http://', '')}"
                iam_client.delete_open_id_connect_provider(
                    OpenIDConnectProviderArn=provider_arn
                )
                time.sleep(2)
            except Exception as del_e:
                log.warning(f"Error deleting existing provider: {del_e}")
            oidc_response = iam_client.create_open_id_connect_provider(
                Url=oidc_url,
                ClientIDList=[client_id],
                ThumbprintList=[thumbprint],
            )
            log.info(f"OIDC provider recreated: {oidc_response}")
            return oidc_response

        else:
            raise

