""" test_bypass_governance_retention.py

Usage: test_bypass_governance_retention.py -c <input_yaml>

<input_yaml>
    configs/test_bypass_governance_retention_reef.yaml
    configs/test_bypass_governance_retention.yaml

Operation:
    Create an owner and a second user.
    The owner creates a bucket with object lock enabled.
    Upload an object with GOVERNANCE retention still in the future.
    The owner deletes that version with no bypass flag. This must be
    AccessDenied, forbidden by object lock.
    The owner deletes that version with BypassGovernanceRetention and no
    bucket policy. This must succeed.
    Upload a second GOVERNANCE object.
    The owner allows the second user only s3:DeleteObjectVersion.
    The second user deletes that version with the bypass flag.
    test_ops.non_owner_bypass_without_permission selects the expected result:
        true: the delete succeeds, then a new GOVERNANCE object is uploaded
        false: AccessDenied, forbidden by object lock, and that version stays
    The owner also allows s3:BypassGovernanceRetention.
    The second user deletes with the bypass flag again. This must succeed.
    When the first non-owner delete removed the version, the second delete
    targets the newly uploaded object. Otherwise it retries the same version.
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import traceback
from datetime import datetime, timedelta

import botocore.exceptions as boto3exception
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import (
    AccessDeniedObjectDeleted,
    RGWBaseException,
    TestExecError,
)
from v2.lib.manage_data import io_generator
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None
LOCK_MODE = "GOVERNANCE"
OBJECT_LOCK_DENIAL = "forbidden by object lock"


def retain_until_date():
    retain_until = datetime.now() + timedelta(days=1)
    return retain_until.isoformat("T", "seconds")


def upload_governance_object(client, bucket, object_index):
    retain_until = retain_until_date()
    key = utils.gen_s3_object_name(bucket, object_index)
    object_path = os.path.join(TEST_DATA_PATH, key)
    log.info(f"Upload {key} in {LOCK_MODE} mode until {retain_until}")
    io_generator(object_path, "9640")
    reusable.object_lock_retention(
        client,
        bucket,
        key,
        object_path,
        LOCK_MODE,
        retain_until,
    )
    version_id = object_version_id(client, bucket, key)
    log.info(f"Uploaded {key} version {version_id}")
    return key, version_id


def object_version_id(client, bucket, key):
    response = client.list_object_versions(Bucket=bucket, Prefix=key)
    versions = [version for version in response.get("Versions", []) if version["Key"] == key]
    for version in versions:
        if version.get("IsLatest"):
            return version["VersionId"]
    if versions:
        return versions[0]["VersionId"]
    raise TestExecError(f"No version found for {key}")


def delete_version(client, bucket, key, version_id, bypass):
    kwargs = {
        "Bucket": bucket,
        "Key": key,
        "VersionId": version_id,
    }
    if bypass:
        kwargs["BypassGovernanceRetention"] = True
    return client.delete_object(**kwargs)


def error_detail(error):
    code = error.response.get("Error", {}).get("Code")
    message = error.response.get("Error", {}).get("Message") or ""
    return code, message


def expect_lock_denial(client, bucket, key, version_id, bypass):
    try:
        delete_version(client, bucket, key, version_id, bypass)
    except boto3exception.ClientError as error:
        code, message = error_detail(error)
        log.info(f"Delete refused: {code}: {message}")
        if code != "AccessDenied" or OBJECT_LOCK_DENIAL not in message.lower():
            raise TestExecError(
                f"Expected AccessDenied containing '{OBJECT_LOCK_DENIAL}', "
                f"got {code}: {message}"
            )
        return
    raise AccessDeniedObjectDeleted(
        f"Delete of {key} version {version_id} succeeded; "
        "object lock should have refused it"
    )


def expect_delete(client, bucket, key, version_id, bypass):
    try:
        delete_version(client, bucket, key, version_id, bypass)
    except boto3exception.ClientError as error:
        code, message = error_detail(error)
        raise TestExecError(
            f"Delete of {key} version {version_id} was refused: {code}: {message}"
        )
    log.info(f"Deleted {key} version {version_id}")


def put_version_delete_policy(owner_client, bucket, user_id, actions):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam:::user/{user_id}"},
                "Action": actions,
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    log.info(f"Bucket policy for {user_id}: {actions}")
    owner_client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    if "non_owner_bypass_without_permission" not in config.test_ops:
        raise TestExecError(
            "test_ops.non_owner_bypass_without_permission is required"
        )
    non_owner_bypass_without_permission = config.test_ops[
        "non_owner_bypass_without_permission"
    ]
    log.info(
        "Non-owner delete with only s3:DeleteObjectVersion is expected to "
        f"{'succeed' if non_owner_bypass_without_permission else 'be refused'}"
    )

    users = s3lib.create_users(config.user_count)
    if not users or len(users) < 2:
        raise TestExecError("test requires two RGW users")
    owner_info = users[0]
    other_info = users[1]
    owner = Auth(owner_info, ssh_con, ssl=config.ssl).do_auth_using_client()
    other = Auth(other_info, ssh_con, ssl=config.ssl).do_auth_using_client()

    bucket = utils.gen_bucket_name_from_userid(owner_info["user_id"], rand_no=0)
    log.info(f"creating bucket with object lock enabled: {bucket}")
    owner.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)

    key, version_id = upload_governance_object(owner, bucket, 0)
    log.info("Owner deletes with no bypass flag and no bucket policy")
    expect_lock_denial(owner, bucket, key, version_id, bypass=False)
    log.info("Owner deletes with the bypass flag and no bucket policy")
    expect_delete(owner, bucket, key, version_id, bypass=True)

    key, version_id = upload_governance_object(owner, bucket, 1)
    put_version_delete_policy(
        owner,
        bucket,
        other_info["user_id"],
        ["s3:DeleteObjectVersion"],
    )
    log.info("Second user deletes with the bypass flag")
    if non_owner_bypass_without_permission:
        expect_delete(other, bucket, key, version_id, bypass=True)
    else:
        expect_lock_denial(other, bucket, key, version_id, bypass=True)

    put_version_delete_policy(
        owner,
        bucket,
        other_info["user_id"],
        ["s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"],
    )
    if non_owner_bypass_without_permission:
        log.info("Upload a new GOVERNANCE object for the second non-owner delete")
        key, version_id = upload_governance_object(owner, bucket, 2)
    else:
        log.info("Second non-owner delete retries the same version")
    log.info("Second user deletes with the bypass flag after the policy update")
    expect_delete(other, bucket, key, version_id, bypass=True)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Bypass governance retention for a non-owner")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        usage = """

        Usage:

          python3 test_bypass_governance_retention.py -c configs/test_bypass_governance_retention.yaml
        """
        parser = argparse.ArgumentParser(description=usage)
        parser.add_argument("-c", dest="config", help=usage)
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
