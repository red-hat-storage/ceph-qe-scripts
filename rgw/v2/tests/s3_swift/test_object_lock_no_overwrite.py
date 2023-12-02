""" test_object_lock_no_overwrite.py - BZ 1890843
BZ 2252336 - object lock retainUntilDate can overflow (32bit seconds)
Polarion CEPH-83574059 - Negative - Verify the objects cannot be overwritten.

Usage: test_object_lock_no_overwrite.py -c <input_yaml>

<input_yaml>
	test_object_lock_no_overwrite.yaml

Operation:
    Create bucket with bucket lock enabled
    Upload key1 with 2 minutes of retention time , and try deletion before retention time passes
    Delete key1 post retention time expiry
    Upload key with 2 minutes retention in GOVERNANCE mode
    Extend retention time to 3 minutes, and try deletion before retnetion period 
    Delete key2 with bypass-governance-retention option
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import logging
import traceback
from datetime import datetime, timedelta

import botocore.exceptions as boto3exception
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import (
    AccessDeniedObjectDeleted,
    ObjectVersionCountMismatch,
    RGWBaseException,
    TestExecError,
)
from v2.lib.manage_data import io_generator
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd.reusable import get_rgw_ip_and_port
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None
password = "32characterslongpassphraseneeded".encode("utf-8")
encryption_key = hashlib.md5(password).hexdigest()


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authentication
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        s3_conn_client = auth.do_auth_using_client()
        # create buckets with object lock configuration
        if config.test_ops["create_bucket"] is True:
            log.info(f"no of buckets to create: {config.bucket_count}")
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info(f"creating bucket with name: {bucket_name_to_create}")
                s3_conn_client.create_bucket(
                    Bucket=bucket_name_to_create, ObjectLockEnabledForBucket=True
                )
                # defining retain until date as current time + 1 day
                timenow = datetime.now() + timedelta(days=1)
                retain_until = f"{timenow.isoformat('T', 'seconds')}"
                log.info(f"Retention time is " + retain_until)
                log.info(
                    f"Upload key1 with retention period of 1 day in COMPLIANCE mode"
                )
                lock_mode = "COMPLIANCE"
                s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, 0)
                log.info(f"s3 object name: {s3_object_name}")
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info(f"s3 object path: {s3_object_path}")
                log.info(f"upload type: normal with lock mode {lock_mode}")
                io_generator(TEST_DATA_PATH + "/" + s3_object_name, "9640")
                obj_body = TEST_DATA_PATH + "/" + s3_object_name
                reusable.object_lock_retention(
                    s3_conn_client,
                    bucket_name_to_create,
                    s3_object_name,
                    obj_body,
                    lock_mode,
                    retain_until,
                )
                # delete key1 before retention period expires, not allowed
                log.info("Try to delete the uploaded object versions")
                versions = s3_conn_client.list_object_versions(
                    Bucket=bucket_name_to_create, Prefix=s3_object_name
                )
                for version_dict in versions["Versions"]:
                    try:
                        s3_conn_client.delete_object(
                            Bucket=bucket_name_to_create,
                            Key=s3_object_name,
                            VersionId=version_dict["VersionId"],
                        )
                        raise AccessDeniedObjectDeleted("Access denied object deleted")
                    except boto3exception.ClientError as e:
                        expected_code = "AccessDenied"
                        actual_code = e.response["Error"]["Code"]
                        assert (
                            actual_code == expected_code
                        ), "Expected: {expected_code}, Actual: {actual_code}"
                log.info("Unable to delete the object in retention period")

                # delete key1 post retention period, unable to test as retention <1 day not allowed

                log.info("Upload key2  with GOVERNANCE mode with 1 day retention")
                timenow = datetime.now() + timedelta(days=1)
                retain_until = timenow.isoformat("T", "seconds")
                log.info(f"Retention time is " + retain_until)
                lock_mode = "GOVERNANCE"
                s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, 1)
                log.info(f"s3 object name: {s3_object_name}")
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info(f"s3 object path: {s3_object_path}")
                log.info(f"upload type: normal with lock mode {lock_mode}")
                io_generator(TEST_DATA_PATH + "/" + s3_object_name, "9640")
                obj_body = TEST_DATA_PATH + "/" + s3_object_name
                reusable.object_lock_retention(
                    s3_conn_client,
                    bucket_name_to_create,
                    s3_object_name,
                    obj_body,
                    lock_mode,
                    retain_until,
                )
                log.info("Change retention period to 2 days")
                timenow = datetime.now() + timedelta(days=2)
                retain_until = timenow.isoformat("T", "seconds")
                retention_dict = {"Mode": "GOVERNANCE", "RetainUntilDate": retain_until}
                versions = s3_conn_client.list_object_versions(
                    Bucket=bucket_name_to_create, Prefix=s3_object_name
                )
                for version_dict in versions["Versions"]:
                    reusable.change_lock_retention(
                        s3_conn_client,
                        bucket_name_to_create,
                        s3_object_name,
                        retention_dict,
                        version_dict["VersionId"],
                    )
                log.info("key2 deletion should not be allowed")
                for version_dict in versions["Versions"]:
                    try:
                        s3_conn_client.delete_object(
                            Bucket=bucket_name_to_create,
                            Key=s3_object_name,
                            VersionId=version_dict["VersionId"],
                        )
                        raise AccessDeniedObjectDeleted("Access denied object deleted")
                    except boto3exception.ClientError as e:
                        expected_code = "AccessDenied"
                        actual_code = e.response["Error"]["Code"]
                        assert (
                            actual_code == expected_code
                        ), "Expected: {expected_code}, Actual: {actual_code}"
                log.info("Unable to delete the object in retention period")
                log.info("Delete key2 with bypassgovernanceretention")
                for version_dict in versions["Versions"]:
                    s3_conn_client.delete_object(
                        Bucket=bucket_name_to_create,
                        Key=s3_object_name,
                        VersionId=version_dict["VersionId"],
                        BypassGovernanceRetention=True,
                    )
                log.info("Delete successful with BypassGovernanceRetention set")

                # BZ 2252336 - Upload object in governance mode with a very long retain date
                log.info(
                    "Upload key3  with GOVERNANCE mode with retainuntil date >=2107"
                )
                retain_until = "2141-01-01T00:00:00"
                log.info(f"Retention time is " + retain_until)
                lock_mode = "GOVERNANCE"
                s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, 1)
                log.info(f"s3 object name: {s3_object_name}")
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info(f"s3 object path: {s3_object_path}")
                log.info(f"upload type: normal with lock mode {lock_mode}")
                io_generator(TEST_DATA_PATH + "/" + s3_object_name, "9640")
                obj_body = TEST_DATA_PATH + "/" + s3_object_name
                reusable.object_lock_retention(
                    s3_conn_client,
                    bucket_name_to_create,
                    s3_object_name,
                    obj_body,
                    lock_mode,
                    retain_until,
                )
                log.info("Get the object lock configuration")
                lock_config = reusable.get_lock_configuration(
                    s3_conn_client,
                    bucket_name_to_create,
                    s3_object_name,
                )
                # check if the retain until year matches the uploaded time
                log.info("Compare the uploaded and obtained retain until time")
                log.info(
                    f"Obtained year:"
                    + lock_config["Retention"]["RetainUntilDate"].strftime("%Y")
                )
                if lock_config["Retention"]["RetainUntilDate"].strftime("%Y") == "2141":
                    log.info("Retain until date matches the uploaded time")
                else:
                    log.info("Mismatch in retain until date")
                    raise RGWBaseException("Retain until time mismatch")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Object lock with no overwrite BZ 1890843")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        usage = """

        Usage:

          python3 test_object_lock.py -c test_object_lock.yaml
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
        ceph_conf = CephConfOp(ssh_con)
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
