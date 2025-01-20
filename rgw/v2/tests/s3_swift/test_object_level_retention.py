""" test_object_lock.py - Test object lock configuration at a object level

Polarion ID : CEPH-83574058
Usage: test_object_level_retention.py -c <input_yaml>

<input_yaml>
	test_object_level_compliance.yaml
    test_object_level_governance.yaml

Operation:
    Create bucket with bucket lock enabled
    Upload object to the bucket with compliance mode with retention date set
    Upload another object in same bucket with governance mode
    Verify overwriting of these objects is not allowed
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import logging
import traceback

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
                rgw_ip_and_port = get_rgw_ip_and_port(ssh_con)
                s3_conn_client.create_bucket(
                    Bucket=bucket_name_to_create, ObjectLockEnabledForBucket=True
                )
                if config.test_ops["create_object"] is True:
                    # uploading data in mentioned mode
                    if config.test_ops["object_compliance"]:
                        lock_mode = "COMPLIANCE"
                    else:
                        lock_mode = "GOVERNANCE"

                    # defining retain until date for longer
                    retain_until = "2030-01-01T00:00:00"
                    log.info(f"s3 objects to create: {config.objects_count}")
                    for oc, size in list(config.mapped_sizes.items()):
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, 0
                        )
                        log.info(f"s3 object name: {s3_object_name}")
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info(f"s3 object path: {s3_object_path}")
                        log.info(f"upload type: normal with lock mode {lock_mode}")
                        io_generator(TEST_DATA_PATH + "/" + s3_object_name, size)
                        obj_body = TEST_DATA_PATH + "/" + s3_object_name
                        reusable.object_lock_retention(
                            s3_conn_client,
                            bucket_name_to_create,
                            s3_object_name,
                            obj_body,
                            lock_mode,
                            retain_until,
                        )

                log.info("Try to delete the uploaded object versions")
                versions = s3_conn_client.list_object_versions(
                    Bucket=bucket_name_to_create
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

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test object lock configuration at a object level")
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
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
