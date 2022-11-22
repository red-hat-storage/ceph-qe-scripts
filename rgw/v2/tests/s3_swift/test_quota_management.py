"""test_quota_management - Test quota management

Usage: test_quota_management.py -c <input_yaml>

<input_yaml>
        Note: any one of these yamls can be used
        test_quota_bucket_max_objects.yaml
        test_quota_bucket_max_size.yaml
        test_quota_user_max_objects.yaml
        test_quota_user_max_size.yaml

Operation:
    Create non tenanted user
    Create bucket
    test bucket quota max objects
    test bucket quota max size
    test user quota max objects
    test user quota max size
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import quota_management as quota_mgmt
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

TEST_DATA_PATH = None
import logging

log = logging.getLogger()


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    log.info(f"Creating {config.user_count} users")
    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        log.info(f"Creating {config.bucket_count} buckets for {each_user['user_id']}")
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
            if config.test_ops.get("bucket_max_size"):
                quota_mgmt.test_max_size(
                    TEST_DATA_PATH,
                    "bucket",
                    config,
                    each_user,
                    bucket,
                    config.bucket_max_size,
                )

            if config.test_ops.get("bucket_max_objects"):
                quota_mgmt.test_max_objects(
                    TEST_DATA_PATH,
                    "bucket",
                    config,
                    each_user,
                    bucket,
                    config.bucket_max_objects,
                )

            if config.test_ops.get("user_max_objects"):
                quota_mgmt.test_max_objects(
                    TEST_DATA_PATH,
                    "user",
                    config,
                    each_user,
                    bucket,
                    config.user_max_objects,
                )

            if config.test_ops.get("user_max_size"):
                quota_mgmt.test_max_size(
                    TEST_DATA_PATH,
                    "user",
                    config,
                    each_user,
                    bucket,
                    config.user_max_size,
                )

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test quota management")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 Automation")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
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
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
