"""
Test NoSuchBucket error thrown for non existing bucket while applying ACL

Usage: test_acl_ops.py -c configs/<input-yaml>
where : <input-yaml> is test_acl_ops.py
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    all_users_info = s3lib.create_users(1)
    # authenticate
    auth = Auth(all_users_info[0], ssl=config.ssl)
    rgw_conn = auth.do_auth()

    if config.set_acl:
        try:
            s3_obj_acl = s3lib.resource_op(
                {
                    "obj": rgw_conn,
                    "resource": "ObjectAcl",
                    "args": ["nonexistingbucket", "nonexistingobject"],
                }
            )
            acls_set_status = s3_obj_acl.put(ACL="private")

        except ClientError as e:
            log.info(e.response)
            if (
                e.response["Error"]["Code"] == "NoSuchBucket"
                and e.response["ResponseMetadata"]["HTTPStatusCode"] == 404
            ):
                log.info("Setting acl for non existing bucket failed as expected")

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    reusable.remove_user(all_users_info[0])


if __name__ == "__main__":

    test_info = AddTestInfo("bucket life cycle: test object expiration")
    test_info.started_info()

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
        args = parser.parse_args()
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read()
        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
