"""
test_swift_static_large_object_expiration.py - Test expiration a Static large object. Check the time for delete

Usage: test_swift_static_large_object_expiration.py -c <input_yaml>

<input_yaml>
        swift_slo_expiry.yaml

Operation:
    Test expiration of a static large object. check after it got deleted.
    create_a_large_file
    upload segments
    create manifest file and upload
    set expiration
    verify expiration
"""

import glob
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import string
import time
import traceback
from datetime import datetime, timedelta, timezone

import names
import v2.lib.manage_data as manage_data
import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from swiftclient import ClientException
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth as s3_auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3cmd import auth as s3cmd_auth
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import swift_reusable as sr
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()


TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()

    # preparing data
    if config.user_type == "non-tenanted":
        users_info = []
        user_info = swiftlib.create_users(1)[-1]
        users_info.append(user_info)
        subuser_info = swiftlib.create_non_tenant_sub_users(
            config.container_count, user_info
        )
        auth = Auth(subuser_info[-1], ssh_con, config.ssl)
        rgw = auth.do_auth()

    if config.static_large_object_upload == True:
        container_name = utils.gen_bucket_name_from_userid(
            user_info["user_id"], rand_no=str(3) + "new"
        )
        object_name = utils.gen_s3_object_name(
            f"{user_info['user_id']}.container.{1}", 1
        )

        filename_test = "a_large_file" + sr.get_unique_name(3)
        rgw.put_container(container_name)
        sr.create_a_large_file(TEST_DATA_PATH, filename_test)

        # Upload segments and create manifest
        segments = sr.upload_segments(
            rgw,
            TEST_DATA_PATH,
            container_name,
            object_name,
            filename_test,
            segment_size=100,
        )
        sr.upload_manifest(rgw, container_name, object_name, segments)

    sr.set_expiration(rgw, container_name, object_name, expiration_after=1)

    # Checking the Download
    metadata = rgw.head_object(container_name, object_name)

    log.info(f"Metadata : {metadata}")

    swift_object_download_fname = object_name + ".download"
    log.info("download object name: %s" % swift_object_download_fname)
    swift_object_download_path = os.path.join(
        TEST_DATA_PATH, swift_object_download_fname
    )
    log.info("download object path: %s" % swift_object_download_path)
    swift_object_downloaded = rgw.get_object(container_name, object_name)
    with open(swift_object_download_path, "wb") as fp:
        fp.write(swift_object_downloaded[1])

    log.info(f"md5 of Downloaded object : {utils.get_md5(swift_object_download_path)}")

    sr.verify_expiration(rgw, container_name, object_name)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("swift slo expiration")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW SWIFT Automation")
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
        config.read(ssh_con)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
