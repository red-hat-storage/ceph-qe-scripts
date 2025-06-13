"""
test_swift_all_objects_lc.py - Test Swift all type of  objects expiration

Usage: test_swift_all_objects_lc.py -c <input_yaml>
<input_yaml>
    configs/test_swift_all_objects_lc.yaml

"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import swift_reusable as sr
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
import os

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
        rgw = auth.do_auth_using_client()

    container_name = utils.gen_bucket_name_from_userid(
        user_info["user_id"], rand_no=str(3) + "new"
    )
    object_name = utils.gen_s3_object_name(f"{user_info['user_id']}.container.{1}", 1)
    rgw.put_container(container_name)

    sr.upload_regular_object(rgw, container_name, TEST_DATA_PATH)
    sr.upload_dlo(rgw, container_name, TEST_DATA_PATH)
    sr.upload_slo(rgw, container_name, TEST_DATA_PATH)
    sr.upload_multipart(rgw, container_name, TEST_DATA_PATH)
    sr.upload_encrypted_object(rgw, container_name, TEST_DATA_PATH)
    sr.upload_compressed_object(rgw, container_name, TEST_DATA_PATH)
    objects = sr.list_all_objects(rgw, container_name)
    log.info(f"All objects in container : {objects}")
    sr.execute_on_all_objects(rgw, container_name, sr.set_expiration)
    time.sleep(100)
    sr.execute_on_all_objects(rgw, container_name, sr.verify_expiration_only)

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
