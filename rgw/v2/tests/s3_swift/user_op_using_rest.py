"""
user_op_using_rest - Test user operation using REST API

Usage: user_op_using_rest.py -c <input_yaml>

<input_yaml>
        test_user_with_REST.yaml

Operation:
    Create Admin user
    Using admin user, create new user using REST request
    Using admin user, Modify existing user using REST request
    Using admin user, Delete user using REST request
"""

# test REST api operation
import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import traceback

import v2.utils.utils as utils
from rgwadmin import RGWAdmin
from v2.lib.admin import UserMgmt

# import v2.lib.resource_op as swiftlib
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()


TEST_DATA_PATH = None


def randomString(stringLength=3):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(stringLength))


def s3_list(l):
    a = []
    a.append(l["user_id"])
    a.append(l["display_name"])
    a.append(l["email"])
    a.append(l["max_buckets"])
    a.append(l["keys"][0]["access_key"])
    a.append(l["keys"][0]["secret_key"])
    return a


def verify_user(api_user, regular_user):
    x = s3_list(api_user)
    y = s3_list(regular_user)
    if x == y:
        return True
    else:
        return False


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    umgmt = UserMgmt()

    host, ip = utils.get_hostname_ip(ssh_con)
    port = utils.get_radosgw_port_no(ssh_con)
    hostname = str(ip) + ":" + str(port)
    log.info(hostname)

    # preparing data
    admin_api_user = "admin_user_" + randomString()
    log.info(admin_api_user)
    user_info = umgmt.create_rest_admin_user(
        user_id=admin_api_user, displayname=admin_api_user
    )

    rgw = RGWAdmin(
        access_key=user_info["access_key"],
        secret_key=user_info["secret_key"],
        server=hostname,
        secure=False,
        verify=False,
    )

    api_user = "api_user_" + randomString()
    log.info(api_user)
    for uc in range(config.user_count):
        # Create User
        data = rgw.create_user(
            uid=api_user, display_name=api_user, email=api_user + "@abc.xyz"
        )
        log.info("User created successfully")
        log.info(data)
        log.info("verification starts")
        op = utils.exec_shell_cmd("radosgw-admin user info --uid %s" % api_user)
        json_doc = json.loads(op)
        log.info(json_doc)
        v = verify_user(data, json_doc)
        if v is False:
            test_info.failed_status("test failed")
            sys.exit(1)
        log.info("Verification for create operation completed")

        # Update User
        data = rgw.modify_user(
            uid=api_user, display_name=api_user + "_11", email=api_user + "_11@umd.edu"
        )
        log.info("User Updated successfully")
        log.info(data)
        log.info("verification starts")
        op = utils.exec_shell_cmd("radosgw-admin user info --uid %s" % api_user)
        json_doc = json.loads(op)
        log.info(json_doc)
        v = verify_user(data, json_doc)
        if v is False:
            test_info.failed_status("test failed")
            sys.exit(1)
        log.info("Verification for Update operation completed")

        # delete User
        data = rgw.remove_user(uid=api_user, purge_data=False)
        log.info(data)
        log.info("User removed")
        op = utils.exec_shell_cmd("radosgw-admin user list")
        json_doc = json.loads(op)
        if api_user in json_doc:
            test_info.failed_status("test failed")
            sys.exit(1)
        log.info("Verification for Delete operation completed")
    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test REST api operation")

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
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
