""" test_tenant_user_secret_key - Test tenanted user with secret key generated using 'gen-secret'.

Usage: test_tenant_user_secret_key.py.py -c <input_yaml>

<input_yaml>
	Note: Any one of these yamls can be used
	test_tenantuser_secretkey_gen.yaml
Operation:
	Create a tenanted user and create subuser with 'gen-secret' parameter and verify upload objects succeeds.
"""
# test tenant user generate secret key
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import random
import traceback

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

TEST_DATA_PATH = None
import logging

log = logging.getLogger()


# create user
# create subuser
# gen secret-key
# create container
# upload object


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # preparing data
    user_names = ["tuffy", "scooby", "max"]
    tenant1 = "tenant" + "_" + str(random.randrange(1, 100))
    cmd = 'radosgw-admin user create --uid=%s --display-name="%s" --tenant=%s' % (
        user_names[0],
        user_names[0],
        tenant1,
    )
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW User creation error")
    log.info("output :%s" % out)
    v1_as_json = json.loads(out)
    log.info("creted user_id: %s" % v1_as_json["user_id"])
    cmd2 = (
        "radosgw-admin subuser create --uid=%s$%s --subuser=%s:swift --tenant=%s --access=full"
        % (tenant1, user_names[0], user_names[0], tenant1)
    )
    out2 = utils.exec_shell_cmd(cmd2)
    if out2 is False:
        raise TestExecError("sub-user creation error")
    v2_as_json = json.loads(out2)
    log.info("created subuser: %s" % v2_as_json["subusers"][0]["id"])
    cmd3 = (
        "radosgw-admin key create --subuser=%s:swift --uid=%s$%s --tenant=%s --key-type=swift --gen-secret"
        % (user_names[0], user_names[0], tenant1, tenant1)
    )
    out3 = utils.exec_shell_cmd(cmd3)
    if out3 is False:
        raise TestExecError("secret_key gen error")
    v3_as_json = json.loads(out3)
    log.info(
        "created subuser: %s\nsecret_key generated: %s"
        % (
            v3_as_json["swift_keys"][0]["user"],
            v3_as_json["swift_keys"][0]["secret_key"],
        )
    )
    user_info = {
        "user_id": v3_as_json["swift_keys"][0]["user"],
        "key": v3_as_json["swift_keys"][0]["secret_key"],
    }
    auth = Auth(user_info, ssh_con, is_secure=config.ssl)
    rgw = auth.do_auth()
    for cc in range(config.container_count):
        container_name = utils.gen_bucket_name_from_userid(
            user_info["user_id"], rand_no=cc
        )
        container = swiftlib.resource_op(
            {"obj": rgw, "resource": "put_container", "args": [container_name]}
        )
        if container is False:
            raise TestExecError("Resource execution failed: container creation faield")
        for oc, size in list(config.mapped_sizes.items()):
            swift_object_name = utils.gen_s3_object_name(
                "%s.container.%s" % (user_names[0], cc), oc
            )
            log.info("object name: %s" % swift_object_name)
            object_path = os.path.join(TEST_DATA_PATH, swift_object_name)
            log.info("object path: %s" % object_path)
            data_info = manage_data.io_generator(object_path, size)
            if data_info is False:
                TestExecError("data creation failed")
            log.info("uploading object: %s" % object_path)
            with open(object_path, "r") as fp:
                rgw.put_object(
                    container_name,
                    swift_object_name,
                    contents=fp.read(),
                    content_type="text/plain",
                )
    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test swift user key gen")
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
