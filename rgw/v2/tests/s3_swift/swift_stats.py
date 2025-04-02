"""
swift_stats - Test swift stat command is working for more than 1000 buckets

Usage: swift_stats.py -c <input_yaml>

<input_yaml>
        swift_stats.yaml

Operation:
    Create tenanted user
    Set max bucket count to 2000
    Create number of buckets mentioned in swift_stats.yaml
    Check swift stat command executing and giving status
"""

import os
import subprocess
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import traceback

import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()

    user_names = ["max", "scooby", "tubyst"]
    tenant = "tenant"
    #added a check if the user already exist, removing and recreating if if its existing
    try:
        cmd = f"radosgw-admin user info --uid={user_names[0]} --tenant={tenant}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        exit_code = process.returncode
        user_check = stdout.decode('utf-8')
        log.info(f"Checking if user exists already:\n{user_check}")

        if "user_id" in user_check:  # if User exists
            log.info(f"User tenant${user_names[0]} already exists, removing and recreating.")
            cmd = f"radosgw-admin user rm --uid={user_names[0]} --tenant={tenant} --purge-data"
            utils.exec_shell_cmd(cmd)

        tenant_user_info = umgmt.create_tenant_user(
            tenant_name=tenant, user_id=user_names[0], displayname=user_names[0]
        )
    except RGWBaseException as e:
        log.error(f"Failed to create tenant user: {e}")
        raise e
    enable_user_quota = utils.exec_shell_cmd(cmd)
    cmd = "radosgw-admin quota set --quota-scope=user --uid={uid} --tenant={tenant} --max_buckets=2000".format(
        uid=user_names[0], tenant=tenant
    )
    max_bucket = utils.exec_shell_cmd(cmd)
    auth = Auth(user_info, ssh_con)
    rgw = auth.do_auth()
    for cc in range(config.container_count):
        container_name = utils.gen_bucket_name_from_userid(
            user_info["user_id"], rand_no=cc
        )
        container = swiftlib.resource_op(
            {"obj": rgw, "resource": "put_container", "args": [container_name]}
        )
        if container is False:
            raise TestExecError("Resource execution failed: container creation failed")

    host, ip = utils.get_hostname_ip(ssh_con)
    port = utils.get_radosgw_port_no(ssh_con)
    hostname = str(ip) + ":" + str(port)
    cmd = "venv/bin/swift -A http://{hostname}/auth/1.0 -U '{uid}' -K '{key}' stat".format(
        hostname=hostname, uid=user_info["user_id"], key=user_info["key"]
    )
    swift_cmd = utils.exec_shell_cmd(cmd)
    swift_cmd = swift_cmd.replace(" ", "")
    swift_cmd = swift_cmd.replace("\n", ":")
    li = list(swift_cmd.split(":"))
    res_dct = {li[i]: li[i + 1] for i in range(0, len(li) - 1, 2)}

    if int(res_dct["Containers"]) == config.container_count:
        cmd = "radosgw-admin user rm --uid={uid} --tenant={tenant} --purge-data".format(
            uid=user_names[0], tenant=tenant
        )
        delete_user_bucket = utils.exec_shell_cmd(cmd)
        test_info.success_status("test passed")
        sys.exit(0)
    else:
        cmd = "radosgw-admin user rm --uid={uid} --tenant={tenant} --purge-data".format(
            uid=user_names[0], tenant=tenant
        )
        delete_user_bucket = utils.exec_shell_cmd(cmd)
        test_info.failed_status("test failed")
        sys.exit(1)


if __name__ == "__main__":

    test_info = AddTestInfo("swift stats")

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
