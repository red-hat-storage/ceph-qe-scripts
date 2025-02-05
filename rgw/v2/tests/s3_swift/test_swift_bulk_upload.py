"""
test_swift_bulk_upload - Test swift bulk upload operation with tar file
Usage: test_swift_bulk_upload.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_swift_bulk_upload.yaml

Operation:
    Create swift user
    Create a single container
    Uploads bulk file i.e tar file containing multiple types of files
    Verify upload success: with number of object = number of files in tar file
"""

import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import traceback

import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.tests.curl import reusable as curl_reusable
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()


TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp(ssh_con)
    log.info(type(ceph_conf))
    rgw_service = RGWService()

    # Installation of curl
    curl_reusable.install_curl(version="7.88.1")

    # user and subuser creation
    users_info = []
    user_info = swiftlib.create_users(1)[-1]
    users_info.append(user_info)
    subuser_info = swiftlib.create_non_tenant_sub_users(1, user_info)
    auth = Auth(subuser_info[-1], ssh_con, config.ssl)
    rgw = auth.do_auth()

    # container creation
    container_name = utils.gen_bucket_name_from_userid(
        user_info["user_id"], rand_no=config.container_count
    )
    container = swiftlib.resource_op(
        {"obj": rgw, "resource": "put_container", "args": [container_name]}
    )
    if container is False:
        raise TestExecError("Resource execution failed: container creation failed")

    auth_response = rgw.get_auth()
    token = auth_response[1]

    # create tar file consist of multiple files
    file_names = []
    for oc, size in list(config.mapped_sizes.items()):
        file_format_list = [".txt", ".pdf", ".bin", ".jpg", ".jpeg", ".yaml", ".py"]
        file_format = random.choice(file_format_list)
        file_name = f"file_{oc}{file_format}"
        utils.exec_shell_cmd(f"fallocate -l {size} {file_name}")
        file_names.append(file_name)

    tar_file_name = "file.tar"
    tar_cmd = f"tar -cvf {tar_file_name} "
    for file in file_names:
        if file != file_names[-1]:
            file = file + " "
        tar_cmd = tar_cmd + file

    utils.exec_shell_cmd(tar_cmd)

    # Uploading object as tar file and verifying the success
    ip_and_port = rgw.authurl.split("/")[2]
    proto = "https" if config.ssl else "http"
    url = f"{proto}://{ip_and_port}/swift/v1/{container_name}?extract-archive=tar"

    curl_cmd = f"curl -i {url} -X PUT -H 'X-Auth-Token: {token}' --data-binary @{tar_file_name}"
    utils.exec_shell_cmd(curl_cmd)

    ls = rgw.get_container(container_name)
    log.info(f"out put is {ls}")
    if int(ls[0]["x-container-object-count"]) != int(config.objects_count):
        raise AssertionError("Swift bulk upload with tar file failed!")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("RGW Swift Bulk Upload")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW Swift Bulk Upload")
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
