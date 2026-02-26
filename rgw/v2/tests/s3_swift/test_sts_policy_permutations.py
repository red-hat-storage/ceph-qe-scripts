"""
test_sts_using_boto_session_policy.py - Test STS using boto

Usage: test_sts_policy_permutations.py -c <input_yaml>
<input_yaml>
    configs/test_sts_role_session_policy_static.yaml


permutations:
1. same/different principal
2. with only role policy and role+session policy
2. effect: allow/deny
3. resource: arn_access_all_buckets_and_objects,
4. for each s3 action

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
import v2.tests.s3_swift.reusables.sts_permutations as sts_permutations
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

# import v2.lib.resource_op as s3lib
# import v2.tests.s3_swift.reusables.sts_permutations as sts_permutations
# import v2.utils.utils as utils
# from v2.lib.exceptions import RGWBaseException, TestExecError
# from v2.lib.resource_op import Config
# from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
# from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
# from v2.tests.s3_swift import reusable
# from v2.tests.s3cmd import reusable as s3cmd_reusable
# from v2.utils.log import configure_logging
# from v2.utils.test_desc import AddTestInfo
# from v2.utils.utils import RGWService


log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    if config.sts is None:
        raise TestExecError("sts policies are missing in yaml config")

    # create users
    config.user_count = 3
    tenant_name = "MountEverest"
    users_info = s3lib.create_tenant_users(
        tenant_name=tenant_name, no_of_users_to_create=config.user_count
    )
    # user1 is the owner
    user1, user2, user3 = users_info[0], users_info[1], users_info[2]
    auth1 = Auth(user1, ssh_con, ssl=config.ssl)
    log.info("adding sts config to ceph.conf")
    sesison_encryption_token = "abcdefghijklmnoq"
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, sesison_encryption_token, ssh_con
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_s3_auth_use_sts, "True", ssh_con
    )
    if config.test_ops.get("verify_policy"):
        ceph_config_set.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_enable_static_website,
            True,
            ssh_con,
        )
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    add_caps_cmd = f'sudo radosgw-admin caps add --uid="{user1["user_id"]}" --tenant {tenant_name} --caps="roles=*"'
    out = utils.exec_shell_cmd(add_caps_cmd)
    if out is False:
        raise Exception("failed to add roles capability to the user")

    utils.exec_shell_cmd("fallocate -l 9KB /home/cephuser/obj9KB")
    utils.exec_shell_cmd("fallocate -l 12MB /home/cephuser/obj12MB")
    utils.exec_shell_cmd("mkdir -p /home/cephuser/obj12MB.parts/")
    utils.exec_shell_cmd(
        "split -b 6m /home/cephuser/obj12MB /home/cephuser/obj12MB.parts/"
    )

    if config.test_ops.get("verify_static_sts_role_session_policy"):
        sts_permutations.test_sts_static_role_session_policy(
            tenant_name, user1, user2, ssh_con, config
        )

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "Test static sts role session policies and sts policy permutations"
    )
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 STS automation")
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
