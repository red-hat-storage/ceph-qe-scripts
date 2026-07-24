"""
Test STS role policy statement field permutations for all S3 actions.

Exercises permutations of Effect, Action, Resource, Condition, and
role-only vs role+session policy for each S3 action mapped in sts_permutations.py.

Usage:
  test_sts_role_policy_field_permutations.py -c configs/test_sts_role_policy_permutations_smoke.yaml
  test_sts_role_policy_field_permutations.py -c configs/test_sts_role_policy_permutations_allow.yaml
  test_sts_role_policy_field_permutations.py -c configs/test_sts_role_policy_permutations_full.yaml

Configs:
  test_sts_role_policy_permutations_smoke.yaml   - small sampled subset
  test_sts_role_policy_permutations_allow.yaml  - Allow effect, all actions/resources
  test_sts_role_policy_permutations_deny.yaml   - Deny effect subset
  test_sts_role_policy_permutations_full.yaml   - entire cartesian product (no sampling)
"""

import argparse
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.tests.s3_swift.reusables.sts_role_policy_permutations as permutations
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    tenant_name = config.test_ops.get("tenant_name", "MountEverest")
    config.user_count = 2
    users_info = s3lib.create_tenant_users(
        tenant_name=tenant_name, no_of_users_to_create=config.user_count
    )
    owner_user, principal_user = users_info[0], users_info[1]

    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()
    session_encryption_token = config.test_ops.get(
        "sts_session_key", "abcdefghijklmnoq"
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, session_encryption_token, ssh_con
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_s3_auth_use_sts, "True", ssh_con
    )
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    log.info("RGW service restarted")

    add_caps_cmd = (
        f'sudo radosgw-admin caps add --uid="{owner_user["user_id"]}" '
        f'--tenant {tenant_name} --caps="roles=*"'
    )
    if utils.exec_shell_cmd(add_caps_cmd) is False:
        raise TestExecError("failed to add roles capability to the bucket owner")

    utils.exec_shell_cmd("fallocate -l 9KB /home/cephuser/obj9KB")
    utils.exec_shell_cmd("fallocate -l 12MB /home/cephuser/obj12MB")
    utils.exec_shell_cmd("mkdir -p /home/cephuser/obj12MB.parts/")
    utils.exec_shell_cmd(
        "split -b 6m /home/cephuser/obj12MB /home/cephuser/obj12MB.parts/"
    )

    permutations.run_sts_role_policy_permutations(
        tenant_name, owner_user, principal_user, ssh_con, config
    )

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("STS role policy field permutations for S3 actions")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s", TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW STS policy permutations")
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
