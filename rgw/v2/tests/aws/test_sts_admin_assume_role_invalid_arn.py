"""
Usage: test_sts_admin_assume_role_invalid_arn.py -c <input_yaml>

<input_yaml>
    configs/test_sts_admin_assume_role_invalid_arn.yaml

Operation:
    Regression for tracker https://tracker.ceph.com/issues/75569
    (PR https://github.com/ceph/ceph/pull/67863):

    1. Enable STS on the cluster
    2. Create an admin user and a normal (non-admin) user
    3. Create a role with path=/
    4. Admin AssumeRole with an invalid RoleArn path → must error, not crash RGW
    5. Non-admin AssumeRole with the same invalid RoleArn → AccessDenied, no crash
"""

import argparse
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None
CONNECT_LOSS = "Could not connect to the endpoint URL"

ASSUME_ROLE_POLICY_DOC = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"AWS":["*"]},"Action":"sts:AssumeRole"}]}'
)


def assert_no_crash(context):
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError(f"ceph daemon crash found after {context}!")


def assume_role_cli(role_arn, role_session_name, endpoint, ssl=False):
    cmd = (
        f"/usr/local/bin/aws sts assume-role "
        f"--role-arn '{role_arn}' "
        f"--role-session-name {role_session_name} "
        f"--endpoint-url {endpoint}"
    )
    if ssl:
        cmd = f"{cmd} --no-verify-ssl"
    return utils.exec_shell_cmd(cmd, return_err=True)


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()

    log.info("adding sts config to ceph.conf")
    session_encryption_token = "abcdefghijklmnoq"
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, session_encryption_token, ssh_con
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_s3_auth_use_sts, "True", ssh_con
    )
    # Restart via local ceph CLI; RGW nodes often lack the ceph binary.
    # Orch restart is asynchronous; allow time for all RGW daemons to come back.
    srv_restarted = rgw_service.restart()
    time.sleep(90)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    log.info("RGW service restarted")

    user_count = config.user_count if config.user_count else 2
    users_info = resource_op.create_users(no_of_users_to_create=user_count)
    admin_user, normal_user = users_info[0], users_info[1]

    utils.exec_shell_cmd(
        f'sudo radosgw-admin user modify --uid="{admin_user["user_id"]}" --admin true'
    )
    log.info(f"Promoted user {admin_user['user_id']} to admin")

    role_name = (
        f"{config.test_ops.get('role_name_prefix', 'crashtest')}."
        f"{admin_user['user_id']}"
    )
    role_session_name = config.test_ops.get("role_session_name", "test")
    invalid_path = config.test_ops.get("invalid_role_arn_path", "bogus")
    invalid_role_arn = f"arn:aws:iam:::role/{invalid_path}/{role_name}"

    log.info(f"Creating role {role_name} with path=/")
    role_create_out = utils.exec_shell_cmd(
        "sudo radosgw-admin role create "
        f"--role-name={role_name} --path=/ "
        f"--assume-role-policy-doc='{ASSUME_ROLE_POLICY_DOC}'"
    )
    if role_create_out is False:
        raise TestExecError(f"Failed to create role {role_name}")
    log.info(f"role create response: {role_create_out}")

    endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)

    # Admin AssumeRole with invalid RoleArn path (crash trigger pre-fix)
    log.info(
        f"Admin user AssumeRole with invalid RoleArn {invalid_role_arn} "
        "(must not crash RGW)"
    )
    aws_auth.do_auth_aws(admin_user)
    admin_err = assume_role_cli(
        invalid_role_arn, role_session_name, endpoint, ssl=config.ssl
    )
    log.info(f"Admin AssumeRole response/error: {admin_err}")
    if admin_err is False or (isinstance(admin_err, str) and CONNECT_LOSS in admin_err):
        raise AssertionError(
            "RGW crash seen while admin AssumeRole with invalid RoleArn "
            f"{invalid_role_arn}"
        )
    if isinstance(admin_err, str) and (
        "Credentials" in admin_err or "AccessKeyId" in admin_err
    ):
        raise TestExecError(
            "Admin AssumeRole unexpectedly succeeded with invalid RoleArn"
        )
    assert_no_crash("admin AssumeRole with invalid RoleArn")

    # Non-admin control: same invalid ARN should AccessDenied, no crash
    log.info(
        f"Normal user AssumeRole with invalid RoleArn {invalid_role_arn} "
        "(expect AccessDenied, no crash)"
    )
    aws_auth.do_auth_aws(normal_user)
    normal_err = assume_role_cli(
        invalid_role_arn, role_session_name, endpoint, ssl=config.ssl
    )
    log.info(f"Normal user AssumeRole response/error: {normal_err}")
    if normal_err is False or (
        isinstance(normal_err, str) and CONNECT_LOSS in normal_err
    ):
        raise AssertionError(
            "RGW crash seen while non-admin AssumeRole with invalid RoleArn "
            f"{invalid_role_arn}"
        )
    if not isinstance(normal_err, str) or "AccessDenied" not in normal_err:
        raise TestExecError(
            "Expected AccessDenied for non-admin AssumeRole with invalid RoleArn, "
            f"got: {normal_err}"
        )
    assert_no_crash("non-admin AssumeRole with invalid RoleArn")

    log.info(f"Cleaning up role {role_name}")
    utils.exec_shell_cmd(f"sudo radosgw-admin role delete --role-name={role_name}")
    s3_reusable.remove_user(admin_user)
    s3_reusable.remove_user(normal_user)

    assert_no_crash("test cleanup")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "STS admin AssumeRole with invalid RoleArn must not crash RGW"
    )

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW STS admin AssumeRole invalid RoleArn crash regression"
        )
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

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
