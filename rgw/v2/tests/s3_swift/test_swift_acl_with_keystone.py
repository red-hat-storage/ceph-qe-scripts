import argparse
import logging
import os
import sys
import time
import traceback

from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import swift_reusable as sr
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

TEST_DATA_PATH = None


def create_swift_bucket_with_acl_keystone(bucket_name, rgw_ip, port, user="admin"):
    """
    Verify the unified namespace behaviour from swift
    """
    keystone_node = "10.0.209.121"
    ssh = utils.connect_remote(keystone_node)

    swift_url = f"http://{rgw_ip}:{port}/swift/v1"
    endpoints = [
        f"openstack endpoint create --region RegionOne swift internal {swift_url}",
        f"openstack endpoint create --region RegionOne swift public {swift_url}",
        f"openstack endpoint create --region RegionOne swift admin {swift_url}",
    ]

    # Prepare the common command prefix
    cmd_prefix = f"source /home/cephuser/key_{user}.rc; "

    # Run endpoint creation commands
    for endpoint_cmd in endpoints:
        cmd = cmd_prefix + endpoint_cmd
        utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)

    sw_bucket = bucket_name
    cmd = cmd_prefix + f"swift post {sw_bucket}"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)

    # List the Swift containers
    cmd = cmd_prefix + "swift list"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)

    # Create the Swift bucket

    # Swift command to set ACL for the container
    cmd = cmd_prefix + f"swift post {sw_bucket} --read-acl .r:*"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    print(out)
    # Using the token to authenticate the swift client
    cmd = cmd_prefix + f"swift stat {sw_bucket} "
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    print(out)

    cmd = cmd_prefix + f"swift post {sw_bucket} --write-acl '*:*'"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    print(out)

    cmd = cmd_prefix + f"swift stat {sw_bucket} "
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    print(out)
    #CHECK THE ACL CHANGES
    if ("Read ACL: .r:*" and "Write ACL: *:*") in out:
        print("SUCCESS")
    else:
        assert 0


def put_keystone_conf(rgw_service_name, user, passw, project, tenant="true"):
    """
    Apply the conf options required for keystone integration to rgw service
    """
    log.info("Apply keystone conf options")
    # Dictionary of the configuration options to be set
    config_options = {
        "rgw_keystone_api_version": "3",
        "rgw_keystone_url": "http://10.0.209.121:5000",
        "rgw_keystone_admin_user": user,
        "rgw_keystone_admin_password": passw,
        "rgw_keystone_admin_domain": "Default",
        "rgw_keystone_admin_project": project,
        "rgw_keystone_implicit_tenants": tenant,
        "rgw_keystone_accepted_roles": "admin,user",
    }

    # Loop through the configuration options and execute commands
    for config_key, config_value in config_options.items():
        cmd = f"ceph config set client.{rgw_service_name} {config_key} {config_value}"
        utils.exec_shell_cmd(cmd)

    # Restart RGW for the options to take effect
    log.info("Restart RGW for options to take effect")
    utils.exec_shell_cmd(f"ceph orch restart {rgw_service_name}")

    time.sleep(10)


def cleanup_keystone(user="admin"):
    """
    Delete the swift endpoints added earlier from the keystone server
    """
    keystone_node = "10.0.209.121"
    ssh = utils.connect_remote(keystone_node)
    log.info("Deleting the swift endpoints")
    cmd = f"source /home/cephuser/key_{user}.rc; openstack endpoint list"
    out = utils.remote_exec_shell_cmd(ssh, cmd, return_output=True)
    idlist = []
    for line in out.splitlines():
        if "swift" in line:
            idlist.append(line.split("|")[1].strip())

    for endpoint in idlist:
        cmd = (
            f"source /home/cephuser/key_{user}.rc; openstack endpoint delete {endpoint}"
        )
        out = utils.remote_exec_shell_cmd(ssh, cmd)


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    bucket_name = sr.get_unique_name()

    rgw_service_name = utils.exec_shell_cmd("ceph orch ls | grep rgw").split(" ")[0]
    log.info(f"rgw service name is {rgw_service_name}")
    rgw_port = utils.get_radosgw_port_no(ssh_con)
    rgw_host, rgw_ip = utils.get_hostname_ip(ssh_con)
    put_keystone_conf(rgw_service_name, "admin", "admin123", "admin", "true")
    create_swift_bucket_with_acl_keystone(
        bucket_name, rgw_ip, rgw_port, "admin"
    )
    cleanup_keystone()

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("Test to verify Keystone authentication from RGW")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW Keystone Auth using AWS")
        parser.add_argument("-c", dest="config", help="RGW Keystone Auth using AWS")
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
        config = resource_op.Config(yaml_file)
        config.read()
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

