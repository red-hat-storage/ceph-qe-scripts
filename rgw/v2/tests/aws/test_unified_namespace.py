"""
test_unified_namespace - Test Unified namespace for S3 and Swift using Keystone auth

Usage: test_keystone_auth.py
Polarion ID - CEPH-83572907
Configs - test_unified_namespace.yaml

Operation:
    Add config options necessary for keystone integration for implicit tenants S3 and Swift separately
    The keystone user exposed should be created as either a tenanted or non tenanted user based on the tenancy specified
    Create buckets and objects from the keystone user
    Test implicit tenants true and check that the bucket is accessible from both S3 and swift
"""

import argparse
import base64
import json
import logging
import os
import random
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
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

    rgw_service_name = utils.exec_shell_cmd("ceph orch ls | grep rgw").split(" ")[0]
    log.info(f"rgw service name is {rgw_service_name}")

    keystone_url = utils.exec_shell_cmd("ceph config dump | grep keystone_url").split()[
        3
    ]
    keystone_server = keystone_url.replace("http://", "").split(":")[0]
    # Put keystone conf options for user demo and implicit tenants Swift only
    log.info("Interating with Keystone for implicit tenants Swift only")
    aws_reusable.put_keystone_conf(rgw_service_name, "demo", "demo1", "demo", "swift")

    access_demo, secret_demo, project_demo = aws_reusable.get_ec2_details(
        keystone_server, "demo"
    )

    # Do a awscli query with keystone credentials
    rgw_port = utils.get_radosgw_port_no(ssh_con)
    rgw_host, rgw_ip = utils.get_hostname_ip(ssh_con)
    aws_auth.install_aws()

    # cleanup any stale swift endpoints
    aws_reusable.cleanup_keystone(keystone_server)

    count = 0
    while count < 2:
        cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 ls --endpoint http://{rgw_ip}:{rgw_port}"
        utils.exec_shell_cmd(cmd)
        time.sleep(5)
        cmd = f"radosgw-admin user list"
        users = json.loads(utils.exec_shell_cmd(cmd))
        if project_demo not in users:
            count += 1
            if count == 2:
                raise RGWBaseException("Keystone user not present in RGW user list")
            log.info("Retrying to get keystone user in 20 seconds")
            time.sleep(20)
        else:
            for line in users:
                if "$" in line and line.split("$")[0] == line.split("$")[1]:
                    raise RGWBaseException("Tenanted user is exposed by keystone")
            log.info("Non tenanted keystone user as expected")
            break

    # Create a bucket on the Keystone user
    for bc in range(config.bucket_count):
        bucket_name = "keystone" + str(bc)
        cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 mb s3://{bucket_name} --endpoint http://{rgw_ip}:{rgw_port} --region us-east-1"
        out = utils.exec_shell_cmd(cmd)
        log.info("Bucket created: " + bucket_name)
        for obj in range(config.objects_count):
            utils.exec_shell_cmd(f"fallocate -l 1K object{obj}")
            cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 cp object{obj} s3://{bucket_name}/object{obj} --endpoint http://{rgw_ip}:{rgw_port} --region us-east-1"
            out = utils.exec_shell_cmd(cmd)
            log.info("Object created on the bucket owned by Keystone user")
        cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 ls s3://{bucket_name} --endpoint http://{rgw_ip}:{rgw_port}"
        out = utils.exec_shell_cmd(cmd)
        log.info(f"Listing bucket {bucket_name}: {out}")

    log.info("Switching to implicit Tenant S3 only")
    aws_reusable.put_keystone_conf(rgw_service_name, "demo", "demo1", "demo", "s3")
    cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 ls --endpoint http://{rgw_ip}:{rgw_port}"
    utils.exec_shell_cmd(cmd)
    time.sleep(2)
    cmd = f"radosgw-admin user list"
    users = json.loads(utils.exec_shell_cmd(cmd))
    for line in users:
        if "$" in line and line.split("$")[0] == line.split("$")[1]:
            tenant1 = line
            log.info("Tenanted user created as expected")
    if not tenant1:
        raise RGWBaseException("Keystone user not present in RGW user list")

    # Create a bucket on the Keystone user
    for bc in range(config.bucket_count):
        bucket_name = "keystone" + str(bc)
        cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 mb s3://{bucket_name} --endpoint http://{rgw_ip}:{rgw_port} --region us-east-1"
        out = utils.exec_shell_cmd(cmd)
        log.info("Bucket created: " + bucket_name)
        for obj in range(config.objects_count):
            utils.exec_shell_cmd(f"fallocate -l 1K object{obj}")
            cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 cp object{obj} s3://{bucket_name}/object{obj} --endpoint http://{rgw_ip}:{rgw_port} --region us-east-1"
            out = utils.exec_shell_cmd(cmd)
            log.info("Object created on the bucket owned by Keystone user")
        cmd = f"AWS_ACCESS_KEY_ID={access_demo} AWS_SECRET_ACCESS_KEY={secret_demo} /usr/local/bin/aws s3 ls s3://{bucket_name} --endpoint http://{rgw_ip}:{rgw_port}"
        out = utils.exec_shell_cmd(cmd)
        log.info(f"Listing bucket {bucket_name}: {out}")

    log.info("Moving to implicit tenant true or both S3 and swift on a different user")
    aws_reusable.put_keystone_conf(
        rgw_service_name, "admin", "admin123", "admin", "true"
    )

    acc_admin, sec_admin, project_admin = aws_reusable.get_ec2_details(
        keystone_server, "admin"
    )

    count = 0
    while count < 2:
        cmd = f"AWS_ACCESS_KEY_ID={acc_admin} AWS_SECRET_ACCESS_KEY={sec_admin} /usr/local/bin/aws s3 ls --endpoint http://{rgw_ip}:{rgw_port}"
        utils.exec_shell_cmd(cmd)
        time.sleep(3)
        cmd = f"radosgw-admin user list"
        users = json.loads(utils.exec_shell_cmd(cmd))
        for line in users:
            if "$" in line and line.split("$")[0] == project_admin:
                tenant1 = line
                log.info("Tenanted user created as expected")
        if tenant1:
            break
        else:
            count += 1
            if count == 2:
                raise RGWBaseException("Keystone user not present in RGW user list")
            log.info("Retrying to get keystone user in 20 seconds")
            time.sleep(20)

    # Create a bucket on the Keystone user
    for bc in range(config.bucket_count):
        bucket_name = "keystone" + str(bc)
        cmd = f"AWS_ACCESS_KEY_ID={acc_admin} AWS_SECRET_ACCESS_KEY={sec_admin} /usr/local/bin/aws s3 mb s3://{bucket_name} --endpoint http://{rgw_ip}:{rgw_port} --region us-east-1"
        out = utils.exec_shell_cmd(cmd)
        log.info("Bucket created: " + bucket_name)
        for obj in range(config.objects_count):
            utils.exec_shell_cmd(f"fallocate -l 1K object{obj}")
            cmd = f"AWS_ACCESS_KEY_ID={acc_admin} AWS_SECRET_ACCESS_KEY={sec_admin} /usr/local/bin/aws s3 cp object{obj} s3://{bucket_name}/object{obj} --endpoint http://{rgw_ip}:{rgw_port} --region us-east-1"
            out = utils.exec_shell_cmd(cmd)
            log.info("Object created on the bucket owned by Keystone user")
        cmd = f"AWS_ACCESS_KEY_ID={acc_admin} AWS_SECRET_ACCESS_KEY={sec_admin} /usr/local/bin/aws s3 ls s3://{bucket_name} --endpoint http://{rgw_ip}:{rgw_port}"
        out = utils.exec_shell_cmd(cmd)
        log.info(f"Listing bucket {bucket_name}: {out}")

    log.info(
        "Check if the S3 bucket created on implicit_tenant=true is accessible on swift also and vice versa"
    )
    sw_bucket = aws_reusable.verify_namespace_swift(
        keystone_server, bucket_name, rgw_ip, rgw_port, "admin"
    )
    cmd = f"AWS_ACCESS_KEY_ID={acc_admin} AWS_SECRET_ACCESS_KEY={sec_admin} /usr/local/bin/aws s3 ls --endpoint http://{rgw_ip}:{rgw_port}"
    out = utils.exec_shell_cmd(cmd)
    if sw_bucket in out:
        log.info("Bucket created from Swift visible to S3 also")
    else:
        raise TestExecError("Swift bucket not visible to S3, diverged namespace")

    # cleanup swift endpoints
    aws_reusable.cleanup_keystone(keystone_server)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("S3 and swift unified namespace using Keystone")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="S3 and swift unified namespace using Keystone"
        )
        parser.add_argument(
            "-c", dest="config", help="S3 and swift unified namespace using Keystone"
        )
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        parser.add_argument(
            "--cloud-type", dest="cloud_type", help="IBMC or RHOSD", default="openstack"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        cloud_type = args.cloud_type
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
