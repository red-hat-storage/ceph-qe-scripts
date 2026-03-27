"""
test_server_access_logging_multisite_collision - Test Server Access Logging in Multisite
Verifies that log object names don't collide when flushing logs from different sites
Usage: test_server_access_logging_multisite_collision.py -c <input_yaml>
<input_yaml>
    test_bucket_logging_multisite_collision.yaml
Operation:
    Verify that in multisite setup, when both primary and secondary sites
    flush log objects, they don't overwrite each other's log objects.
    This verifies BZ 2373177 fix.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback
import uuid

import botocore.exceptions
import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import server_access_logging as bkt_logging
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # Verify multisite is configured
    if not utils.is_cluster_multisite():
        raise TestExecError(
            "This test requires multisite configuration. Please set up multisite first."
        )

    # Check if we're on primary or secondary
    is_primary = utils.is_cluster_primary()
    log.info(f"Current cluster is {'primary' if is_primary else 'secondary'}")

    # Get remote site connection
    remote_zone_name = "secondary" if is_primary else "primary"
    remote_rgw_ip = utils.get_rgw_ip_zone(remote_zone_name)
    log.info(f"Remote zone: {remote_zone_name}, IP: {remote_rgw_ip}")
    remote_ssh_con = utils.connect_remote(remote_rgw_ip)

    # Determine primary and secondary connections
    # Always use primary site for bucket creation and initial setup
    if is_primary:
        primary_ssh_con = ssh_con
        secondary_ssh_con = remote_ssh_con
        primary_zone_name = "primary"
        secondary_zone_name = "secondary"
    else:
        primary_ssh_con = remote_ssh_con
        secondary_ssh_con = ssh_con
        primary_zone_name = "primary"
        secondary_zone_name = "secondary"

    # add service2 sdk extras so that bucket logging api's and respective fields are supported
    utils.add_service2_sdk_extras(
        sdk_file_location="https://github.com/ceph/ceph/blob/main/examples/rgw/boto3/service-2.sdk-extras.json?raw=true"
    )

    # create user
    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        # authenticate on primary site
        auth_primary = Auth(each_user, primary_ssh_con, ssl=config.ssl)
        rgw_conn_primary = auth_primary.do_auth()
        rgw_s3_client_primary = auth_primary.do_auth_using_client()

        # authenticate on secondary site
        auth_secondary = Auth(each_user, secondary_ssh_con, ssl=config.ssl)
        rgw_conn_secondary = auth_secondary.do_auth()
        rgw_s3_client_secondary = auth_secondary.do_auth_using_client()

        # Get primary site IP and port for bucket creation
        primary_ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(
            primary_ssh_con, config.ssl
        )

        # Create source and destination buckets on primary site
        src_bucket_name = f"src-bkt-{each_user['user_id']}"
        dest_bucket_name = f"dest-bkt-{each_user['user_id']}"

        log.info(f"Creating source bucket: {src_bucket_name} on primary site")
        src_bucket_primary = reusable.create_bucket(
            src_bucket_name, rgw_conn_primary, each_user, primary_ip_and_port
        )

        log.info(f"Creating destination bucket: {dest_bucket_name} on primary site")
        dest_bucket_primary = reusable.create_bucket(
            dest_bucket_name, rgw_conn_primary, each_user, primary_ip_and_port
        )

        # Wait for buckets to sync to secondary site
        log.info("Waiting for buckets to sync to secondary site...")
        time.sleep(10)
        reusable.verify_bucket_sync_on_other_site(secondary_ssh_con, src_bucket_primary)
        reusable.verify_bucket_sync_on_other_site(
            secondary_ssh_con, dest_bucket_primary
        )

        # Put bucket policy on dest bucket to allow logging service
        bucket_policy_generated = config.test_ops["policy_document"]
        bucket_policy = json.dumps(bucket_policy_generated)
        bucket_policy = bucket_policy.replace("<dest_bucket_name>", dest_bucket_name)
        bucket_policy = bucket_policy.replace("<source_bucket_name>", src_bucket_name)
        bucket_policy = bucket_policy.replace(
            "<source_user_name>", each_user["user_id"]
        )
        bucket_policy_generated = json.loads(bucket_policy)
        config.test_ops["policy_document"] = bucket_policy_generated

        bucket_policy_obj = s3lib.resource_op(
            {
                "obj": rgw_conn_primary,
                "resource": "BucketPolicy",
                "args": [dest_bucket_name],
            }
        )
        put_policy = s3lib.resource_op(
            {
                "obj": bucket_policy_obj,
                "resource": "put",
                "kwargs": dict(
                    ConfirmRemoveSelfBucketAccess=True, Policy=bucket_policy
                ),
            }
        )
        log.info(f"put policy response on {dest_bucket_name}: {put_policy}")
        if put_policy is False:
            raise TestExecError("Resource execution failed: put bucket policy failed")

        # Put bucket logging on primary site
        log.info(f"Putting bucket logging on {src_bucket_name} from primary site")
        bkt_logging.put_bucket_logging(
            rgw_s3_client_primary, src_bucket_name, dest_bucket_name, config
        )

        # Wait for logging config to sync
        time.sleep(5)

        # Perform operations from primary site
        log.info("Performing operations from primary site...")
        objects_created_primary = []
        for oc, size in list(config.mapped_sizes.items())[:5]:  # Create 5 objects
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(src_bucket_name, oc)
            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
            log.info(f"Creating object {s3_object_name} from primary site")
            reusable.upload_object(
                s3_object_name,
                src_bucket_primary,
                TEST_DATA_PATH,
                config,
                each_user,
            )
            objects_created_primary.append((s3_object_name, s3_object_path))

        # Flush logs from primary site
        log.info("Flushing logs from primary site...")
        tenant_name = each_user.get("tenant")
        if tenant_name:
            bucket_name_for_flush = f"{tenant_name}/{src_bucket_name}"
        else:
            bucket_name_for_flush = src_bucket_name

        cmd = (
            f"sudo radosgw-admin bucket logging flush --bucket {bucket_name_for_flush}"
        )
        out = utils.remote_exec_shell_cmd(primary_ssh_con, cmd, return_output=True)
        log.info(f"Primary site flush output: {out}")
        if out is False:
            raise TestExecError("bucket logging flush failed on primary site")

        strings_list = out.split()
        flushed_log_object_name_primary = strings_list[
            4
        ]  # fifth string is the log object name
        flushed_log_object_name_primary = flushed_log_object_name_primary[
            1:-1
        ]  # remove quotes
        log.info(f"Primary site flushed log object: {flushed_log_object_name_primary}")

        # Wait a bit before secondary operations
        time.sleep(5)

        # Perform operations from secondary site
        log.info("Performing operations from secondary site...")
        # Get bucket on secondary site
        src_bucket_secondary = s3lib.resource_op(
            {
                "obj": rgw_conn_secondary,
                "resource": "Bucket",
                "args": [src_bucket_name],
            }
        )

        objects_created_secondary = []
        for oc, size in list(config.mapped_sizes.items())[
            5:10
        ]:  # Create 5 more objects
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(src_bucket_name, oc)
            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
            log.info(f"Creating object {s3_object_name} from secondary site")
            reusable.upload_object(
                s3_object_name,
                src_bucket_secondary,  # Use bucket via secondary endpoint
                TEST_DATA_PATH,
                config,
                each_user,
            )
            objects_created_secondary.append((s3_object_name, s3_object_path))

        # Flush logs from secondary site (on remote site)
        log.info("Flushing logs from secondary site...")
        # Need to flush from secondary site, so we need to execute command on secondary
        if tenant_name:
            bucket_name_for_flush = f"{tenant_name}/{src_bucket_name}"
        else:
            bucket_name_for_flush = src_bucket_name

        cmd = (
            f"sudo radosgw-admin bucket logging flush --bucket {bucket_name_for_flush}"
        )
        out = utils.remote_exec_shell_cmd(secondary_ssh_con, cmd, return_output=True)
        log.info(f"Secondary site flush output: {out}")
        if out is False:
            raise TestExecError("bucket logging flush failed on secondary site")

        strings_list = out.split()
        flushed_log_object_name_secondary = strings_list[
            4
        ]  # fifth string is the log object name
        flushed_log_object_name_secondary = flushed_log_object_name_secondary[
            1:-1
        ]  # remove quotes
        log.info(
            f"Secondary site flushed log object: {flushed_log_object_name_secondary}"
        )

        # Wait for log objects to be written
        log.info("Waiting for log objects to be written to target bucket...")
        time.sleep(10)

        # Verify both log objects exist in the destination bucket
        log.info("Verifying log objects in destination bucket...")
        objects_list = reusable.list_bucket_objects(
            rgw_s3_client_primary, dest_bucket_name
        )

        log_object_names = [obj["Key"] for obj in objects_list]
        log.info(f"Found log objects in destination bucket: {log_object_names}")

        log.info(f"waiting for 60 seconds for sync of log objects")
        time.sleep(60)

        # Verify both log objects exist
        if flushed_log_object_name_primary not in log_object_names:
            raise TestExecError(
                f"Primary site log object {flushed_log_object_name_primary} not found in destination bucket"
            )

        if flushed_log_object_name_secondary not in log_object_names:
            raise TestExecError(
                f"Secondary site log object {flushed_log_object_name_secondary} not found in destination bucket"
            )

        # Verify log object names are different (no collision)
        if flushed_log_object_name_primary == flushed_log_object_name_secondary:
            raise TestExecError(
                f"Log object name collision detected! Both sites flushed with same name: {flushed_log_object_name_primary}"
            )

        log.info(
            f"SUCCESS: Log object names are unique. Primary: {flushed_log_object_name_primary}, Secondary: {flushed_log_object_name_secondary}"
        )

        # Verify log object name format (should have ordered integer suffix)
        log.info("Verifying log object name format...")
        bkt_logging.verify_log_object_name(
            flushed_log_object_name_primary,
            each_user["user_id"],
            src_bucket_name,
            config,
        )
        bkt_logging.verify_log_object_name(
            flushed_log_object_name_secondary,
            each_user["user_id"],
            src_bucket_name,
            config,
        )

        # Cleanup
        log.info("Cleaning up test objects...")
        reusable.delete_objects(src_bucket_primary)
        # reusable.delete_objects(src_bucket_secondary)

        # Remove user
        reusable.remove_user(each_user)


if __name__ == "__main__":
    test_info = AddTestInfo("test server access logging multisite collision")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
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
        ceph_conf = CephConfOp(ssh_con)
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

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
