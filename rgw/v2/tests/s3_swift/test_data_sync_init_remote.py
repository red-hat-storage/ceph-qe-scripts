"""
test data sync init feature at the remote site with multiple buckets resharded to 1999 shards

Usage: test_data_sync_init_remote.py -c <input_yaml>
<input_yaml>
    multisite_configs/test_data_sync_init_remote_zone.yaml


Operation:
    In a multisite environment, create a rgw user and reduce the value of rgw_max_ojs_per_shard to say 1 or 2
    Stop the remote site
    Create multiple buckets with the user creds
    Write objects to the above buckets so they are dynamically resharded to 1999 shards
    Do data sync init on the remote site and wait for metadata and data to sync
    Test the sync consistency across the sites
 

"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import json
import logging
import random
import time
import traceback
import uuid

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.sync_status import sync_status
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import (
    upload_object_via_s3client as put_object_s3client,
)
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = reusable.get_auth(each_user, ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()

        # authenticate with s3 client
        s3_client = auth.do_auth_using_client()

        # get ceph version
        ceph_version_id, ceph_version_name = utils.get_ceph_version()
        is_multisite = utils.is_cluster_multisite()
        if is_multisite:
            log.info(
                "The environment is multisite, test data sync init on the remote site."
            )
            utils.exec_shell_cmd(
                "ceph config set client.rgw.shared.pri  rgw_max_objs_per_shard 1"
            )
            utils.exec_shell_cmd("ceph orch restart rgw.shared.pri")
            remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
            stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                "ceph config set client.rgw.shared.sec  rgw_max_objs_per_shard 1"
            )
            stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                "ceph orch stop rgw.shared.sec"
            )
            # create buckets
            if config.test_ops["create_bucket"] is True:
                log.info("no of buckets to create: %s" % config.bucket_count)
                bucket_list = []
                for bc in range(config.bucket_count):
                    bucket_name_to_create = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=bc
                    )
                    bucket_list.append(bucket_name_to_create)
                    bucket = reusable.create_bucket_sync_init(
                        bucket_name_to_create, rgw_conn, each_user
                    )
                    if config.test_ops.get("enable_version", False):
                        log.info("enable bucket version")
                        reusable.enable_versioning(
                            bucket, rgw_conn, each_user, write_bucket_io_info
                        )

                    if config.test_ops["create_object"] is True:
                        # uploading data
                        log.info("s3 objects to create: %s" % config.objects_count)
                        for oc, size in list(config.mapped_sizes.items()):
                            log.info(f"print {oc}")
                            config.obj_size = size
                            s3_object_name = utils.gen_s3_object_name(
                                bucket_name_to_create, oc
                            )
                            put_object_s3client.upload_object_via_s3client(
                                s3_client,
                                bucket_name_to_create,
                                s3_object_name,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                            )

                stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                    "ceph orch start rgw.shared.sec"
                )
                stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                    "radosgw-admin data sync init --source-zone primary"
                )
                stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                    "ceph orch restart rgw.shared.sec"
                )
                log.info("Check sync status in remote site")
                sync_status(retry=30, delay=60, ssh_con=remote_site_ssh_con)
                for bucket in bucket_list:
                    log.info(f"test bucket stats for the bucket {bucket}")
                    reusable.test_bucket_stats_across_sites(bucket, config)
            log.info("Reset the rgw_max_objs_per_shard to 10 on both sites.")
            utils.exec_shell_cmd(
                "ceph config set client.rgw.shared.pri  rgw_max_objs_per_shard 10"
            )
            utils.exec_shell_cmd("ceph orch restart rgw.shared.pri")
            remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
            stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                "ceph config set client.rgw.shared.sec  rgw_max_objs_per_shard 10"
            )
            stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                "ceph orch restart rgw.shared.sec"
            )
        reusable.remove_user(each_user)
        # check for any crashes during the execution
        crash_info = reusable.check_for_crash()
        if crash_info:
            raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("test data sync init with 1999 shards")
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
