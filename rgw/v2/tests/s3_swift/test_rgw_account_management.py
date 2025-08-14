"""
This script test the rgw accounts feature for various account management scenarios
1. when a legacy rgw user having bucket and objects is migrated to an rgw account with any IO failure
2. Account ownership change not supported for rgw users in the 2 separate accounts
3. Future work : testing the account quota management
The script is test_rgw_account_management.py
The Input yamls are
# configs/test_account_ownership_change_user_adoption.yaml
# multisite_configs/test_rgw_accounts_at_scale.yaml
# multisite_configs/test_scale_aws_transition_retain_true.yaml

Usage  is test_rgw_account_management.py -c  <path_to_config_file>

"""

import concurrent.futures
import os
import random
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import quota_management as quota_mgmt
from v2.tests.s3_swift.reusables import rgw_accounts as accounts
from v2.tests.s3_swift.reusables import rgw_s3_elbencho as elbencho
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

TEST_DATA_PATH = None
import logging

log = logging.getLogger()


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)

    io_info_initialize.initialize(basic_io_structure.initial())

    if config.test_ops.get("test_via_rgw_accounts", False) is True:
        # create rgw account, account root user, iam user and return iam user details
        tenant_name = config.test_ops.get("tenant_name")
        region = config.test_ops.get("region")
        all_users_info = accounts.create_rgw_account_with_iam_user(
            config,
            tenant_name,
            region,
        )
    else:
        log.info(f"Creating {config.user_count} users")
        all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        log.info(f"Creating {config.bucket_count} buckets for {each_user['user_id']}")
        user_buckets = []  # Store buckets for this user
        if config.test_ops.get("reuse_account_bucket", False) is True:
            life_cycle_rule = {"Rules": config.lifecycle_conf}
            reusable.prepare_for_bucket_lc_transition(config)
            bucket = accounts.reuse_account_bucket(config, rgw_conn, each_user)
            reusable.configure_rgw_lc_settings()
            reusable.put_get_bucket_lifecycle_test(
                bucket, rgw_conn, rgw_conn2, life_cycle_rule, config
            )
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            user_buckets.append(bucket_name)
            bucket = reusable.create_bucket(
                bucket_name, rgw_conn, each_user, ip_and_port
            )

            if config.test_ops.get("enable_version", False):
                log.info("Enable bucket versioning")
                reusable.enable_versioning(
                    bucket, rgw_conn, each_user, write_bucket_io_info
                )

            # First executor for user adoption
            if config.test_ops.get("test_rgwUser_adoption_by_rgwAccount", False):
                with concurrent.futures.ThreadPoolExecutor() as user_adoption_executor:
                    log.info("Modify the user to an RGW account")
                    user_adoption_future = user_adoption_executor.submit(
                        accounts.perform_user_adoption, config, each_user, bucket
                    )

            # Second executor for object uploads
            with concurrent.futures.ThreadPoolExecutor() as upload_executor:
                futures = []

                if config.test_ops.get("create_object", False):
                    log.info(f"S3 objects to create: {config.objects_count}")

                    if (
                        not hasattr(config, "mapped_sizes")
                        or config.mapped_sizes is None
                    ):
                        log.warning(
                            "config.mapped_sizes is not set. Generating default sizes."
                        )
                        config.mapped_sizes = {
                            f"object_{i}": random.randint(
                                config.objects_size_range["min"],
                                config.objects_size_range["max"],
                            )
                            * 1024
                            for i in range(config.objects_count)
                        }

                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                        log.info(f"S3 object name: {s3_object_name}")
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info(f"S3 object path: {s3_object_path}")

                        time.sleep(0.5)  # Slow down upload operations

                        if config.test_ops.get("upload_type") == "multipart":
                            log.info("Upload type: multipart")
                            futures.append(
                                upload_executor.submit(
                                    reusable.upload_mutipart_object,
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )
                            )
                        else:
                            if config.test_ops.get("enable_version", False):
                                futures.append(
                                    upload_executor.submit(
                                        reusable.upload_version_object,
                                        config,
                                        each_user,
                                        rgw_conn,
                                        s3_object_name,
                                        config.obj_size,
                                        bucket,
                                        TEST_DATA_PATH,
                                    )
                                )
                            else:
                                log.info("Upload type: normal")
                                futures.append(
                                    upload_executor.submit(
                                        reusable.upload_object,
                                        s3_object_name,
                                        bucket,
                                        TEST_DATA_PATH,
                                        config,
                                        each_user,
                                    )
                                )

                concurrent.futures.wait(futures)
            if config.test_ops.get("test_account_ownership_change", False):
                log.info(
                    "Test RGW account ownership change of 2 RGW users belonging to different accounts."
                )
                accounts.account_ownership_change(config)

        if config.test_ops.get("put_object_elbencho", False):
            time.sleep(30)
            elbencho.elbencho_run_put_workload(each_user, user_buckets, config)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("Ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test RGW account management")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("Test data directory does not exist, creating it..")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW S3 Automation")
        parser.add_argument("-c", dest="config", help="RGW Test YAML configuration")
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
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("Test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("Test failed")
        sys.exit(1)
