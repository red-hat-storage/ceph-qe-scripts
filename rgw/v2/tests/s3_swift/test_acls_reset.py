"""
test_acls_reset.py - Test ACL operations with reset to private

Usage: test_acls_reset.py -c <input_yaml>

Operation:
    Give permissions to multiple users and then reset ACLs to private
    Test that after reset, users can no longer access the bucket
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback
import warnings

# Suppress urllib3 HeaderParsingError warnings
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")
warnings.filterwarnings("ignore", message=".*HeaderParsingError.*")
# Suppress urllib3 connection warnings in logs - set to CRITICAL to suppress all warnings
urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.setLevel(logging.CRITICAL)
logging.getLogger("urllib3.connectionpool").setLevel(logging.CRITICAL)
logging.getLogger("urllib3.connection").setLevel(logging.CRITICAL)
logging.getLogger("urllib3.util.response").setLevel(logging.CRITICAL)

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
import yaml
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec_write(config, ssh_con):
    """
    Test giving permissions to multiple users and then resetting ACLs to private
    """
    test_info = AddTestInfo("give the permission for all the users and then reset it")
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:
        # test case starts
        test_info.started_info()

        # Create users
        all_user_details = s3lib.create_users(config.user_count)
        user1 = all_user_details[0]
        log.info("user1: %s" % user1)

        # Authenticate user1
        haproxy = getattr(config, "haproxy", False)
        auth1 = reusable.get_auth(user1, ssh_con, config.ssl, haproxy)
        rgw_conn1 = auth1.do_auth()
        rgw_conn1_c = auth1.do_auth_using_client()

        # Get canonical ID of user1
        temp_bucket_name1 = utils.gen_bucket_name_from_userid(
            user1["user_id"], rand_no=999
        )
        temp_bucket1 = reusable.create_bucket(temp_bucket_name1, rgw_conn1, user1)
        acl_response1 = rgw_conn1_c.get_bucket_acl(Bucket=temp_bucket_name1)
        u1_canonical_id = acl_response1["Owner"]["ID"]
        reusable.delete_bucket(temp_bucket1)

        # User1 creates bucket
        bucket_name1 = utils.gen_bucket_name_from_userid(user1["user_id"], rand_no=0)
        bucket1 = reusable.create_bucket(bucket_name1, rgw_conn1, user1)

        # Process each other user
        all_user_details_others = all_user_details[1:]  # All users except user1
        for each_user in all_user_details_others:
            log.info("iter ------------------>")
            log.info("user2: %s" % each_user)

            # Authenticate user2
            auth2 = reusable.get_auth(each_user, ssh_con, config.ssl, haproxy)
            rgw_conn2 = auth2.do_auth()
            rgw_conn2_c = auth2.do_auth_using_client()

            # Get canonical ID of user2
            temp_bucket_name2 = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=999
            )
            temp_bucket2 = reusable.create_bucket(
                temp_bucket_name2, rgw_conn2, each_user
            )
            acl_response2 = rgw_conn2_c.get_bucket_acl(Bucket=temp_bucket_name2)
            u2_canonical_id = acl_response2["Owner"]["ID"]
            reusable.delete_bucket(temp_bucket2)

            log.info("canonical id of u2: %s" % u2_canonical_id)

            # Set READ permission for user2
            log.info("setting only read permission")
            current_acl = rgw_conn1_c.get_bucket_acl(Bucket=bucket_name1)
            grants_read = {
                "Grants": [
                    {
                        "Grantee": {
                            "ID": current_acl["Owner"]["ID"],
                            "Type": "CanonicalUser",
                        },
                        "Permission": "FULL_CONTROL",
                    },
                    {
                        "Grantee": {
                            "ID": u2_canonical_id,
                            "Type": "CanonicalUser",
                        },
                        "Permission": "READ",
                    },
                ],
                "Owner": current_acl["Owner"],
            }
            log.info("write persmission are not set")
            rgw_conn1_c.put_bucket_acl(
                Bucket=bucket_name1, AccessControlPolicy=grants_read
            )

            # User2 creates their own bucket
            bucket_name2 = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=0
            )
            bucket2 = reusable.create_bucket(bucket_name2, rgw_conn2, each_user)

            # Add bucket1 to user2's IO info so upload_object can track it
            write_bucket_info = BucketIoInfo()
            basic_io_structure = BasicIOInfoStructure()
            bucket_info = basic_io_structure.bucket(**{"name": bucket_name1})
            write_bucket_info.add_bucket_info(each_user["access_key"], bucket_info)

            # Try to upload object with user2 (should fail without WRITE permission)
            bucket1_u2 = s3lib.resource_op(
                {"obj": rgw_conn2, "resource": "Bucket", "args": [bucket_name1]}
            )
            config.mapped_sizes = utils.make_mapped_sizes(config)
            uploaded = False
            for oc, size in list(config.mapped_sizes.items())[:1]:  # Only first object
                config.obj_size = size
                s3_object_name = u2_canonical_id + ".key." + str(oc)
                try:
                    reusable.upload_object(
                        s3_object_name, bucket1_u2, TEST_DATA_PATH, config, each_user
                    )
                    uploaded = True
                except Exception as e:
                    log.info(
                        "upload failed as expected without WRITE permission: %s" % e
                    )
                    uploaded = False
                break

            if uploaded:
                raise TestExecError("object created even with no permission")
            else:
                log.info("no write permission set and hence failing to create object")

            # Set WRITE permission for user2
            log.info("setting permission to write also")
            current_acl = rgw_conn1_c.get_bucket_acl(Bucket=bucket_name1)
            grants_write = {
                "Grants": [
                    {
                        "Grantee": {
                            "ID": current_acl["Owner"]["ID"],
                            "Type": "CanonicalUser",
                        },
                        "Permission": "FULL_CONTROL",
                    },
                    {
                        "Grantee": {
                            "ID": u2_canonical_id,
                            "Type": "CanonicalUser",
                        },
                        "Permission": "WRITE",
                    },
                ],
                "Owner": current_acl["Owner"],
            }
            rgw_conn1_c.put_bucket_acl(
                Bucket=bucket_name1, AccessControlPolicy=grants_write
            )

            # Now user2 should be able to upload
            for oc, size in list(config.mapped_sizes.items())[:1]:  # Only first object
                config.obj_size = size
                s3_object_name = u2_canonical_id + ".key." + str(oc)
                reusable.upload_object(
                    s3_object_name, bucket1_u2, TEST_DATA_PATH, config, each_user
                )
                log.info("object created after permission set")
                break

        # Reset ACLs to private (remove all grants except owner)
        log.info(
            "***************** removing grants and making the bucket private *****************"
        )
        current_acl = rgw_conn1_c.get_bucket_acl(Bucket=bucket_name1)
        grants_private = {
            "Grants": [
                {
                    "Grantee": {
                        "ID": current_acl["Owner"]["ID"],
                        "Type": "CanonicalUser",
                    },
                    "Permission": "FULL_CONTROL",
                }
            ],
            "Owner": current_acl["Owner"],
        }
        rgw_conn1_c.put_bucket_acl(
            Bucket=bucket_name1, AccessControlPolicy=grants_private
        )
        log.info("bucket ACL reset to private")

        # Verify that other users can no longer upload
        for each_user in all_user_details_others:
            log.info("iter ------------------>")
            # Authenticate user2
            auth2 = reusable.get_auth(each_user, ssh_con, config.ssl, haproxy)
            rgw_conn2 = auth2.do_auth()
            rgw_conn2_c = auth2.do_auth_using_client()

            # Get bucket using user2's connection
            bucket1_u2 = s3lib.resource_op(
                {"obj": rgw_conn2, "resource": "Bucket", "args": [bucket_name1]}
            )

            # Try to upload (should fail)
            config.mapped_sizes = utils.make_mapped_sizes(config)
            uploaded = False
            for oc, size in list(config.mapped_sizes.items())[:1]:  # Only first object
                config.obj_size = size
                s3_object_name = "test_reset." + str(oc)
                try:
                    reusable.upload_object(
                        s3_object_name, bucket1_u2, TEST_DATA_PATH, config, each_user
                    )
                    uploaded = True
                except Exception as e:
                    log.info("upload failed as expected after ACL reset: %s" % e)
                    uploaded = False
                break

            if uploaded:
                raise TestExecError(
                    "object created even with no permission after reset"
                )
            else:
                log.info("no write permission set and hence failing to create object")

        test_info.success_status("test completed")
    except AssertionError as e:
        log.error(e)
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)
    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    test_info = AddTestInfo("test acls reset")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW Automation")
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
        if yaml_file is None:
            config.user_count = 2
            config.bucket_count = 2
            config.objects_count = 10
            config.objects_size_range = {"min": 10, "max": 50}
        else:
            if hasattr(config, "user_count") and config.user_count:
                pass
            else:
                config.user_count = 2
            if hasattr(config, "bucket_count") and config.bucket_count:
                pass
            else:
                config.bucket_count = 2
            if hasattr(config, "objects_count") and config.objects_count:
                pass
            else:
                config.objects_count = 10
            if hasattr(config, "objects_size_range") and config.objects_size_range:
                pass
            else:
                config.objects_size_range = {"min": 10, "max": 50}

        log.info(
            "user_count:%s\n"
            "bucket_count: %s\n"
            "objects_count: %s\n"
            "objects_size_range: %s\n"
            % (
                config.user_count,
                config.bucket_count,
                config.objects_count,
                config.objects_size_range,
            )
        )
        test_exec_write(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
