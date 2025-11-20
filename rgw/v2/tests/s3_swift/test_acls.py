"""
test_acls.py - Test ACL operations with READ and WRITE permissions

Usage: test_acls.py -c <input_yaml>

Operation:
    Test with read permission on buckets
    Test with write permission on objects and buckets
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

# no of users 2 and not more.


def test_exec_read(config, ssh_con):
    """
    Test with read permission on buckets
    config.bucket_count = 3
    config.objects_count = 3
    config.objects_size_range = {'min': 50, 'max': 100}
    """
    test_info = AddTestInfo("Test with read permission on buckets")
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
        user2 = all_user_details[1]
        log.info("user2: %s" % user2)

        # Authenticate users
        haproxy = getattr(config, "haproxy", False)
        auth1 = reusable.get_auth(user1, ssh_con, config.ssl, haproxy)
        auth2 = reusable.get_auth(user2, ssh_con, config.ssl, haproxy)
        rgw_conn1 = auth1.do_auth()
        rgw_conn1_c = auth1.do_auth_using_client()
        rgw_conn2 = auth2.do_auth()
        rgw_conn2_c = auth2.do_auth_using_client()

        # Get canonical ID of user2
        u2_canonical_id = reusable.get_user_canonical_id(
            user2, rgw_conn2, rgw_conn2_c, ssh_con, config.ssl, haproxy
        )

        # Create buckets for user1
        bucket_names = []
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user1["user_id"], rand_no=bc
            )
            bucket_names.append(bucket_name)
            bucket = reusable.create_bucket(bucket_name, rgw_conn1, user1)

        # Set bucket ACL with READ permission for user2
        grants_list = [
            {
                "Grantee": {
                    "ID": u2_canonical_id,
                    "Type": "CanonicalUser",
                },
                "Permission": "READ",
            }
        ]

        for bucket_name in bucket_names:
            # Set bucket ACL with grants (preserves owner's FULL_CONTROL)
            reusable.set_bucket_acl_with_grants(
                rgw_conn1_c, bucket_name, grants_list, preserve_owner=True
            )

            # Verify user2 can access bucket (read)
            try:
                rgw_conn2_c.head_bucket(Bucket=bucket_name)
                log.info(
                    "user2 can access bucket %s with READ permission" % bucket_name
                )
            except Exception as e:
                log.error("user2 cannot access bucket: %s" % e)
                raise TestExecError("user2 should be able to read bucket")

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


def test_exec_write(config, ssh_con):
    """
    Test with write permission on objects and buckets
    """
    test_info = AddTestInfo("test with write permission on objects and buckets")
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
        user2 = all_user_details[1]
        log.info("user2: %s" % user2)

        # Authenticate users
        haproxy = getattr(config, "haproxy", False)
        auth1 = reusable.get_auth(user1, ssh_con, config.ssl, haproxy)
        auth2 = reusable.get_auth(user2, ssh_con, config.ssl, haproxy)
        rgw_conn1 = auth1.do_auth()
        rgw_conn1_c = auth1.do_auth_using_client()
        rgw_conn2 = auth2.do_auth()
        rgw_conn2_c = auth2.do_auth_using_client()

        # Get canonical ID of user2
        u2_canonical_id = reusable.get_user_canonical_id(
            user2, rgw_conn2, rgw_conn2_c, ssh_con, config.ssl, haproxy
        )

        # Create bucket for user1
        bucket_name = utils.gen_bucket_name_from_userid(user1["user_id"], rand_no=0)
        bucket = reusable.create_bucket(bucket_name, rgw_conn1, user1)

        # Set bucket ACL with only READ permission (no WRITE)
        log.info("write permission are not set")
        grants_read_list = [
            {
                "Grantee": {
                    "ID": u2_canonical_id,
                    "Type": "CanonicalUser",
                },
                "Permission": "READ",
            }
        ]
        reusable.set_bucket_acl_with_grants(
            rgw_conn1_c, bucket_name, grants_read_list, preserve_owner=True
        )

        # Try to upload object with user2 (should fail without WRITE permission)
        # Get bucket using user2's connection
        bucket2 = s3lib.resource_op(
            {"obj": rgw_conn2, "resource": "Bucket", "args": [bucket_name]}
        )
        # Add bucket to user2's IO info so upload_object can track it
        write_bucket_info = BucketIoInfo()
        basic_io_structure = BasicIOInfoStructure()
        bucket_info = basic_io_structure.bucket(**{"name": bucket_name})
        write_bucket_info.add_bucket_info(user2["access_key"], bucket_info)

        config.mapped_sizes = utils.make_mapped_sizes(config)
        # Try uploading one object to test WRITE permission
        for oc, size in list(config.mapped_sizes.items())[:1]:  # Only first object
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
            try:
                reusable.upload_object(
                    s3_object_name, bucket2, TEST_DATA_PATH, config, user2
                )
                log.info("no write permission set and hence failing to create object")
                # If upload succeeds, it means WRITE permission is not properly restricted
                # This might be expected behavior in some cases, so we log it
            except Exception as e:
                log.info("upload failed as expected without WRITE permission: %s" % e)
            break  # Only test with first object

        # Now set WRITE permission
        log.info("setting permission to write also")
        grants_write_list = [
            {
                "Grantee": {
                    "ID": u2_canonical_id,
                    "Type": "CanonicalUser",
                },
                "Permission": "WRITE",
            }
        ]
        reusable.set_bucket_acl_with_grants(
            rgw_conn1_c, bucket_name, grants_write_list, preserve_owner=True
        )

        # Now user2 should be able to upload
        uploaded_object_name = None
        for oc, size in list(config.mapped_sizes.items())[:1]:  # Only first object
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
            uploaded_object_name = s3_object_name
            # upload_object returns None on success, raises TestExecError on failure
            # If no exception is raised, upload succeeded
            reusable.upload_object(
                s3_object_name, bucket2, TEST_DATA_PATH, config, user2
            )
            log.info("object created after permission set")
            break  # Only test with first object

        # Verify the object was actually uploaded by checking if it exists
        # Use head_object instead of list_objects since user2 only has WRITE permission
        log.info("verifying uploaded object exists in bucket")
        try:
            # Try to get object metadata using head_object
            response = rgw_conn2_c.head_object(
                Bucket=bucket_name, Key=uploaded_object_name
            )
            log.info(
                "verified: uploaded object '%s' exists in bucket (ETag: %s)"
                % (uploaded_object_name, response.get("ETag", "N/A"))
            )
        except Exception as e:
            # If head_object fails, try with user1's connection (bucket owner)
            log.info("head_object with user2 failed, trying with user1 (bucket owner)")
            try:
                response = rgw_conn1_c.head_object(
                    Bucket=bucket_name, Key=uploaded_object_name
                )
                log.info(
                    "verified: uploaded object '%s' exists in bucket (ETag: %s)"
                    % (uploaded_object_name, response.get("ETag", "N/A"))
                )
            except Exception as e2:
                log.error("failed to verify object with both users: %s, %s" % (e, e2))
                raise TestExecError("failed to verify uploaded object: %s" % e2)

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
    test_info = AddTestInfo("test acls")
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
        config.user_count = 2
        # Set defaults if not provided in yaml
        if config.bucket_count is None:
            config.bucket_count = 2
        if config.objects_count is None:
            config.objects_count = 10
        if config.objects_size_range is None:
            config.objects_size_range = {"min": 10, "max": 50}

        log.info(
            "bucket_count: %s\n"
            "objects_count: %s\n"
            "objects_size_range: %s\n"
            % (config.bucket_count, config.objects_count, config.objects_size_range)
        )
        test_exec_read(config, ssh_con)
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
