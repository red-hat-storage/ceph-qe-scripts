"""
test_acls_copy_obj.py - Test ACL operations with object copying between buckets

Usage: test_acls_copy_obj.py -c <input_yaml>

Operation:
    Test copying objects between buckets with ACL permissions
    User1 creates bucket with READ permission for user2
    User1 uploads objects
    User2 creates bucket with FULL_CONTROL permission for user1
    User1 copies objects from their bucket to user2's bucket
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

# only 2 users test case and 1 bucket in each user


def test_exec_read(config, ssh_con):
    """
    Test copying objects between buckets with ACL permissions
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

        # Get canonical IDs
        temp_bucket_name1 = utils.gen_bucket_name_from_userid(
            user1["user_id"], rand_no=999
        )
        temp_bucket1 = reusable.create_bucket(temp_bucket_name1, rgw_conn1, user1)
        acl_response1 = rgw_conn1_c.get_bucket_acl(Bucket=temp_bucket_name1)
        u1_canonical_id = acl_response1["Owner"]["ID"]
        reusable.delete_bucket(temp_bucket1)

        temp_bucket_name2 = utils.gen_bucket_name_from_userid(
            user2["user_id"], rand_no=999
        )
        temp_bucket2 = reusable.create_bucket(temp_bucket_name2, rgw_conn2, user2)
        acl_response2 = rgw_conn2_c.get_bucket_acl(Bucket=temp_bucket_name2)
        u2_canonical_id = acl_response2["Owner"]["ID"]
        reusable.delete_bucket(temp_bucket2)

        log.info("canonical id of u1: %s" % u1_canonical_id)
        log.info("canonical id of u2: %s" % u2_canonical_id)

        # User1 creates bucket with READ permission for user2
        bucket_name1 = utils.gen_bucket_name_from_userid(user1["user_id"], rand_no=0)
        bucket1 = reusable.create_bucket(bucket_name1, rgw_conn1, user1)

        # Set bucket ACL with READ permission for user2
        # Must include owner's FULL_CONTROL and user2's READ
        current_acl1 = rgw_conn1_c.get_bucket_acl(Bucket=bucket_name1)
        grants1 = {
            "Grants": [
                {
                    "Grantee": {
                        "ID": current_acl1["Owner"]["ID"],
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
            "Owner": current_acl1["Owner"],
        }
        rgw_conn1_c.put_bucket_acl(Bucket=bucket_name1, AccessControlPolicy=grants1)
        log.info("set READ permission for user2 on user1's bucket")

        # User1 uploads objects
        config.mapped_sizes = utils.make_mapped_sizes(config)
        uploaded_keys = []
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            s3_object_name = u1_canonical_id + ".key." + str(oc)
            reusable.upload_object(
                s3_object_name, bucket1, TEST_DATA_PATH, config, user1
            )
            uploaded_keys.append(s3_object_name)

        # List all keys from user1's bucket
        log.info("all keys from user 1--------------")
        all_objects1 = bucket1.objects.all()
        for obj in all_objects1:
            log.info("name: %s" % obj.key)

        # User2 creates bucket with FULL_CONTROL permission for user1
        bucket_name2 = utils.gen_bucket_name_from_userid(user2["user_id"], rand_no=0)
        bucket2 = reusable.create_bucket(bucket_name2, rgw_conn2, user2)

        # Set bucket ACL with FULL_CONTROL permission for user1
        # Must include owner's FULL_CONTROL and user1's FULL_CONTROL
        current_acl2 = rgw_conn2_c.get_bucket_acl(Bucket=bucket_name2)
        grants2 = {
            "Grants": [
                {
                    "Grantee": {
                        "ID": current_acl2["Owner"]["ID"],
                        "Type": "CanonicalUser",
                    },
                    "Permission": "FULL_CONTROL",
                },
                {
                    "Grantee": {
                        "ID": u1_canonical_id,
                        "Type": "CanonicalUser",
                    },
                    "Permission": "FULL_CONTROL",
                },
            ],
            "Owner": current_acl2["Owner"],
        }
        rgw_conn2_c.put_bucket_acl(Bucket=bucket_name2, AccessControlPolicy=grants2)
        log.info("set FULL_CONTROL permission for user1 on user2's bucket")

        # Get bucket2 using user1's connection
        bucket2_u1 = s3lib.resource_op(
            {"obj": rgw_conn1, "resource": "Bucket", "args": [bucket_name2]}
        )

        # Copy objects from user1's bucket to user2's bucket
        log.info("copying the objects from u1 to u2")
        for key_name in uploaded_keys:
            # Create object reference in destination bucket
            dest_obj = s3lib.resource_op(
                {
                    "obj": bucket2_u1,
                    "resource": "Object",
                    "args": [key_name],
                }
            )
            # Copy object from source bucket to destination bucket
            copy_response = dest_obj.copy_from(
                CopySource={"Bucket": bucket_name1, "Key": key_name}
            )
            if copy_response is None:
                raise TestExecError("copy object failed for %s" % key_name)
            log.info("copied object: %s" % key_name)

        # List all keys from user2's bucket (using user1's connection)
        log.info("all keys from user 2--------------")
        all_objects2 = bucket2_u1.objects.all()
        for obj in all_objects2:
            log.info("name: %s" % obj.key)

        # Verify copied objects using user2's connection
        log.info("verifying copied objects--------")
        all_objects3 = bucket2.objects.all()
        for obj in all_objects3:
            log.info("all keys from user 2--------------")
            log.info("name: %s" % obj.key)

        # Verify all objects were copied
        copied_keys = [obj.key for obj in all_objects3]
        for key_name in uploaded_keys:
            if key_name not in copied_keys:
                raise TestExecError("object %s was not copied successfully" % key_name)
        log.info("all objects copied successfully")

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
    test_info = AddTestInfo("test acls copy obj")
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
        config.bucket_count = 1
        if yaml_file is None:
            config.objects_count = 4
            config.objects_size_range = {"min": 10, "max": 50}
        else:
            if hasattr(config, "objects_count") and config.objects_count:
                pass
            else:
                config.objects_count = 4
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
        test_exec_read(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
