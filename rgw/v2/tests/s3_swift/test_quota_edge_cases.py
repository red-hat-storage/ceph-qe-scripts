"""test_quota_edge_cases - Test quota edge cases and boundary conditions

Usage: test_quota_edge_cases.py -c <input_yaml>

<input_yaml>
        Note: any one of these yamls can be used
        test_quota_edge_zero.yaml
        test_quota_edge_one.yaml
        test_quota_edge_exact_boundary.yaml
        test_quota_edge_large_values.yaml
        test_quota_decrease_below_usage.yaml
        test_quota_timing_after_delete.yaml

Operation:
    Test edge cases and boundary conditions for quota:
    - Zero quota (should reject all uploads)
    - Quota = 1 (minimum boundary)
    - Exact boundary testing
    - Large quota values
    - Decreasing quota below current usage
    - Quota timing after deletes
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import quota_management as quota_mgmt
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

TEST_DATA_PATH = None
import logging

log = logging.getLogger()


def test_quota_zero(config, each_user, bucket, quota_scope):
    """Test quota set to 0 - should reject all uploads"""
    log.info(f"Testing {quota_scope} quota with max_objects=0")
    quota_mgmt.set_quota(quota_scope=quota_scope, user_info=each_user, max_objects=0)
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    log.info("Attempting upload with quota=0 (should fail)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 1, 0
    )
    if uploaded:
        raise AssertionError(f"{quota_scope} quota=0 failed - upload succeeded")
    log.info(f"{quota_scope} quota=0 test passed - upload correctly rejected")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)


def test_quota_one(config, each_user, bucket, quota_scope):
    """Test quota set to 1 - boundary test"""
    log.info(f"Testing {quota_scope} quota with max_objects=1")
    quota_mgmt.set_quota(quota_scope=quota_scope, user_info=each_user, max_objects=1)
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    log.info("Upload 1 object (should succeed)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 1, 100
    )
    if not uploaded:
        raise AssertionError(f"{quota_scope} quota=1 failed - first upload rejected")

    log.info("Upload 2nd object (should fail)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 2, 100
    )
    if uploaded:
        raise AssertionError(f"{quota_scope} quota=1 failed - second upload succeeded")
    log.info(f"{quota_scope} quota=1 test passed")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)
    reusable.delete_objects(bucket)


def test_exact_boundary(config, each_user, bucket, quota_scope, max_size):
    """Test exact boundary - upload object exactly at quota limit"""
    log.info(f"Testing {quota_scope} quota exact boundary with max_size={max_size}")
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=max_size
    )
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    log.info(f"Upload object exactly at limit ({max_size} bytes)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 1, max_size
    )
    if not uploaded:
        raise AssertionError(
            f"{quota_scope} quota exact boundary failed - upload at limit rejected"
        )

    log.info(f"Upload 1 more byte ({max_size + 1} bytes - should fail)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 2, 1
    )
    if uploaded:
        raise AssertionError(
            f"{quota_scope} quota exact boundary failed - upload beyond limit succeeded"
        )
    log.info(f"{quota_scope} quota exact boundary test passed")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)
    reusable.delete_objects(bucket)


def test_large_quota_values(config, each_user, bucket, quota_scope):
    """Test very large quota values (1PB)"""
    large_quota = 1024 * 1024 * 1024 * 1024 * 1024  # 1 PB
    log.info(f"Testing {quota_scope} quota with large value: {large_quota} bytes (1PB)")
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=large_quota
    )
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    log.info("Upload small object with 1PB quota (should succeed)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 1, 1024
    )
    if not uploaded:
        raise AssertionError(f"{quota_scope} large quota test failed - upload rejected")
    log.info(f"{quota_scope} large quota test passed")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)
    reusable.delete_objects(bucket)


def test_multipart_quota(config, each_user, bucket, quota_scope, rgw_conn):
    """Test quota enforcement with multipart uploads"""
    log.info(f"Testing {quota_scope} quota with multipart upload")
    max_size = 10 * 1024 * 1024  # 10MB
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=max_size
    )
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    s3_object_name = utils.gen_s3_object_name(bucket.name, 0)
    log.info(f"Multipart upload object: {s3_object_name}")
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)

    # Create file larger than quota
    part_size = 5 * 1024 * 1024  # 5MB per part
    num_parts = 3  # Total 15MB > 10MB quota

    log.info(f"Creating {num_parts} parts of {part_size} bytes each (total > quota)")
    try:
        reusable.upload_mutipart_object(
            s3_object_name=s3_object_name,
            bucket=bucket,
            TEST_DATA_PATH=TEST_DATA_PATH,
            config=config,
            user_info=each_user,
        )
        raise AssertionError(
            f"{quota_scope} multipart quota test failed - upload succeeded despite exceeding quota"
        )
    except TestExecError as e:
        log.info(
            f"{quota_scope} multipart quota correctly enforced - upload failed: {e}"
        )

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)


def test_multipart_abort_quota_reclaim(config, each_user, bucket, quota_scope):
    """Test quota reclamation after aborting multipart upload"""
    log.info(f"Testing {quota_scope} quota reclamation after multipart abort")
    max_size = 10 * 1024 * 1024  # 10MB
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=max_size
    )
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    s3_object_name = utils.gen_s3_object_name(bucket.name, 0)
    log.info(f"Initiating multipart upload: {s3_object_name}")

    # Initiate multipart
    mpu = bucket.initiate_multipart_upload(Key=s3_object_name)

    # Upload parts (total 8MB)
    part_size = 4 * 1024 * 1024
    parts = []
    for i in range(1, 3):  # 2 parts
        part = mpu.Part(i)
        data = os.urandom(part_size)
        response = part.upload(Body=data)
        parts.append({"PartNumber": i, "ETag": response["ETag"]})
        log.info(f"Uploaded part {i}")

    log.info("Aborting multipart upload")
    mpu.abort()
    log.info("Multipart upload aborted")

    # Wait for quota recalculation
    log.info("Waiting 10 seconds for quota recalculation")
    time.sleep(10)

    # Try to upload 9MB object (should succeed if quota was reclaimed)
    log.info("Attempting upload after abort (should succeed)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 1, 9 * 1024 * 1024
    )
    if not uploaded:
        raise AssertionError(
            f"{quota_scope} multipart abort test failed - quota not reclaimed"
        )
    log.info(f"{quota_scope} multipart abort quota reclaim test passed")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)
    reusable.delete_objects(bucket)


def test_decrease_quota_below_usage(config, each_user, bucket, quota_scope):
    """Test decreasing quota below current usage"""
    log.info(f"Testing {quota_scope} quota decrease below current usage")

    # Set quota to 10MB and upload 8MB
    initial_quota = 10 * 1024 * 1024
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=initial_quota
    )
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    log.info(f"Uploading 8MB object with {initial_quota} quota")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 1, 8 * 1024 * 1024
    )
    if not uploaded:
        raise AssertionError("Failed to upload initial object")

    # Decrease quota to 5MB (below current usage of 8MB)
    new_quota = 5 * 1024 * 1024
    log.info(f"Decreasing quota to {new_quota} bytes (below current usage)")
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=new_quota
    )

    # Try to upload even 1 byte more (should fail)
    log.info("Attempting upload after quota decrease (should fail)")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 2, 100
    )
    if uploaded:
        raise AssertionError(
            f"{quota_scope} decrease quota test failed - upload succeeded despite being over quota"
        )
    log.info(f"{quota_scope} decrease quota below usage test passed")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)
    reusable.delete_objects(bucket)


def test_quota_timing_after_delete(config, each_user, bucket, quota_scope):
    """Test quota recalculation timing after object deletion"""
    log.info(f"Testing {quota_scope} quota timing after delete")
    max_size = 10 * 1024 * 1024
    quota_mgmt.set_quota(
        quota_scope=quota_scope, user_info=each_user, max_size=max_size
    )
    quota_mgmt.toggle_quota("enable", quota_scope, each_user)

    # Fill quota with 10 x 1MB objects
    log.info("Uploading 10 x 1MB objects to fill quota")
    for i in range(1, 11):
        uploaded = quota_mgmt.upload_object_initiate(
            TEST_DATA_PATH, config, each_user, bucket, bucket.name, i, 1024 * 1024
        )
        if not uploaded:
            raise AssertionError(f"Failed to upload object {i}")

    # Verify quota is full
    log.info("Verifying quota is full")
    uploaded = quota_mgmt.upload_object_initiate(
        TEST_DATA_PATH, config, each_user, bucket, bucket.name, 11, 100
    )
    if uploaded:
        raise AssertionError("Quota not enforced - extra upload succeeded")

    # Delete 5 objects (free 5MB)
    log.info("Deleting 5 objects to free quota")
    objects_to_delete = [
        {"Key": utils.gen_s3_object_name(bucket.name, i)} for i in range(1, 6)
    ]
    bucket.delete_objects(Delete={"Objects": objects_to_delete})

    # Retry upload with backoff (eventual consistency)
    log.info("Retrying upload after delete (with retry for eventual consistency)")
    max_retries = 5
    retry_delay = 2
    upload_succeeded = False

    for attempt in range(1, max_retries + 1):
        log.info(f"Attempt {attempt}/{max_retries}")
        uploaded = quota_mgmt.upload_object_initiate(
            TEST_DATA_PATH, config, each_user, bucket, bucket.name, 11, 4 * 1024 * 1024
        )
        if uploaded:
            upload_succeeded = True
            log.info(f"Upload succeeded on attempt {attempt}")
            break
        log.info(f"Upload still blocked, waiting {retry_delay}s...")
        time.sleep(retry_delay)

    if not upload_succeeded:
        raise AssertionError(
            f"{quota_scope} timing test failed - quota not reclaimed after {max_retries} attempts"
        )
    log.info(f"{quota_scope} quota timing after delete test passed")

    quota_mgmt.toggle_quota("disable", quota_scope, each_user)
    reusable.delete_objects(bucket)


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    log.info(f"Creating {config.user_count} users")
    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        log.info(f"Creating {config.bucket_count} buckets for {each_user['user_id']}")

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            bucket = reusable.create_bucket(
                bucket_name, rgw_conn, each_user, ip_and_port
            )

            quota_scope = config.test_ops.get("quota_scope", "bucket")

            if config.test_ops.get("test_quota_zero"):
                test_quota_zero(config, each_user, bucket, quota_scope)

            if config.test_ops.get("test_quota_one"):
                test_quota_one(config, each_user, bucket, quota_scope)

            if config.test_ops.get("test_exact_boundary"):
                max_size = config.test_ops.get("boundary_size", 10 * 1024)
                test_exact_boundary(config, each_user, bucket, quota_scope, max_size)

            if config.test_ops.get("test_large_quota"):
                test_large_quota_values(config, each_user, bucket, quota_scope)

            if config.test_ops.get("test_multipart_quota"):
                test_multipart_quota(config, each_user, bucket, quota_scope, rgw_conn)

            if config.test_ops.get("test_multipart_abort"):
                test_multipart_abort_quota_reclaim(
                    config, each_user, bucket, quota_scope
                )

            if config.test_ops.get("test_decrease_below_usage"):
                test_decrease_quota_below_usage(config, each_user, bucket, quota_scope)

            if config.test_ops.get("test_quota_timing"):
                test_quota_timing_after_delete(config, each_user, bucket, quota_scope)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test quota edge cases and boundary conditions")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 Quota Edge Cases")
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
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
