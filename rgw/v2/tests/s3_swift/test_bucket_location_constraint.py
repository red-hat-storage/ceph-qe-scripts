"""
test_bucket_location_constraint - Test bucket creation with location constraints in multisite setup

Usage: test_bucket_location_constraint.py -c <input_yaml>

<input_yaml>
        test_bucket_location_constraint.yaml

Operation:
    This test validates bucket creation behavior with different location constraints
    across multiple zonegroups in a multisite RGW setup using AWS CLI, boto3, and s3cmd.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3cmd_auth
from v2.lib.s3cmd.resource_op import S3CMD
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """Main test execution function"""
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Get zonegroup names from config
    primary_zonegroup = config.test_ops.get("primary_zonegroup")
    tertiary_zonegroup = config.test_ops.get("tertiary_zonegroup")

    log.info(f"Primary zonegroup: {primary_zonegroup}")

    # Get primary endpoint
    primary_ip = utils.get_rgw_ip_zone("primary")
    primary_port = utils.get_radosgw_port_no(ssh_con)
    primary_endpoint = f"http://{primary_ip}:{primary_port}"

    # Get tertiary zonegroup endpoint if tertiary tests are enabled
    if tertiary_zonegroup:
        log.info(f"Tertiary zonegroup: {tertiary_zonegroup}")
        tertiary_zg_info = utils.exec_shell_cmd(
            f"radosgw-admin zonegroup get --rgw-zonegroup={tertiary_zonegroup}"
        )
        if not tertiary_zg_info:
            raise TestExecError(
                f"Failed to get zonegroup info for {tertiary_zonegroup}"
            )
        tertiary_zg_json = json.loads(tertiary_zg_info)
        tertiary_endpoint = tertiary_zg_json["endpoints"][0]
        tertiary_ip_and_port = tertiary_endpoint.replace("http://", "").replace(
            "https://", ""
        )
        log.info(f"Tertiary endpoint: {tertiary_endpoint}")
    else:
        tertiary_endpoint = None
        tertiary_ip_and_port = None

    # Create users
    all_users_info = s3lib.create_users(config.user_count)

    # Wait for metadata sync if tertiary endpoint is configured
    if tertiary_endpoint:
        log.info("Waiting for metadata sync to tertiary site...")
        time.sleep(30)  # Give time for metadata sync
        log.info("Metadata sync wait complete")

    # Get IP and port for primary endpoint
    primary_ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)

    for each_user in all_users_info:
        log.info(f"Test user: {each_user['user_id']}")

        # Setup AWS CLI authentication
        aws_auth.do_auth_aws(each_user)
        cli_aws = AWS()

        # Create boto3 connections for primary endpoint
        auth_primary = Auth(each_user, ssh_con)
        auth_primary.endpoint_url = primary_endpoint
        log.info(f"Primary endpoint for boto3: {auth_primary.endpoint_url}")
        rgw_primary = auth_primary.do_auth()
        rgw_client_primary = auth_primary.do_auth_using_client()

        # Setup s3cmd for primary endpoint
        s3cmd_auth.do_auth(each_user, primary_ip_and_port)

        # Create boto3 connections for tertiary endpoint
        if tertiary_endpoint:
            auth_tertiary = Auth(each_user, ssh_con)
            auth_tertiary.endpoint_url = tertiary_endpoint
            log.info(f"Tertiary endpoint for boto3: {auth_tertiary.endpoint_url}")
            rgw_tertiary = auth_tertiary.do_auth()
            rgw_client_tertiary = auth_tertiary.do_auth_using_client()
        else:
            rgw_tertiary = None
            rgw_client_tertiary = None

        # Track created buckets: (bucket_name, tool, rgw_conn_or_endpoint, ip_and_port_for_s3cmd)
        created_buckets = []

        try:
            if config.test_ops["create_bucket"]:
                # Test 1 & 2: Primary zonegroup tests
                if config.test_ops.get("test_primary_zg", True):
                    # Test 1: Create bucket in primary zonegroup via primary endpoint
                    log.info("=" * 100)
                    log.info(
                        f"TEST 1: Create bucket in {primary_zonegroup} via primary endpoint"
                    )
                    log.info("=" * 100)

                    # Test 1a: Using boto3
                    bucket_name_boto = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=1
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_boto}' using boto3 with location {primary_zonegroup}"
                    )
                    bucket = reusable.create_bucket(
                        bucket_name_boto,
                        rgw_primary,
                        each_user,
                        location=primary_zonegroup,
                    )
                    created_buckets.append(
                        (
                            bucket_name_boto,
                            "boto3",
                            rgw_primary,
                            bucket,
                            primary_ip_and_port,
                        )
                    )

                    location_response = rgw_client_primary.get_bucket_location(
                        Bucket=bucket_name_boto
                    )
                    actual_location = location_response.get("LocationConstraint", "")
                    log.info(f"Bucket '{bucket_name_boto}' location: {actual_location}")
                    if actual_location != primary_zonegroup:
                        raise TestExecError(
                            f"Expected {primary_zonegroup}, got {actual_location}"
                        )

                    # Test 1b: Using AWS CLI
                    bucket_name_aws = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=2
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_aws}' using AWS CLI with region {primary_zonegroup}"
                    )
                    aws_reusable.create_bucket(
                        cli_aws,
                        bucket_name_aws,
                        primary_endpoint,
                        region=primary_zonegroup,
                    )
                    created_buckets.append(
                        (
                            bucket_name_aws,
                            "aws",
                            primary_endpoint,
                            None,
                            primary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_aws}' created via AWS CLI")

                    # Verify location
                    actual_location = aws_reusable.get_bucket_location(
                        cli_aws, bucket_name_aws, primary_endpoint
                    )
                    log.info(f"Bucket '{bucket_name_aws}' location: {actual_location}")
                    if actual_location != primary_zonegroup:
                        raise TestExecError(
                            f"Expected {primary_zonegroup}, got {actual_location}"
                        )

                    # Test 1c: Using s3cmd
                    s3cmd_auth.do_auth(each_user, primary_ip_and_port)
                    bucket_name_s3cmd = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=3
                    )
                    log.info(f"Creating bucket '{bucket_name_s3cmd}' using s3cmd")
                    s3cmd_reusable.create_bucket(bucket_name_s3cmd, primary_endpoint)
                    created_buckets.append(
                        (
                            bucket_name_s3cmd,
                            "s3cmd",
                            primary_endpoint,
                            None,
                            primary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_s3cmd}' created via s3cmd")

                    # Verify location using s3cmd info
                    s3cmd_info = S3CMD("info", [])
                    cmd = s3cmd_info.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    log.info(f"Bucket '{bucket_name_s3cmd}' info: {output}")

                    # Test 2: Create bucket in tertiary zonegroup via primary endpoint (should fail)
                    log.info("=" * 100)
                    log.info(
                        f"TEST 2: Create bucket in {tertiary_zonegroup} via primary endpoint (should fail)"
                    )
                    log.info("=" * 100)

                    # Test 2a: Using boto3
                    bucket_name_boto = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=4
                    )
                    log.info(
                        f"Attempting to create bucket '{bucket_name_boto}' using boto3 with location {tertiary_zonegroup}"
                    )
                    try:
                        bucket = reusable.create_bucket(
                            bucket_name_boto,
                            rgw_primary,
                            each_user,
                            location=tertiary_zonegroup,
                        )
                        created_buckets.append(
                            (
                                bucket_name_boto,
                                "boto3",
                                rgw_primary,
                                bucket,
                                primary_ip_and_port,
                            )
                        )
                        raise Exception(
                            f"Bucket creation should have failed with IllegalLocationConstraintException"
                        )
                    except TestExecError as e:
                        log.info(
                            f"boto3: Bucket creation correctly failed as expected: {e}"
                        )

                    # Test 2b: Using AWS CLI
                    bucket_name_aws = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=5
                    )
                    log.info(
                        f"Attempting to create bucket '{bucket_name_aws}' using AWS CLI with region {tertiary_zonegroup}"
                    )
                    bucket_created = aws_reusable.create_bucket(
                        cli_aws,
                        bucket_name_aws,
                        primary_endpoint,
                        region=tertiary_zonegroup,
                    )
                    if bucket_created:
                        created_buckets.append(
                            (
                                bucket_name_aws,
                                "aws",
                                primary_endpoint,
                                None,
                                primary_ip_and_port,
                            )
                        )
                        raise TestExecError(
                            "Bucket creation should have failed with IllegalLocationConstraintException"
                        )
                    else:
                        log.info(
                            "AWS CLI: Bucket creation correctly failed with IllegalLocationConstraintException"
                        )

                    # Test 2c: Using s3cmd
                    bucket_name_s3cmd = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=6
                    )
                    log.info(
                        f"Attempting to create bucket '{bucket_name_s3cmd}' using s3cmd with region {tertiary_zonegroup}"
                    )
                    s3cmd_create = S3CMD("mb", [f"--region={tertiary_zonegroup}"])
                    cmd = s3cmd_create.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    if output is not False:
                        created_buckets.append(
                            (
                                bucket_name_s3cmd,
                                "s3cmd",
                                primary_endpoint,
                                None,
                                primary_ip_and_port,
                            )
                        )
                        raise TestExecError(
                            f"Bucket creation should have failed with IllegalLocationConstraintException"
                        )
                    log.info(
                        "s3cmd: Bucket creation correctly failed with IllegalLocationConstraintException"
                    )

                # Test 3 & 4: Tertiary zonegroup tests
                if config.test_ops.get("test_tertiary_zg", True):
                    # Test 3: Create bucket in tertiary zonegroup via tertiary endpoint
                    log.info("=" * 100)
                    log.info(
                        f"TEST 3: Create bucket in {tertiary_zonegroup} via {tertiary_zonegroup} endpoint"
                    )
                    log.info("=" * 100)

                    # Test 3a: Using boto3
                    bucket_name_boto = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=7
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_boto}' using boto3 with location {tertiary_zonegroup}"
                    )
                    bucket = reusable.create_bucket(
                        bucket_name_boto,
                        rgw_tertiary,
                        each_user,
                        location=tertiary_zonegroup,
                    )
                    created_buckets.append(
                        (
                            bucket_name_boto,
                            "boto3",
                            rgw_tertiary,
                            bucket,
                            tertiary_ip_and_port,
                        )
                    )

                    location_response = rgw_client_tertiary.get_bucket_location(
                        Bucket=bucket_name_boto
                    )
                    actual_location = location_response.get("LocationConstraint", "")
                    log.info(f"Bucket '{bucket_name_boto}' location: {actual_location}")
                    if actual_location != tertiary_zonegroup:
                        raise TestExecError(
                            f"Expected {tertiary_zonegroup}, got {actual_location}"
                        )

                    # Test 3b: Using AWS CLI
                    bucket_name_aws = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=8
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_aws}' using AWS CLI with region {tertiary_zonegroup}"
                    )
                    aws_reusable.create_bucket(
                        cli_aws,
                        bucket_name_aws,
                        tertiary_endpoint,
                        region=tertiary_zonegroup,
                    )
                    created_buckets.append(
                        (
                            bucket_name_aws,
                            "aws",
                            tertiary_endpoint,
                            None,
                            tertiary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_aws}' created via AWS CLI")

                    # Verify location
                    actual_location = aws_reusable.get_bucket_location(
                        cli_aws, bucket_name_aws, tertiary_endpoint
                    )
                    log.info(f"Bucket '{bucket_name_aws}' location: {actual_location}")
                    if actual_location != tertiary_zonegroup:
                        raise TestExecError(
                            f"Expected {tertiary_zonegroup}, got {actual_location}"
                        )

                    # Test 3c: Using s3cmd (reconfigure for tertiary endpoint)
                    s3cmd_auth.do_auth(each_user, tertiary_ip_and_port)
                    bucket_name_s3cmd = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=9
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_s3cmd}' using s3cmd with region {tertiary_zonegroup}"
                    )
                    s3cmd_create = S3CMD("mb", [f"--region={tertiary_zonegroup}"])
                    cmd = s3cmd_create.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    if not output or "ERROR" in str(output):
                        raise TestExecError(f"s3cmd bucket creation failed: {output}")
                    created_buckets.append(
                        (
                            bucket_name_s3cmd,
                            "s3cmd",
                            tertiary_endpoint,
                            None,
                            tertiary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_s3cmd}' created via s3cmd")

                    # Verify location using s3cmd info
                    s3cmd_info = S3CMD("info", [])
                    cmd = s3cmd_info.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    log.info(f"Bucket '{bucket_name_s3cmd}' info: {output}")

                    # Test 4: Create primary zonegroup bucket via tertiary endpoint (should fail)
                    log.info("=" * 100)
                    log.info(
                        f"TEST 4: Create {primary_zonegroup} bucket via {tertiary_zonegroup} endpoint (should fail)"
                    )
                    log.info("=" * 100)

                    # Test 4a: Using boto3
                    bucket_name_boto = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=10
                    )
                    log.info(
                        f"Attempting to create bucket '{bucket_name_boto}' using boto3 with location {primary_zonegroup}"
                    )
                    try:
                        bucket = reusable.create_bucket(
                            bucket_name_boto,
                            rgw_tertiary,
                            each_user,
                            location=primary_zonegroup,
                        )
                        created_buckets.append(
                            (
                                bucket_name_boto,
                                "boto3",
                                rgw_tertiary,
                                bucket,
                                tertiary_ip_and_port,
                            )
                        )
                        raise Exception(
                            f"Bucket creation should have failed with IllegalLocationConstraintException"
                        )
                    except TestExecError as e:
                        log.info(
                            f"boto3: Bucket creation correctly failed as expected: {e}"
                        )

                    # Test 4b: Using AWS CLI
                    bucket_name_aws = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=11
                    )
                    log.info(
                        f"Attempting to create bucket '{bucket_name_aws}' using AWS CLI with region {primary_zonegroup}"
                    )
                    bucket_created = aws_reusable.create_bucket(
                        cli_aws,
                        bucket_name_aws,
                        tertiary_endpoint,
                        region=primary_zonegroup,
                    )
                    if bucket_created:
                        created_buckets.append(
                            (
                                bucket_name_aws,
                                "aws",
                                tertiary_endpoint,
                                None,
                                tertiary_ip_and_port,
                            )
                        )
                        raise TestExecError(
                            "Bucket creation should have failed with IllegalLocationConstraintException"
                        )
                    else:
                        log.info(
                            "AWS CLI: Bucket creation correctly failed with IllegalLocationConstraintException"
                        )

                    # Test 4c: Using s3cmd
                    bucket_name_s3cmd = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=12
                    )
                    log.info(
                        f"Attempting to create bucket '{bucket_name_s3cmd}' using s3cmd with region {primary_zonegroup}"
                    )
                    s3cmd_create = S3CMD("mb", [f"--region={primary_zonegroup}"])
                    cmd = s3cmd_create.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    if output is not False:
                        created_buckets.append(
                            (
                                bucket_name_s3cmd,
                                "s3cmd",
                                tertiary_endpoint,
                                None,
                                tertiary_ip_and_port,
                            )
                        )
                        raise TestExecError(
                            f"Bucket creation should have failed with IllegalLocationConstraintException"
                        )
                    log.info(
                        "s3cmd: Bucket creation correctly failed with IllegalLocationConstraintException"
                    )

                # Test 5 & 6: Default zonegroup tests
                if config.test_ops.get("test_default_zg", True):
                    # Test 5: Create bucket via tertiary endpoint without region (defaults to tertiary zonegroup)
                    log.info("=" * 100)
                    log.info(
                        f"TEST 5: Create bucket via {tertiary_zonegroup} endpoint without region (defaults to {tertiary_zonegroup})"
                    )
                    log.info("=" * 100)

                    # Test 5a: Using boto3
                    bucket_name_boto = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=13
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_boto}' using boto3 without location"
                    )
                    bucket = reusable.create_bucket(
                        bucket_name_boto, rgw_tertiary, each_user, location=None
                    )
                    created_buckets.append(
                        (
                            bucket_name_boto,
                            "boto3",
                            rgw_tertiary,
                            bucket,
                            tertiary_ip_and_port,
                        )
                    )

                    location_response = rgw_client_tertiary.get_bucket_location(
                        Bucket=bucket_name_boto
                    )
                    actual_location = location_response.get("LocationConstraint", "")
                    log.info(f"Bucket '{bucket_name_boto}' location: {actual_location}")
                    if actual_location != tertiary_zonegroup:
                        raise TestExecError(
                            f"Expected default {tertiary_zonegroup}, got {actual_location}"
                        )

                    # Test 5b: Using AWS CLI
                    bucket_name_aws = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=14
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_aws}' using AWS CLI without region"
                    )
                    aws_reusable.create_bucket(
                        cli_aws, bucket_name_aws, tertiary_endpoint
                    )
                    created_buckets.append(
                        (
                            bucket_name_aws,
                            "aws",
                            tertiary_endpoint,
                            None,
                            tertiary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_aws}' created via AWS CLI")

                    # Verify location
                    actual_location = aws_reusable.get_bucket_location(
                        cli_aws, bucket_name_aws, tertiary_endpoint
                    )
                    log.info(f"Bucket '{bucket_name_aws}' location: {actual_location}")
                    if actual_location != tertiary_zonegroup:
                        raise TestExecError(
                            f"Expected default {tertiary_zonegroup}, got {actual_location}"
                        )

                    # Test 5c: Using s3cmd
                    bucket_name_s3cmd = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=15
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_s3cmd}' using s3cmd without region"
                    )
                    s3cmd_reusable.create_bucket(bucket_name_s3cmd, tertiary_endpoint)
                    created_buckets.append(
                        (
                            bucket_name_s3cmd,
                            "s3cmd",
                            tertiary_endpoint,
                            None,
                            tertiary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_s3cmd}' created via s3cmd")

                    # Verify location using s3cmd info
                    s3cmd_info = S3CMD("info", [])
                    cmd = s3cmd_info.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    log.info(f"Bucket '{bucket_name_s3cmd}' info: {output}")

                    # Test 6: Create bucket via primary endpoint without region (defaults to primary zonegroup)
                    log.info("=" * 100)
                    log.info(
                        f"TEST 6: Create bucket via primary endpoint without region (defaults to {primary_zonegroup})"
                    )
                    log.info("=" * 100)

                    # Reconfigure s3cmd for primary endpoint
                    s3cmd_auth.do_auth(each_user, primary_ip_and_port)

                    # Test 6a: Using boto3
                    bucket_name_boto = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=16
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_boto}' using boto3 without location"
                    )
                    bucket = reusable.create_bucket(
                        bucket_name_boto, rgw_primary, each_user, location=None
                    )
                    created_buckets.append(
                        (
                            bucket_name_boto,
                            "boto3",
                            rgw_primary,
                            bucket,
                            primary_ip_and_port,
                        )
                    )

                    location_response = rgw_client_primary.get_bucket_location(
                        Bucket=bucket_name_boto
                    )
                    actual_location = location_response.get("LocationConstraint", "")
                    log.info(f"Bucket '{bucket_name_boto}' location: {actual_location}")
                    if actual_location != primary_zonegroup:
                        raise TestExecError(
                            f"Expected default {primary_zonegroup}, got {actual_location}"
                        )

                    # Test 6b: Using AWS CLI
                    bucket_name_aws = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=17
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_aws}' using AWS CLI without region"
                    )
                    aws_reusable.create_bucket(
                        cli_aws, bucket_name_aws, primary_endpoint
                    )
                    created_buckets.append(
                        (
                            bucket_name_aws,
                            "aws",
                            primary_endpoint,
                            None,
                            primary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_aws}' created via AWS CLI")

                    # Verify location
                    actual_location = aws_reusable.get_bucket_location(
                        cli_aws, bucket_name_aws, primary_endpoint
                    )
                    log.info(f"Bucket '{bucket_name_aws}' location: {actual_location}")
                    if actual_location != primary_zonegroup:
                        raise TestExecError(
                            f"Expected default {primary_zonegroup}, got {actual_location}"
                        )

                    # Test 6c: Using s3cmd
                    bucket_name_s3cmd = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=18
                    )
                    log.info(
                        f"Creating bucket '{bucket_name_s3cmd}' using s3cmd without region"
                    )
                    s3cmd_reusable.create_bucket(bucket_name_s3cmd, primary_endpoint)
                    created_buckets.append(
                        (
                            bucket_name_s3cmd,
                            "s3cmd",
                            primary_endpoint,
                            None,
                            primary_ip_and_port,
                        )
                    )
                    log.info(f"Bucket '{bucket_name_s3cmd}' created via s3cmd")

                    # Verify location using s3cmd info
                    s3cmd_info = S3CMD("info", [])
                    cmd = s3cmd_info.command([f"s3://{bucket_name_s3cmd}"])
                    output = utils.exec_shell_cmd(cmd)
                    log.info(f"Bucket '{bucket_name_s3cmd}' info: {output}")

                log.info("=" * 100)
                log.info("ALL TESTS PASSED")
                log.info("=" * 100)

        except Exception as e:
            log.error(f"Test failed: {str(e)}")
            log.error(traceback.format_exc())
            raise
        finally:
            log.info("Cleaning up buckets...")

            for (
                bucket_name,
                tool,
                rgw_conn_or_endpoint,
                bucket_obj,
                ip_and_port,
            ) in created_buckets:
                try:
                    if tool == "boto3":
                        # Get fresh bucket object from the correct connection
                        bucket_to_delete = rgw_conn_or_endpoint.Bucket(bucket_name)
                        reusable.delete_bucket(bucket_to_delete)
                        log.info(f"Deleted boto3 bucket: {bucket_name}")
                    elif tool == "aws":
                        aws_reusable.delete_bucket(
                            cli_aws, bucket_name, rgw_conn_or_endpoint
                        )
                        log.info(f"Deleted AWS CLI bucket: {bucket_name}")
                    elif tool == "s3cmd":
                        # Reconfigure s3cmd for the correct endpoint
                        s3cmd_auth.do_auth(each_user, ip_and_port)
                        s3cmd_delete = S3CMD("rb", [])
                        cmd = s3cmd_delete.command([f"s3://{bucket_name}"])
                        utils.exec_shell_cmd(cmd)
                        log.info(f"Deleted s3cmd bucket: {bucket_name}")
                except Exception as e:
                    log.warning(f"Failed to delete bucket {bucket_name}: {e}")

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test bucket creation with location constraints")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="RGW Bucket Location Constraint Test"
        )
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            default="info",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", default="127.0.0.1", help="RGW Node"
        )
        args = parser.parse_args()

        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)

        configure_logging(
            f_name=os.path.basename(os.path.splitext(args.config)[0]),
            set_level=args.log_level.upper(),
        )
        config = Config(args.config)
        config.read(ssh_con)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
