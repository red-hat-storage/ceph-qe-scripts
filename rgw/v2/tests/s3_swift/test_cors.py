"""
Test CORS (Cross-Origin Resource Sharing) functionality for Ceph RGW.

This test validates:
- Setting CORS configuration on buckets
- Getting CORS configuration
- Preflight OPTIONS requests
- Cross-origin requests (GET, PUT, DELETE)
- CORS header validation
- Multiple CORS rules
- Wildcard origins
- Deleting CORS configuration
"""

import argparse
import json
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.manage_data import io_generator
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddIOInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import cors
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    log.warning("requests library not available. Some CORS tests will be skipped.")

try:
    from requests_aws4auth import AWS4Auth

    AWS4AUTH_AVAILABLE = True
except ImportError:
    AWS4AUTH_AVAILABLE = False
    log.warning(
        "requests-aws4auth library not available. CORS requests will not be authenticated."
    )


def test_exec(config, ssh_con):
    """
    Execute CORS tests.

    Args:
        config: Test configuration
        ssh_con: SSH connection object

    Returns:
        None: Raises exception on failure
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Create users
    all_users_info = s3lib.create_users(config.user_count)
    if not all_users_info:
        raise TestExecError("Failed to create users")

    user_info = all_users_info[0]

    # Authenticate
    auth = Auth(user_info, ssh_con, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    s3_client = auth.do_auth_using_client()

    # Extract credentials for AWS4Auth
    access_key = user_info["access_key"]
    secret_key = user_info["secret_key"]
    log.info(f"Using access key: {access_key}")

    # Get RGW endpoint
    rgw_port = utils.get_radosgw_port_no(ssh_con)
    rgw_host, rgw_ip = utils.get_hostname_ip(ssh_con)
    endpoint_url = (
        f"http{'s' if config.ssl else ''}://{rgw_host or 'localhost'}:{rgw_port or 80}"
    )
    log.info(f"RGW endpoint: {endpoint_url}")

    # Create bucket
    bucket_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=1)
    log.info(f"Creating bucket: {bucket_name}")
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info)

    # Upload test object
    object_key = "cors-test-object.txt"
    object_data = "CORS test object data"
    log.info(f"Uploading test object: {object_key}")
    for oc, size in list(config.mapped_sizes.items()):
        config.obj_size = size
        reusable.upload_object(
            object_key,
            bucket,
            TEST_DATA_PATH,
            config,
            user_info,
        )

    test_results = []

    try:
        # Test 1: Basic CORS configuration
        log.info("=" * 80)
        log.info("TEST 1: Basic CORS configuration")
        log.info("=" * 80)
        result = cors.test_cors_configuration(s3_client, bucket_name, config)
        test_results.append(("Basic CORS configuration", result))

        # Test 2: Multiple CORS rules
        log.info("=" * 80)
        log.info("TEST 2: Multiple CORS rules")
        log.info("=" * 80)
        result = cors.test_cors_multiple_rules(s3_client, bucket_name)
        test_results.append(("Multiple CORS rules", result))

        # Test 3: Wildcard origin
        log.info("=" * 80)
        log.info("TEST 3: Wildcard origin")
        log.info("=" * 80)
        result = cors.test_cors_wildcard_origin(s3_client, bucket_name)
        test_results.append(("Wildcard origin", result))

        # Test 4: Preflight request
        log.info("=" * 80)
        log.info("TEST 4: CORS preflight request")
        log.info("=" * 80)
        result = cors.test_cors_preflight_request(
            endpoint_url,
            bucket_name,
            object_key,
            access_key,
            secret_key,
            verify_ssl=config.ssl,
        )
        test_results.append(("CORS preflight request", result))

        # Test 5: Actual CORS request
        log.info("=" * 80)
        log.info("TEST 5: Actual CORS request")
        log.info("=" * 80)
        result = cors.test_cors_actual_request(
            endpoint_url,
            bucket_name,
            object_key,
            access_key,
            secret_key,
            verify_ssl=config.ssl,
        )
        test_results.append(("Actual CORS request", result))

        # Test 6: Delete CORS configuration
        log.info("=" * 80)
        log.info("TEST 6: Delete CORS configuration")
        log.info("=" * 80)
        result = cors.test_cors_delete_configuration(s3_client, bucket_name)
        test_results.append(("Delete CORS configuration", result))

        # Print test summary
        log.info("=" * 80)
        log.info("TEST SUMMARY")
        log.info("=" * 80)
        passed = sum(1 for _, result in test_results if result)
        total = len(test_results)
        for test_name, result in test_results:
            status = "PASSED" if result else "FAILED"
            log.info(f"{test_name}: {status}")
        log.info(f"Total: {passed}/{total} tests passed")
        log.info("=" * 80)

        if passed != total:
            raise TestExecError(f"Some CORS tests failed: {total - passed}/{total}")

    except Exception as e:
        log.error(f"CORS test execution failed: {e}")
        raise TestExecError(f"CORS test execution failed: {e}")

    finally:
        # Cleanup
        if config.test_ops.get("delete_bucket", True):
            log.info("Cleaning up test resources")
            reusable.delete_objects(bucket)
            reusable.delete_bucket(bucket)


if __name__ == "__main__":
    test_info = AddTestInfo("RGW CORS functionality test")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"Test data path: {TEST_DATA_PATH}")

        if not os.path.exists(TEST_DATA_PATH):
            log.info(f"Test data directory not found. Creating: {TEST_DATA_PATH}")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW CORS functionality test")
        parser.add_argument("-c", dest="config", help="Test config yaml file")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node IP", default="127.0.0.1"
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
        config.rgw_host = rgw_node
        config.read()

        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("CORS test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("CORS test failed")
        sys.exit(1)
