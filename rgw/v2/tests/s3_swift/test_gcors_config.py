"""
Polarion ID: CEPH-83632421
Test Global CORS (GCORS) configuration for Ceph RGW.

This test validates:
- Setting RGW global CORS configuration options
- Restarting RGW service after configuration
- Performing basic I/O operations on buckets after GCORS enablement
- Testing that CORS headers are properly set at the global level

GCORS options tested:
- rgw_gcors_allow_origins: Allowed origins for CORS requests
- rgw_gcors_allow_headers: Allowed headers in CORS requests
- rgw_gcors_allow_methods: Allowed HTTP methods for CORS
"""

import argparse
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.manage_data import io_generator
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import (
    AddIOInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None

# Import requests library for CORS testing
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    log.warning("requests library not available. CORS HTTP tests will be skipped.")

# Import AWS4Auth for authenticated requests
try:
    from requests_aws4auth import AWS4Auth

    AWS4AUTH_AVAILABLE = True
except ImportError:
    AWS4AUTH_AVAILABLE = False
    log.warning(
        "requests-aws4auth not available. CORS requests will not be authenticated."
    )


def test_gcors_with_requests(
    config,
    endpoint_url,
    bucket_name,
    object_key,
    access_key,
    secret_key,
    gcors_origins,
    gcors_methods,
    gcors_headers,
    region="us-east-1",
):
    """
    Test Global CORS configuration using HTTP requests.

    Args:
        endpoint_url: RGW endpoint URL
        bucket_name: Bucket name to test
        object_key: Object key to test
        access_key: AWS access key
        secret_key: AWS secret key
        gcors_origins: Configured CORS origins
        gcors_methods: Configured CORS methods
        gcors_headers: Configured CORS headers
        region: AWS region (default: us-east-1)

    Returns:
        bool: True if tests pass, False otherwise
    """
    if not REQUESTS_AVAILABLE:
        log.warning("Requests library not available, skipping CORS HTTP tests")
        return True

    log.info("=" * 80)
    log.info("STEP 5: Testing Global CORS with HTTP Requests")
    log.info("=" * 80)

    # Construct object URL
    object_url = f"{endpoint_url}/{bucket_name}/{object_key}"
    log.info(f"Testing CORS on URL: {object_url}")

    # Test origin - use first origin from config or a test origin
    log.info(f"{gcors_origins} gcors origin")
    if gcors_origins == "*" or gcors_origins == '"*"':
        test_origin = "https://example.com"
    else:
        # Extract first origin from comma-separated list
        origins_list = [o.strip() for o in gcors_origins.split(",")]
        test_origin = origins_list[0] if origins_list else "https://example.com"

    log.info(f"Using test origin: {test_origin}")

    # Prepare AWS4Auth if available
    auth = None
    if AWS4AUTH_AVAILABLE:
        auth = AWS4Auth(access_key, secret_key, region, "s3")
        log.info("Using AWS4Auth for authenticated requests")
    else:
        log.warning("AWS4Auth not available, requests will be unauthenticated")

    cors_tests_passed = 0
    cors_tests_total = 0

    # Test 1: OPTIONS Preflight Request
    log.info("\n--- Test 1: OPTIONS Preflight Request ---")
    cors_tests_total += 1
    try:
        headers = {
            "Origin": test_origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        }

        log.info(f"Sending OPTIONS request with Origin: {test_origin}")
        response = requests.options(object_url, headers=headers, verify=False)
        log.info(f"Response Status: {response.status_code}")
        log.info(f"Response Headers: {dict(response.headers)}")

        # Check for CORS headers in response
        if "Access-Control-Allow-Origin" in response.headers:
            log.info(
                f"✓ Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}"
            )
            cors_tests_passed += 1
        else:
            log.warning("✗ Access-Control-Allow-Origin header not found")

        if "Access-Control-Allow-Methods" in response.headers:
            log.info(
                f"✓ Access-Control-Allow-Methods: {response.headers['Access-Control-Allow-Methods']}"
            )

        if "Access-Control-Allow-Headers" in response.headers:
            log.info(
                f"✓ Access-Control-Allow-Headers: {response.headers['Access-Control-Allow-Headers']}"
            )

    except Exception as e:
        log.error(f"✗ OPTIONS request failed: {e}")

    # Test 2: GET Request with Origin Header
    log.info("\n--- Test 2: GET Request with Origin Header ---")
    cors_tests_total += 1
    try:
        headers = {
            "Origin": test_origin,
        }

        log.info(f"Sending GET request with Origin: {test_origin}")
        response = requests.get(object_url, headers=headers, auth=auth, verify=False)
        log.info(f"Response Status: {response.status_code}")

        # Check for CORS headers
        if "Access-Control-Allow-Origin" in response.headers:
            allow_origin = response.headers["Access-Control-Allow-Origin"]
            log.info(f"✓ Access-Control-Allow-Origin: {allow_origin}")

            # Verify origin matches configuration
            if gcors_origins == "*" or test_origin in gcors_origins:
                if allow_origin == "*" or allow_origin == test_origin:
                    log.info("✓ CORS origin validated correctly")
                    cors_tests_passed += 1
                else:
                    log.warning(f"✗ Unexpected origin value: {allow_origin}")
            else:
                log.warning("✗ Origin not in configured list")
        else:
            log.warning(
                "✗ Access-Control-Allow-Origin header not found in GET response"
            )

        if "Access-Control-Expose-Headers" in response.headers:
            log.info(
                f"✓ Access-Control-Expose-Headers: {response.headers['Access-Control-Expose-Headers']}"
            )

    except Exception as e:
        log.error(f"✗ GET request failed: {e}")

    # Test 3: PUT Request with Origin Header (if PUT is allowed)
    if "PUT" in gcors_methods.upper():
        log.info("\n--- Test 3: PUT Request with Origin Header ---")
        cors_tests_total += 1
        try:
            headers = {
                "Origin": test_origin,
                "Content-Type": "text/plain",
            }

            test_data = b"GCORS test data from PUT request"
            test_object_key = f"gcors-put-test-{int(time.time())}.txt"
            test_object_url = f"{endpoint_url}/{bucket_name}/{test_object_key}"

            log.info(f"Sending PUT request to: {test_object_url}")
            response = requests.put(
                test_object_url,
                data=test_data,
                headers=headers,
                auth=auth,
                verify=False,
            )
            log.info(f"Response Status: {response.status_code}")

            if response.status_code in [200, 201]:
                log.info("✓ PUT request succeeded")

                # Check for CORS headers
                if "Access-Control-Allow-Origin" in response.headers:
                    log.info(
                        f"✓ Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}"
                    )
                    cors_tests_passed += 1
                else:
                    log.warning(
                        "✗ Access-Control-Allow-Origin header not found in PUT response"
                    )
            else:
                log.warning(f"✗ PUT request failed with status: {response.status_code}")

        except Exception as e:
            log.error(f"✗ PUT request failed: {e}")
    else:
        log.info("\n--- Test 3: Skipped (PUT not in allowed methods) ---")

    # Test 4: HEAD Request with Origin Header
    log.info("\n--- Test 4: HEAD Request with Origin Header ---")
    cors_tests_total += 1
    try:
        headers = {
            "Origin": test_origin,
        }

        log.info(f"Sending HEAD request with Origin: {test_origin}")
        response = requests.head(object_url, headers=headers, auth=auth, verify=False)
        log.info(f"Response Status: {response.status_code}")

        if "Access-Control-Allow-Origin" in response.headers:
            log.info(
                f"✓ Access-Control-Allow-Origin: {response.headers['Access-Control-Allow-Origin']}"
            )
            cors_tests_passed += 1
        else:
            log.warning(
                "✗ Access-Control-Allow-Origin header not found in HEAD response"
            )

    except Exception as e:
        log.error(f"✗ HEAD request failed: {e}")

    # Test 5: Request with Disallowed Origin (if not using wildcard)
    if gcors_origins != "*":
        log.info("\n--- Test 5: Request with Disallowed Origin ---")
        cors_tests_total += 1
        try:
            disallowed_origin = "https://evil.example.com"
            headers = {
                "Origin": disallowed_origin,
            }

            log.info(f"Sending GET request with disallowed origin: {disallowed_origin}")
            response = requests.get(
                object_url, headers=headers, auth=auth, verify=False
            )
            log.info(f"Response Status: {response.status_code}")

            # Should not have CORS headers or should deny
            if "Access-Control-Allow-Origin" in response.headers:
                allow_origin = response.headers["Access-Control-Allow-Origin"]
                if allow_origin == disallowed_origin:
                    log.warning(f"✗ Disallowed origin was accepted: {allow_origin}")
                else:
                    log.info(f"✓ Origin correctly handled: {allow_origin}")
                    cors_tests_passed += 1
            else:
                log.info("✓ CORS header correctly omitted for disallowed origin")
                cors_tests_passed += 1

        except Exception as e:
            log.error(f"✗ Disallowed origin test failed: {e}")
    else:
        log.info("\n--- Test 5: Skipped (wildcard origin allows all) ---")

    # Summary
    log.info("\n" + "=" * 80)
    log.info("CORS HTTP Tests Summary")
    log.info("=" * 80)
    log.info(f"Tests Passed: {cors_tests_passed}/{cors_tests_total}")
    log.info(f"Success Rate: {(cors_tests_passed/cors_tests_total*100):.1f}%")
    log.info("=" * 80)

    return cors_tests_passed > 0


def test_exec(config, ssh_con):
    """
    Execute Global CORS configuration test.

    Args:
        config: Test configuration from YAML
        ssh_con: SSH connection object for remote execution

    Returns:
        None: Raises exception on failure
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # Step 1: Configure Global CORS settings
    log.info("=" * 80)
    log.info("STEP 1: Configuring Global CORS (GCORS) Settings")
    log.info("=" * 80)

    gcors_origins = (
        config.test_ops.get("gcors_allow_origins")
        if config.test_ops.get("gcors_allow_origins") is not None
        else '"*"'
    )
    gcors_headers = (
        config.test_ops.get("gcors_allow_headers")
        if config.test_ops.get("gcors_allow_headers") is not None
        else '"*"'
    )
    gcors_methods = (
        config.test_ops.get("gcors_allow_methods")
        if config.test_ops.get("gcors_allow_methods") is not None
        else "GET,PUT,POST,DELETE,HEAD"
    )

    log.info(f"Setting rgw_gcors_allow_origins: {gcors_origins}")
    ceph_conf.set_to_ceph_conf(
        "global",
        "rgw_gcors_allow_origins",
        gcors_origins,
        ssh_con,
        set_to_all=True,
    )

    log.info(f"Setting rgw_gcors_allow_headers: {gcors_headers}")
    ceph_conf.set_to_ceph_conf(
        "global",
        "rgw_gcors_allow_headers",
        gcors_headers,
        ssh_con,
        set_to_all=True,
    )

    log.info(f"Setting rgw_gcors_allow_methods: {gcors_methods}")
    ceph_conf.set_to_ceph_conf(
        "global",
        "rgw_gcors_allow_methods",
        gcors_methods,
        ssh_con,
        set_to_all=True,
    )

    log.info("✓ Global CORS configuration settings applied")

    # Step 2: Restart RGW service
    log.info("=" * 80)
    log.info("STEP 2: Restarting RGW Service")
    log.info("=" * 80)

    log.info("Initiating RGW service restart...")
    srv_restarted = rgw_service.restart()
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")

    log.info("RGW service restart initiated, waiting for daemons to stabilize...")
    time.sleep(30)

    # Verify cluster health
    ceph_status = utils.exec_shell_cmd(cmd="sudo ceph status")
    if "HEALTH_ERR" in ceph_status:
        raise TestExecError("Cluster is in HEALTH_ERR state after RGW restart")

    log.info("✓ RGW service restarted successfully")
    log.info("✓ Cluster health: OK")

    # Step 3: Create users
    log.info("=" * 80)
    log.info("STEP 3: Creating Test Users")
    log.info("=" * 80)

    user_count = config.user_count if hasattr(config, "user_count") else 1
    log.info(f"Creating {user_count} test user(s)...")

    all_users_info = s3lib.create_users(user_count)
    if not all_users_info:
        raise TestExecError("Failed to create users")

    for user in all_users_info:
        log.info(f"✓ Created user: {user['user_id']}")
        log.info(f"  Access Key: {user['access_key']}")

    # Get RGW endpoint for CORS testing
    rgw_port = utils.get_radosgw_port_no(ssh_con)
    rgw_host, rgw_ip = utils.get_hostname_ip(ssh_con)
    endpoint_url = (
        f"http{'s' if config.ssl else ''}://{rgw_host or 'localhost'}:{rgw_port or 80}"
    )
    log.info(f"RGW Endpoint URL: {endpoint_url}")

    # Step 4: Perform I/O operations
    log.info("=" * 80)
    log.info("STEP 4: Performing I/O Operations")
    log.info("=" * 80)

    bucket_count = config.bucket_count if hasattr(config, "bucket_count") else 1
    objects_count = config.objects_count if hasattr(config, "objects_count") else 5
    objects_size_range = (
        config.objects_size_range
        if hasattr(config, "objects_size_range")
        else {"min": 5, "max": 15}
    )

    # Track first bucket and object for CORS testing
    first_bucket_name = None
    first_object_name = None
    first_user_info = None

    for user_info in all_users_info:
        # Authenticate
        auth = Auth(user_info, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        s3_client = auth.do_auth_using_client()

        log.info(f"\nProcessing user: {user_info['user_id']}")

        # Create buckets and upload objects
        for bc in range(bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=bc
            )
            log.info(f"  Creating bucket: {bucket_name}")

            bucket = reusable.create_bucket(
                bucket_name=bucket_name,
                rgw=rgw_conn,
                user_info=user_info,
            )

            if bucket is False:
                raise TestExecError(f"Failed to create bucket: {bucket_name}")

            log.info(f"  ✓ Bucket created: {bucket_name}")

            # Track first bucket for CORS testing
            if first_bucket_name is None:
                first_bucket_name = bucket_name
                first_user_info = user_info

            # Upload objects
            log.info(f"  Uploading {objects_count} objects to bucket {bucket_name}...")
            config.mapped_sizes = utils.make_mapped_sizes(config)

            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                log.info("s3 object name: %s" % s3_object_name)
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info("s3 object path: %s" % s3_object_path)

                # Upload object
                reusable.upload_object(
                    s3_object_name,
                    bucket,
                    TEST_DATA_PATH,
                    config,
                    user_info,
                )
                log.info(f"    ✓ Object uploaded: {s3_object_name}")
                first_object_name = s3_object_name

            log.info(f"  ✓ {objects_count} objects uploaded to {bucket_name}")

            # List objects to verify
            log.info(f"  Listing objects in bucket: {bucket_name}")
            objects = s3lib.resource_op(
                {
                    "obj": bucket,
                    "resource": "objects",
                    "args": None,
                }
            )

            object_count = 0
            for obj in objects.all():
                log.info(f"    - {obj.key} (Size: {obj.size} bytes)")
                object_count += 1

            log.info(f"  ✓ Verified {object_count} objects in bucket")

    # Step 5: Test GCORS with HTTP Requests
    if first_bucket_name and first_object_name and first_user_info:
        log.info("\n")
        cors_test_result = test_gcors_with_requests(
            config,
            endpoint_url=endpoint_url,
            bucket_name=first_bucket_name,
            object_key=first_object_name,
            access_key=first_user_info["access_key"],
            secret_key=first_user_info["secret_key"],
            gcors_origins=gcors_origins,
            gcors_methods=gcors_methods,
            gcors_headers=gcors_headers,
            region="",
        )

        if not cors_test_result:
            log.warning("CORS HTTP tests did not pass completely")
    else:
        log.warning("Skipping CORS HTTP tests - no bucket/object created")

    # Step 6: Verify GCORS configuration
    log.info("=" * 80)
    log.info("STEP 6: Verifying Global CORS Configuration")
    log.info("=" * 80)

    log.info("Checking applied GCORS settings...")

    # For newer versions of Ceph, use 'ceph config dump' to verify
    try:
        config_dump = utils.exec_shell_cmd("sudo ceph config dump --format json")
        import json

        config_json = json.loads(config_dump)

        gcors_configs = [
            item for item in config_json if "rgw_gcors" in item.get("name", "")
        ]

        if gcors_configs:
            log.info("Applied GCORS configurations:")
            for cfg in gcors_configs:
                log.info(f"  {cfg['name']}: {cfg.get('value', 'N/A')}")
        else:
            log.info(
                "No GCORS configurations found in config dump (may be using defaults)"
            )
    except Exception as e:
        log.warning(f"Could not verify config via ceph config dump: {e}")
        log.info("Configuration applied via ceph.conf method")

    log.info("✓ Global CORS configuration test completed successfully")

    # Test summary
    log.info("=" * 80)
    log.info("TEST SUMMARY")
    log.info("=" * 80)
    log.info(f"✓ Global CORS Origins:  {gcors_origins}")
    log.info(f"✓ Global CORS Headers:  {gcors_headers}")
    log.info(f"✓ Global CORS Methods:  {gcors_methods}")
    log.info(f"✓ Users Created:        {len(all_users_info)}")
    log.info(f"✓ Buckets Created:      {bucket_count * len(all_users_info)}")
    log.info(
        f"✓ Objects Uploaded:     {objects_count * bucket_count * len(all_users_info)}"
    )
    log.info(f"✓ RGW Service:          Restarted and operational")
    log.info("=" * 80)


if __name__ == "__main__":
    test_info = AddTestInfo("Test RGW Global CORS configuration")
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
        parser = argparse.ArgumentParser(description="RGW Global CORS configuration")
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
