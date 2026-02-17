"""
Test multisite RGW using elbencho with FULL SYNC mode

This script tests multisite RGW deployments using elbencho to validate full sync.
Full sync tests involve stopping the secondary zone, writing data to primary,
then restarting secondary and verifying complete sync.

Test Scenarios:
1. PUT: Test full sync with 1 bucket and 1.3M objects/bkt
2. PUT: Test full sync with 5 buckets and 1.3M objects/bkt
3. PUT: Test full sync with 5 versioned buckets and 1.3M objects/bkt (10 versions each, 2 bytes)
4. LC DELETE: Test full sync with 5 versioned buckets (10 versions → delete all)
5. PUT: Test full sync with 1 bucket with special character object names (%-+) using boto3

Workflow for PUT tests (Scenarios 1-3, 5):
1. Stop secondary zone RGW sync services
2. Create buckets on primary
3. Upload objects to primary (elbencho for 1-3, boto3 for 5)
4. Start secondary zone RGW sync services
5. Verify sync using `radosgw-admin bucket stats` comparison

Workflow for LC DELETE test (Scenario 4):
1. Use buckets from Scenario 3 (5 versioned buckets with 10 versions per object)
2. Stop secondary zone RGW sync services
3. Apply LC deletion policy on primary
4. Wait for deletion to complete on primary (num_objects = 0)
5. Start secondary zone RGW sync services
6. Verify deletion synced to secondary (num_objects = 0)

Size Distribution (for non-versioned tests):
- 25% objects: 1-2B
- 37% objects: 2-4B
- 25% objects: 4-8B
- 3% objects: 8-256B
- 10% objects: 1KB-10KB
Average size: ~600 bytes

Note: Versioned tests use consistent 2-byte objects for all versions

Usage: test_multisite_elbencho_full_sync.py -c <config_yaml>
"""

import concurrent.futures
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import re
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_s3_elbencho as elbencho
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

TEST_DATA_PATH = None
log = logging.getLogger()
from v2.tests.s3_swift.reusables import scale_sync_test


def test_exec(config, ssh_con):
    """
    Main test execution function - runs 5 specific full sync scenarios.

    Args:
        config: Parsed YAML configuration
        ssh_con: SSH connection to RGW node
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()

    io_info_initialize.initialize(basic_io_structure.initial())

    # Verify multisite setup
    scale_sync_test.verify_multisite_setup()

    # Install elbencho on both sites
    log.info("Installing and configuring elbencho on both sites")
    elbencho.elbench_install_configure()

    # Get multisite configuration info (realm, zones)
    # Priority: Config values > Auto-detection > Defaults
    log.info("Getting multisite configuration information...")

    # Check if config has explicit values
    config_realm = config.test_ops.get("rgw_realm")
    config_zones = config.test_ops.get("rgw_zones")
    config_zonegroup = config.test_ops.get("rgw_zonegroup")

    if config_realm and config_zones and config_zonegroup:
        # Use config values (highest priority)
        realm_name = config_realm
        zone_names = config_zones
        zonegroup_name = config_zonegroup
        log.info(f"Using CONFIGURED values:")
        log.info(f"  • Realm: {realm_name}")
        log.info(f"  • Zones: {zone_names}")
        log.info(f"  • Zonegroup: {zonegroup_name}")
    else:
        # Try auto-detection
        try:
            detected_zones, detected_realm = reusable.get_multisite_info()

            # Use detected values, but allow config to override individual fields
            realm_name = config_realm if config_realm else detected_realm
            zone_names = config_zones if config_zones else detected_zones
            zonegroup_name = config_zonegroup if config_zonegroup else "shared"

            log.info(f"Using AUTO-DETECTED values (with config overrides):")
            log.info(
                f"  • Realm: {realm_name} {'(config)' if config_realm else '(detected)'}"
            )
            log.info(
                f"  • Zones: {zone_names} {'(config)' if config_zones else '(detected)'}"
            )
            log.info(
                f"  • Zonegroup: {zonegroup_name} {'(config)' if config_zonegroup else '(default)'}"
            )
        except Exception as e:
            log.warning(f"Could not auto-detect multisite info: {e}")

            # Fall back to config or hardcoded defaults
            realm_name = config_realm if config_realm else "india"
            zone_names = config_zones if config_zones else "primary,secondary"
            zonegroup_name = config_zonegroup if config_zonegroup else "shared"

            log.info(f"Using DEFAULT values:")
            log.info(f"  • Realm: {realm_name}")
            log.info(f"  • Zones: {zone_names}")
            log.info(f"  • Zonegroup: {zonegroup_name}")

    log.info("")

    # Auto-detect which zone the local and remote sites are in
    log.info("=" * 100)
    log.info("AUTO-DETECTING LOCAL AND REMOTE ZONES")
    log.info("=" * 100)
    (
        local_zone,
        remote_zone,
        master_zone,
        zonegroup_config,
    ) = scale_sync_test.detect_local_and_remote_zones()
    (
        local_zone,
        remote_zone,
        master_zone,
        zonegroup_config,
    ) = scale_sync_test.detect_local_and_remote_zones()

    # Determine which is primary/secondary based on master zone
    if local_zone == master_zone:
        primary_zone = local_zone
        secondary_zone = remote_zone
        log.info(f"✓ Local site is MASTER/PRIMARY zone: '{primary_zone}'")
        log.info(f"✓ Remote site is SLAVE/SECONDARY zone: '{secondary_zone}'")
    else:
        primary_zone = remote_zone
        secondary_zone = local_zone
        log.info(f"✓ Remote site is MASTER/PRIMARY zone: '{primary_zone}'")
        log.info(f"✓ Local site is SLAVE/SECONDARY zone: '{secondary_zone}'")

    log.info("=" * 100 + "\n")

    # Validate that zones are different
    if local_zone == remote_zone:
        raise TestExecError(
            f"Local and remote zones cannot be the same! Both are set to: {local_zone}"
        )

    # Configure RGW settings ONLY on the local zone
    log.info("=" * 100)
    log.info(f"CONFIGURING RGW SETTINGS ON LOCAL ZONE ('{local_zone}')")
    log.info("=" * 100 + "\n")

    scale_sync_test.configure_rgw_settings(
        ssh_con=None,
        site_name="local",
        zone_name=local_zone,
        realm_name=realm_name,
        zonegroup_name=zonegroup_name,
    )

    log.info("=" * 100)
    log.info(f"SKIPPING RGW CONFIGURATION ON REMOTE ZONE ('{remote_zone}')")
    log.info("Remote zone configuration should be done on the remote cluster")
    log.info("=" * 100 + "\n")

    log.info("=" * 100)
    log.info("✓ RGW CONFIGURATION SUMMARY")
    log.info("=" * 100)
    log.info(f"LOCAL ZONE ('{local_zone}') configured with:")
    log.info(f"  • rgw_zone = {local_zone}")
    log.info(f"  • rgw_realm = {realm_name}")
    log.info(f"  • rgw_zonegroup = {zonegroup_name}")
    log.info(f"  • Is Master: {local_zone == master_zone}")
    log.info("")
    log.info(f"REMOTE ZONE ('{remote_zone}'):")
    log.info(f"  • rgw_zone = {remote_zone}")
    log.info(f"  • Configuration skipped (done on remote cluster)")
    log.info(f"  • Is Master: {remote_zone == master_zone}")
    log.info("=" * 100 + "\n")

    # Get endpoints from zonegroup configuration
    log.info("=" * 100)
    log.info("DISCOVERING ENDPOINTS FROM ZONEGROUP CONFIGURATION")
    log.info("=" * 100)
    local_endpoint = elbencho.get_endpoint_elbencho(zone_name=local_zone)
    remote_endpoint = elbencho.get_remote_endpoint_elbencho(zone_name=remote_zone)

    if not local_endpoint:
        raise TestExecError(f"Failed to get local endpoint for zone '{local_zone}'")
    if not remote_endpoint:
        raise TestExecError(f"Failed to get remote endpoint for zone '{remote_zone}'")

    log.info(f"✓ Local endpoint (zone '{local_zone}'): {local_endpoint}")
    log.info(f"✓ Remote endpoint (zone '{remote_zone}'): {remote_endpoint}")
    log.info(
        f"✓ Primary/Master endpoint (zone '{primary_zone}'): {local_endpoint if primary_zone == local_zone else remote_endpoint}"
    )
    log.info(
        f"✓ Secondary/Slave endpoint (zone '{secondary_zone}'): {remote_endpoint if secondary_zone == remote_zone else local_endpoint}"
    )
    log.info("=" * 100 + "\n")

    # Get the ha_io host for the endpoint (HAProxy at port 5000)
    log.info("=" * 100)
    log.info(f"GETTING HA_IO HOST FOR ENDPOINT (HAProxy)")
    log.info("=" * 100)
    ha_io_hostname = scale_sync_test.get_local_ha_io_hostname()
    if not ha_io_hostname:
        log.warning("Could not get ha_io host, falling back to default detection")
        ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
    else:
        # Use ha_io host at port 5000 (HAProxy)
        # Format: "hostname:5000" or "https://hostname:5000" if SSL
        haproxy_port = 5000
        if config.ssl:
            ip_and_port = f"https://{ha_io_hostname}:{haproxy_port}"
        else:
            ip_and_port = f"{ha_io_hostname}:{haproxy_port}"
        log.info(f"✓ Using ha_io endpoint (HAProxy): {ip_and_port}")
    log.info("=" * 100 + "\n")

    # Determine which SSH connection and site name to use for secondary zone operations
    # The secondary zone is where we stop services for full sync tests
    if secondary_zone == local_zone:
        # Local site is the secondary/slave - stop services locally
        secondary_ssh_con = None
        secondary_site_name = "local (secondary/slave)"
        log.info(f"⚠ WARNING: Local site is the SECONDARY/SLAVE zone!")
        log.info(f"⚠ Full sync tests typically run from the PRIMARY/MASTER zone.")
        log.info(
            f"⚠ Services will be stopped on the LOCAL site (zone '{secondary_zone}').\n"
        )
    else:
        # Remote site is the secondary/slave - stop services remotely
        # Establish SSH connection to the secondary zone
        log.info(f"✓ Local site is the PRIMARY/MASTER zone ('{primary_zone}')")
        log.info(
            f"✓ Services will be stopped on the REMOTE site (zone '{secondary_zone}')."
        )
        secondary_ssh_con = scale_sync_test.get_remote_conn_for_zone(secondary_zone)
        secondary_site_name = "remote (secondary/slave)"

    # Run sanity check if configured
    if config.test_ops.get("run_sanity_check", False):
        sanity_passed = scale_sync_test.run_sanity_check(
            config,
            ssh_con,
            realm_name,
            secondary_zone,
            secondary_ssh_con,
            secondary_site_name,
        )
        if not sanity_passed:
            raise TestExecError("Sanity check failed - aborting test")

        # Ask user if they want to proceed
        log.info("\nSanity check completed successfully!")
        proceed = (
            input("\nDo you want to proceed with the full test? (yes/no): ")
            .strip()
            .lower()
        )
        if proceed not in ["yes", "y"]:
            log.info("Test aborted by user after sanity check")
            return

    # Store bucket names for each scenario
    scenario_buckets = {
        "scenario1": [],  # 1 bucket
        "scenario2": [],  # 5 buckets
        "scenario3": [],  # 5 versioned buckets (will be reused in scenario 4)
        "scenario5": [],  # 1 bucket with special characters
    }

    # Create test user for all scenarios
    log.info("Creating test user for all scenarios")
    all_users_info = s3lib.create_users(1)
    test_user = all_users_info[0]
    log.info(f"Created test user: {test_user['user_id']}")

    # Authenticate with ha_io endpoint (HAProxy at port 5000)
    auth = Auth(test_user, ssh_con, ssl=config.ssl, haproxy=True)
    # Override endpoint URL to use ha_io hostname if available
    if ha_io_hostname:
        haproxy_port = 5000
        auth.endpoint_url = (
            f"https://{ha_io_hostname}:{haproxy_port}"
            if config.ssl
            else f"http://{ha_io_hostname}:{haproxy_port}"
        )
        log.info(f"Overriding Auth endpoint to use ha_io host: {auth.endpoint_url}")
    else:
        log.info(f"Using default Auth endpoint (HAProxy): {auth.endpoint_url}")

    # Use zonegroup name as region for multisite compatibility
    log.info(f"Using zonegroup '{zonegroup_name}' as region for boto3")
    rgw_conn = auth.do_auth(region_name=zonegroup_name)

    # Verify authentication works by listing buckets
    log.info("Verifying authentication on ha_io endpoint...")
    try:
        # Try to list buckets as a connectivity test
        list(rgw_conn.buckets.limit(1))
        log.info(f"✓ Authentication successful on endpoint {auth.endpoint_url}")
    except Exception as e:
        log.error(f"Authentication failed on ha_io endpoint: {e}")
        log.info("Waiting 10 seconds for user metadata to sync to HAProxy endpoint...")
        time.sleep(10)
        # Retry
        try:
            list(rgw_conn.buckets.limit(1))
            log.info(
                f"✓ Authentication successful on endpoint {auth.endpoint_url} after retry"
            )
        except Exception as retry_e:
            raise TestExecError(
                f"Authentication failed on ha_io endpoint {auth.endpoint_url} even after retry. "
                f"Error: {retry_e}. Check that HAProxy is running on port 5000 and user '{test_user['user_id']}' exists."
            )

    # Get test parameters
    objects_per_bucket = config.test_ops.get(
        "objects_per_bucket", 1300000
    )  # Default/fallback
    threads = config.test_ops.get("threads", 200)

    # Per-scenario object counts (with fallback to global objects_per_bucket)
    scenario1_objects = config.test_ops.get(
        "scenario1_objects_per_bucket", objects_per_bucket
    )
    scenario2_objects = config.test_ops.get(
        "scenario2_objects_per_bucket", objects_per_bucket
    )
    scenario3_objects = config.test_ops.get(
        "scenario3_objects_per_bucket", objects_per_bucket
    )
    scenario4_objects = config.test_ops.get(
        "scenario4_objects_per_bucket", objects_per_bucket
    )
    scenario5_objects = config.test_ops.get(
        "scenario5_objects_per_bucket", objects_per_bucket
    )

    # Track scenario results
    scenario_results = {
        "scenario1": {"status": "SKIPPED", "error": None},
        "scenario2": {"status": "SKIPPED", "error": None},
        "scenario3": {"status": "SKIPPED", "error": None},
        "scenario4": {"status": "SKIPPED", "error": None},
        "scenario5": {"status": "SKIPPED", "error": None},
    }

    # =============================================================================
    # SCENARIO 1: Full sync with 1 bucket and 1.3M objects
    # =============================================================================
    if config.test_ops.get("run_scenario1", True):
        try:
            log.info("\n" + "=" * 100)
            log.info("SCENARIO 1: Full sync with 1 bucket and 1.3M objects/bucket")
            log.info("=" * 100 + "\n")

            # Stop RGW services for the specified realm on secondary zone (with retry until stopped)
            log.info(
                f"STEP 1: Stopping RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.stop_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )

            # Verify secondary is stopped via sync status (should show expected error)
            # Retry verification up to 3 times with 30 second waits
            is_stopped = False
            for verify_attempt in range(1, 4):
                log.info(f"Verification attempt {verify_attempt}/3")
                is_stopped = scale_sync_test.verify_secondary_stopped_via_sync_status()
                if is_stopped:
                    break
                if verify_attempt < 3:
                    log.info(f"Waiting 30 seconds before retry...")
                    time.sleep(30)

            if not is_stopped:
                raise TestExecError(
                    "Secondary zone is not fully stopped. Sync status does not show expected error. "
                    "This could indicate RGW services are still running on secondary."
                )
            log.info("✓ Secondary zone stopped\n")

            # Create bucket on primary
            log.info("STEP 2: Creating 1 bucket on primary")
            bucket_name = f"{test_user['user_id']}-scenario1-bkt-0"
            bucket = reusable.create_bucket(
                bucket_name, rgw_conn, test_user, ip_and_port, skip_sync_check=True
            )
            scenario_buckets["scenario1"].append(bucket_name)
            log.info(f"✓ Created bucket: {bucket_name}\n")

            # Upload objects to primary
            log.info(f"STEP 3: Uploading {scenario1_objects} objects to primary")
            scale_sync_test.run_elbencho_with_size_distribution(
                local_endpoint,
                "primary",
                scenario1_objects,
                scenario_buckets["scenario1"],
                test_user,
                threads,
                {"use_special_chars": False},
            )
            log.info("✓ Upload complete\n")

            # Start RGW services for the specified realm on secondary zone (with retry until running)
            log.info(
                f"STEP 4: Starting RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.start_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info("✓ Secondary zone started\n")

            # Verify sync
            log.info("STEP 5: Verifying sync using bucket stats")
            time.sleep(60)  # Initial wait for sync to start
            scale_sync_test.verify_sync_using_bucket_stats(
                scenario_buckets["scenario1"], secondary_ssh_con
            )
            log.info("✅ SCENARIO 1 COMPLETED SUCCESSFULLY\n")
            scenario_results["scenario1"]["status"] = "PASSED"
        except Exception as e:
            log.error(f"\n❌ SCENARIO 1 FAILED: {str(e)}\n")
            scenario_results["scenario1"]["status"] = "FAILED"
            scenario_results["scenario1"]["error"] = str(e)
            # Continue to next scenario

    # =============================================================================
    # SCENARIO 2: Full sync with 5 buckets and 1.3M objects each
    # =============================================================================
    if config.test_ops.get("run_scenario2", True):
        try:
            log.info("\n" + "=" * 100)
            log.info("SCENARIO 2: Full sync with 5 buckets and 1.3M objects/bucket")
            log.info("=" * 100 + "\n")

            # Stop secondary zone (with retry until stopped)
            log.info(
                f"STEP 1: Stopping RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.stop_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )

            # Verify secondary is stopped via sync status (should show expected error)
            # Retry verification up to 3 times with 30 second waits
            is_stopped = False
            for verify_attempt in range(1, 4):
                log.info(f"Verification attempt {verify_attempt}/3")
                is_stopped = scale_sync_test.verify_secondary_stopped_via_sync_status()
                if is_stopped:
                    break
                if verify_attempt < 3:
                    log.info(f"Waiting 30 seconds before retry...")
                    time.sleep(30)

            if not is_stopped:
                raise TestExecError(
                    "Secondary zone is not fully stopped. Sync status does not show expected error. "
                    "This could indicate RGW services are still running on secondary."
                )
            log.info("✓ Secondary zone stopped\n")

            # Create 5 buckets on primary
            log.info("STEP 2: Creating 5 buckets on primary")
            for i in range(5):
                bucket_name = f"{test_user['user_id']}-scenario2-bkt-{i}"
                bucket = reusable.create_bucket(
                    bucket_name, rgw_conn, test_user, ip_and_port, skip_sync_check=True
                )
                scenario_buckets["scenario2"].append(bucket_name)
                log.info(f"  Created bucket: {bucket_name}")
            log.info(f"✓ Created {len(scenario_buckets['scenario2'])} buckets\n")

            # Upload objects to primary
            log.info(
                f"STEP 3: Uploading {scenario2_objects} objects per bucket to primary"
            )
            scale_sync_test.run_elbencho_with_size_distribution(
                local_endpoint,
                "primary",
                scenario2_objects,
                scenario_buckets["scenario2"],
                test_user,
                threads,
                {"use_special_chars": False},
            )
            log.info("✓ Upload complete\n")

            # Start secondary zone (with retry until running)
            log.info(
                f"STEP 4: Starting RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.start_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info("✓ Secondary zone started\n")

            # Verify sync
            log.info("STEP 5: Verifying sync using bucket stats")
            time.sleep(60)  # Initial wait for sync to start
            scale_sync_test.verify_sync_using_bucket_stats(
                scenario_buckets["scenario2"], secondary_ssh_con
            )
            log.info("✅ SCENARIO 2 COMPLETED SUCCESSFULLY\n")
            scenario_results["scenario2"]["status"] = "PASSED"
        except Exception as e:
            log.error(f"\n❌ SCENARIO 2 FAILED: {str(e)}\n")
            scenario_results["scenario2"]["status"] = "FAILED"
            scenario_results["scenario2"]["error"] = str(e)
            # Continue to next scenario

    # =============================================================================
    # SCENARIO 3: Full sync with 5 versioned buckets, 1.3M objects, 10 versions each
    # =============================================================================
    if config.test_ops.get("run_scenario3", True):
        try:
            log.info("\n" + "=" * 100)
            log.info(
                "SCENARIO 3: Full sync with 5 versioned buckets, 1.3M objects, 10 versions/object"
            )
            log.info("=" * 100 + "\n")

            # Stop secondary zone (with retry until stopped)
            log.info(
                f"STEP 1: Stopping RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.stop_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )

            # Verify secondary is stopped via sync status (should show expected error)
            # Retry verification up to 3 times with 30 second waits
            is_stopped = False
            for verify_attempt in range(1, 4):
                log.info(f"Verification attempt {verify_attempt}/3")
                is_stopped = scale_sync_test.verify_secondary_stopped_via_sync_status()
                if is_stopped:
                    break
                if verify_attempt < 3:
                    log.info(f"Waiting 30 seconds before retry...")
                    time.sleep(30)

            if not is_stopped:
                raise TestExecError(
                    "Secondary zone is not fully stopped. Sync status does not show expected error. "
                    "This could indicate RGW services are still running on secondary."
                )
            log.info("✓ Secondary zone stopped\n")

            # Create 5 versioned buckets on primary
            log.info("STEP 2: Creating 5 versioned buckets on primary")
            for i in range(5):
                bucket_name = f"{test_user['user_id']}-scenario3-bkt-{i}"
                bucket = reusable.create_bucket(
                    bucket_name, rgw_conn, test_user, ip_and_port, skip_sync_check=True
                )
                # Enable versioning
                reusable.enable_versioning(
                    bucket, rgw_conn, test_user, write_bucket_io_info
                )
                scenario_buckets["scenario3"].append(bucket_name)
                log.info(f"  Created versioned bucket: {bucket_name}")
            log.info(
                f"✓ Created {len(scenario_buckets['scenario3'])} versioned buckets\n"
            )

            # Upload 10 versions of objects to primary
            log.info(
                f"STEP 3: Uploading {scenario3_objects} objects with 10 versions each to primary"
            )
            scale_sync_test.run_versioned_workload(
                local_endpoint,
                "primary",
                scenario3_objects,
                scenario_buckets["scenario3"],
                test_user,
                threads,
                version_count=10,
            )
            log.info("✓ Upload complete (10 versions per object)\n")

            # Start secondary zone (with retry until running)
            log.info(
                f"STEP 4: Starting RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.start_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info("✓ Secondary zone started\n")

            # Verify sync
            log.info("STEP 5: Verifying sync using bucket stats")
            time.sleep(60)  # Initial wait for sync to start
            scale_sync_test.verify_sync_using_bucket_stats(
                scenario_buckets["scenario3"], secondary_ssh_con
            )
            log.info("✅ SCENARIO 3 COMPLETED SUCCESSFULLY\n")
            scenario_results["scenario3"]["status"] = "PASSED"
        except Exception as e:
            log.error(f"\n❌ SCENARIO 3 FAILED: {str(e)}\n")
            scenario_results["scenario3"]["status"] = "FAILED"
            scenario_results["scenario3"]["error"] = str(e)
            # Continue to next scenario

    # =============================================================================
    # SCENARIO 4: LC DELETE - Full sync with 5 versioned buckets (10 versions → delete all)
    # =============================================================================
    if config.test_ops.get("run_scenario4", True):
        try:
            log.info("\n" + "=" * 100)
            log.info(
                "SCENARIO 4: LC DELETE - Full sync with 5 versioned buckets (10 versions → delete all)"
            )
            log.info("Using buckets from Scenario 3")
            log.info("=" * 100 + "\n")

            if not scenario_buckets["scenario3"]:
                raise TestExecError(
                    "Scenario 3 buckets not available for scenario 4. Run scenario 3 first."
                )

            # Stop secondary zone - ALL RGW services
            log.info(
                f"STEP 1: Stopping RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.stop_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info("✓ Secondary zone stopped\n")

            # Apply LC deletion policy and process until bucket stats = 0
            log.info(
                "STEP 2: Applying LC deletion policy to delete object versions on primary (10 versions per object)"
            )

            lc_max_wait = config.test_ops.get(
                "lc_max_wait_time", 10800
            )  # Default 3 hours
            lc_check_interval = 30  # Check every 30 seconds
            expiration_days = config.test_ops.get("lc_expiration_days", 1)

            # Apply initial LC policy for object versions (not delete markers yet)
            log.info(
                "\nApplying initial LC policy to delete object versions on primary"
            )
            for bucket_name in scenario_buckets["scenario3"]:
                bucket = rgw_conn.Bucket(bucket_name)
                scale_sync_test.setup_lifecycle_expiration(
                    bucket, rgw_conn, expiration_days
                )
            log.info(
                f"✓ LC policies applied to {len(scenario_buckets['scenario3'])} buckets\n"
            )

            # Process LC until bucket stats show num_objects = 0
            log.info("STEP 3: Processing LC on primary until bucket stats = 0")
            primary_stats = scale_sync_test.process_lc_until_bucket_stats_zero(
                bucket_names=scenario_buckets["scenario3"],
                ssh_con=None,
                site_name="primary",
                objects_per_bucket=scenario4_objects,
                version_count=10,  # Total 10 versions per object
                max_wait_time=lc_max_wait,
                check_interval=lc_check_interval,
            )

            log.info(f"\n{'='*80}")
            log.info(f"PRIMARY LC DELETION STATISTICS:")
            log.info(
                f"  Time taken: {primary_stats['time_seconds']} seconds ({primary_stats['time_seconds']/60:.1f} minutes)"
            )
            log.info(f"  Total buckets: {primary_stats['total_buckets']}")
            log.info(f"  Objects per bucket: {primary_stats['objects_per_bucket']:,}")
            log.info(f"  Versions per object: {primary_stats['version_count']}")
            log.info(
                f"  Total versions deleted per bucket: {primary_stats['objects_per_bucket'] * primary_stats['version_count']:,}"
            )
            log.info(f"{'='*80}\n")

            # Start secondary zone - RGW services for the specified realm
            log.info(
                f"STEP 4: Starting RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.start_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info("✓ Secondary zone started\n")

            # Monitor sync on secondary - wait for bucket stats to reach 0
            log.info(
                "STEP 5: Verifying LC deletion sync to secondary (waiting for bucket stats = 0)"
            )
            time.sleep(60)  # Initial wait for sync to start

            lc_sync_max_wait = config.test_ops.get(
                "lc_max_wait_time", 10800
            )  # Default 3 hours
            lc_sync_check_interval = 30  # Check every 30 seconds

            # Monitor secondary bucket stats until num_objects = 0 (no LC processing, just monitoring sync)
            secondary_stats = scale_sync_test.process_lc_until_bucket_stats_zero(
                bucket_names=scenario_buckets["scenario3"],
                ssh_con=secondary_ssh_con,
                site_name="secondary",
                objects_per_bucket=scenario4_objects,
                version_count=10,  # Total 10 versions per object
                max_wait_time=lc_sync_max_wait,
                check_interval=lc_sync_check_interval,
                process_lc=False,  # Only monitor bucket stats, don't process LC on secondary
            )

            log.info(f"\n{'='*80}")
            log.info(f"SECONDARY LC DELETION SYNC STATISTICS:")
            log.info(
                f"  Time taken: {secondary_stats['time_seconds']} seconds ({secondary_stats['time_seconds']/60:.1f} minutes)"
            )
            log.info(f"  Total buckets: {secondary_stats['total_buckets']}")
            log.info(f"  Objects per bucket: {secondary_stats['objects_per_bucket']:,}")
            log.info(f"  Versions per object: {secondary_stats['version_count']}")
            log.info(f"{'='*80}\n")

            # Get RGW connection on secondary for bucket list/index verification
            auth_secondary = Auth(test_user, secondary_ssh_con, ssl=config.ssl)
            rgw_conn_secondary = auth_secondary.do_auth(region_name=zonegroup_name)

            # Verify bucket list and index on PRIMARY
            log.info("STEP 6: Verifying bucket list and index on PRIMARY")
            scale_sync_test.verify_and_cleanup_bucket_list_and_index(
                bucket_names=scenario_buckets["scenario3"],
                rgw_conn=rgw_conn,
                ssh_con=None,
                site_name="primary",
                lc_expiration_days=expiration_days,
                max_wait_time=lc_max_wait,
                check_interval=lc_check_interval,
            )
            log.info("✓ Primary bucket list and index verification complete\n")

            # Verify bucket list and index on SECONDARY
            log.info("STEP 7: Verifying bucket list and index on SECONDARY")
            scale_sync_test.verify_and_cleanup_bucket_list_and_index(
                bucket_names=scenario_buckets["scenario3"],
                rgw_conn=rgw_conn_secondary,
                ssh_con=secondary_ssh_con,
                site_name="secondary",
                lc_expiration_days=expiration_days,
                max_wait_time=lc_sync_max_wait,
                check_interval=lc_sync_check_interval,
            )
            log.info("✓ Secondary bucket list and index verification complete\n")

            log.info(f"\n{'='*80}")
            log.info(f"SCENARIO 4 LC DELETION SUMMARY:")
            log.info(
                f"  Primary LC processing: {primary_stats['time_seconds']} seconds ({primary_stats['time_seconds']/60:.1f} minutes)"
            )
            log.info(
                f"  Secondary sync time: {secondary_stats['time_seconds']} seconds ({secondary_stats['time_seconds']/60:.1f} minutes)"
            )
            log.info(f"  Total objects per bucket: {scenario4_objects:,}")
            log.info(f"  Total versions per object: 10")
            log.info(f"  Total buckets: {len(scenario_buckets['scenario3'])}")
            log.info(f"{'='*80}\n")

            log.info("✅ SCENARIO 4 COMPLETED SUCCESSFULLY\n")
            scenario_results["scenario4"]["status"] = "PASSED"
        except Exception as e:
            log.error(f"\n❌ SCENARIO 4 FAILED: {str(e)}\n")
            scenario_results["scenario4"]["status"] = "FAILED"
            scenario_results["scenario4"]["error"] = str(e)
            # Continue to next scenario

    # =============================================================================
    # SCENARIO 5: Full sync with 1 bucket and special character object names (boto3)
    # =============================================================================
    if config.test_ops.get("run_scenario5", True):
        try:
            log.info("\n" + "=" * 100)
            log.info(
                "SCENARIO 5: Full sync with 1 bucket and special character object names"
            )
            log.info("Using boto3 with 200 threads | Object names contain: %-+")
            log.info("=" * 100 + "\n")

            # Stop ALL RGW services on secondary zone
            log.info(
                f"STEP 1: Stopping RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.stop_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )

            # Verify secondary is stopped via sync status (should show expected error)
            # Retry verification up to 3 times with 30 second waits
            is_stopped = False
            for verify_attempt in range(1, 4):
                log.info(f"Verification attempt {verify_attempt}/3")
                is_stopped = scale_sync_test.verify_secondary_stopped_via_sync_status()
                if is_stopped:
                    break
                if verify_attempt < 3:
                    log.info(f"Waiting 30 seconds before retry...")
                    time.sleep(30)

            if not is_stopped:
                raise TestExecError(
                    "Secondary zone is not fully stopped. Sync status does not show expected error. "
                    "This could indicate RGW services are still running on secondary."
                )
            log.info("✓ Secondary zone stopped\n")

            # Create bucket on primary
            log.info("STEP 2: Creating 1 bucket on primary")
            bucket_name = f"{test_user['user_id']}-scenario5-special-chars-bkt"
            bucket = reusable.create_bucket(
                bucket_name, rgw_conn, test_user, ip_and_port, skip_sync_check=True
            )
            scenario_buckets["scenario5"].append(bucket_name)
            log.info(f"✓ Created bucket: {bucket_name}\n")

            # Upload objects with special characters using boto3
            log.info(
                f"STEP 3: Uploading {scenario5_objects:,} objects with special character names to primary"
            )
            log.info(f"Using boto3 with {threads} threads")
            scale_sync_test.run_boto3_workload_with_special_chars(
                rgw_conn=rgw_conn,
                zone_name="primary",
                num_objects=scenario5_objects,
                buckets=scenario_buckets["scenario5"],
                threads=threads,
            )
            log.info("✓ Upload complete\n")

            # Start ALL RGW services on secondary zone
            log.info(
                f"STEP 4: Starting RGW services for realm '{realm_name}' on secondary"
            )
            elbencho.start_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info("✓ Secondary zone started\n")

            # Verify sync
            log.info("STEP 5: Verifying sync using bucket stats")
            time.sleep(60)  # Initial wait for sync to start
            scale_sync_test.verify_sync_using_bucket_stats(
                scenario_buckets["scenario5"], secondary_ssh_con
            )
            log.info("✅ SCENARIO 5 COMPLETED SUCCESSFULLY\n")
            scenario_results["scenario5"]["status"] = "PASSED"
        except Exception as e:
            log.error(f"\n❌ SCENARIO 5 FAILED: {str(e)}\n")
            scenario_results["scenario5"]["status"] = "FAILED"
            scenario_results["scenario5"]["error"] = str(e)
            # Continue to final checks

    # =============================================================================
    # SCENARIO RESULTS SUMMARY
    # =============================================================================
    log.info("\n" + "=" * 100)
    log.info("SCENARIO RESULTS SUMMARY")
    log.info("=" * 100 + "\n")

    passed_count = 0
    failed_count = 0
    skipped_count = 0

    for scenario, result in scenario_results.items():
        status_icon = (
            "✅"
            if result["status"] == "PASSED"
            else "❌"
            if result["status"] == "FAILED"
            else "⊘"
        )
        log.info(f"{status_icon} {scenario.upper()}: {result['status']}")
        if result["error"]:
            log.info(f"   Error: {result['error']}")

        if result["status"] == "PASSED":
            passed_count += 1
        elif result["status"] == "FAILED":
            failed_count += 1
        else:
            skipped_count += 1

    log.info(f"\n{'='*100}")
    log.info(
        f"Total: {len(scenario_results)} | Passed: {passed_count} | Failed: {failed_count} | Skipped: {skipped_count}"
    )
    log.info(f"{'='*100}\n")

    # =============================================================================
    # FINAL HEALTH CHECKS
    # =============================================================================
    log.info("\n" + "=" * 100)
    log.info("RUNNING FINAL HEALTH CHECKS")
    log.info("=" * 100 + "\n")

    # Check for crashes
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("Ceph daemon crash detected!")

    # Check cluster health
    log.info("Checking cluster health")
    out = utils.get_ceph_status()
    if not out:
        raise TestExecError("Cluster health check failed")

    # Final status
    log.info("\n" + "=" * 100)
    if failed_count == 0 and passed_count > 0:
        log.info("TEST COMPLETED - ALL RUN SCENARIOS PASSED")
    elif failed_count > 0:
        log.info(f"TEST COMPLETED - {failed_count} SCENARIO(S) FAILED")
    else:
        log.info("TEST COMPLETED - NO SCENARIOS WERE RUN")
    log.info("=" * 100)

    # Return status based on results
    if failed_count > 0:
        raise TestExecError(f"Test failed: {failed_count} scenario(s) failed")


if __name__ == "__main__":
    test_info = AddTestInfo("Multisite RGW elbencho full sync test - 5 scenarios")

    try:
        # Setup test data directory
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)

        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        # Parse arguments
        parser = argparse.ArgumentParser(
            description="RGW Multisite Elbencho Full Sync Test Suite - 4 Scenarios"
        )
        parser.add_argument(
            "-c", dest="config", required=True, help="RGW Test YAML configuration"
        )
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node IP", default="127.0.0.1"
        )
        args = parser.parse_args()

        # Setup logging
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())

        # Connect to RGW node
        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)

        # Load config
        config = Config(yaml_file)
        try:
            config.read()
        except TypeError as e:
            # Workaround for set_frontend() argument mismatch in older framework versions
            if "set_frontend()" in str(e):
                log.warning(f"Config.read() failed with SSL configuration error: {e}")
                log.warning("Using manual config reading as workaround")

                # Read YAML manually
                import yaml

                with open(yaml_file, "r") as f:
                    yaml_config = yaml.safe_load(f)

                # Set config attributes manually
                config.user_count = yaml_config["config"].get("user_count", 1)
                config.bucket_count = yaml_config["config"].get("bucket_count", 1)
                config.ssl = yaml_config["config"].get("ssl", False)

                # Create test_ops namespace
                class TestOps:
                    def __init__(self, ops_dict):
                        for key, value in ops_dict.items():
                            setattr(self, key, value)

                    def get(self, key, default=None):
                        return getattr(self, key, default)

                config.test_ops = TestOps(yaml_config["config"].get("test_ops", {}))
            else:
                raise

        # Start test
        test_info.started_info()
        test_exec(config, ssh_con)
        test_info.success_status("Test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(f"Test failed: {e}")
        log.error(traceback.format_exc())
        test_info.failed_status("Test failed")
        sys.exit(1)

    finally:
        if TEST_DATA_PATH and os.path.exists(TEST_DATA_PATH):
            utils.cleanup_test_data_path(TEST_DATA_PATH)
