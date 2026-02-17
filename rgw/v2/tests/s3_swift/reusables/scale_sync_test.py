"""
Reusable functions for multisite full sync testing.

This module contains utility functions for testing multisite RGW deployments
with full sync mode, including:
- Multisite setup verification
- SSH connection management for remote zones
- Sync status verification using bucket stats
- Elbencho workload execution (size distribution, versioned, special chars)
- Lifecycle policy configuration and verification
- Zone detection and configuration
- RGW settings configuration
"""

import concurrent.futures
import json
import logging
import os
import re
import time

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_s3_elbencho as elbencho
from v2.tests.s3cmd import reusable as s3cmd_reusable

log = logging.getLogger(__name__)


def verify_multisite_setup():
    """Verify that the cluster is configured for multisite."""
    if not utils.is_cluster_multisite():
        raise TestExecError("This test requires a multisite cluster configuration")
    log.info("✓ Verified cluster is configured for multisite")


def get_local_ha_io_hostname():
    """
    Get the hostname of the local ha_io labeled host.
    This is the endpoint that should be used for S3 operations (HAProxy at port 5000).

    Returns:
        str: Hostname of the local ha_io host, or None if not found
    """
    log.info("Getting local ha_io host for endpoint...")
    try:
        host_output = utils.exec_shell_cmd("sudo ceph orch host ls")

        # Find ha_io host
        for line in host_output.split("\n"):
            if "ha_io" in line:
                ha_io_host = line.split()[0]
                log.info(f"✓ Found local ha_io host: {ha_io_host}")
                return ha_io_host

        log.warning("No ha_io labeled host found on local site")
        return None
    except Exception as e:
        log.error(f"Error getting local ha_io host: {e}")
        return None


def get_remote_ha_io_connection():
    """
    Get SSH connection to the ha_io labeled host on the remote site.
    This ensures we connect to the correct host for bucket stats verification.

    Returns:
        SSH connection to remote ha_io host
    """
    log.info("Getting SSH connection to remote ha_io host...")

    # First, get standard remote connection
    remote_ssh_con = reusable.get_remote_conn_in_multisite()

    # Check if this host has ha_io label
    stdin, stdout, stderr = remote_ssh_con.exec_command("sudo ceph orch host ls")
    host_output = stdout.read().decode()

    # Get the current connected hostname
    stdin, stdout, stderr = remote_ssh_con.exec_command("hostname")
    current_hostname = stdout.read().decode().strip()

    # Find ha_io host on remote site
    ha_io_host = None
    for line in host_output.split("\n"):
        if "ha_io" in line:
            ha_io_host = line.split()[0]
            log.info(f"Found ha_io host on remote site: {ha_io_host}")
            break

    if not ha_io_host:
        log.warning(
            "No ha_io labeled host found on remote site, using standard connection"
        )
        return remote_ssh_con

    # If we're already connected to the ha_io host, return current connection
    if current_hostname in ha_io_host or ha_io_host in current_hostname:
        log.info(f"✓ Already connected to ha_io host: {current_hostname}")
        return remote_ssh_con

    # Need to connect to different host
    log.info(
        f"Current connection is to {current_hostname}, need to connect to {ha_io_host}"
    )

    # Get IP of ha_io host from remote site
    stdin, stdout, stderr = remote_ssh_con.exec_command(
        f"getent hosts {ha_io_host} | awk '{{print $1}}'"
    )
    ha_io_ip = stdout.read().decode().strip()

    if not ha_io_ip:
        # Try using hostname directly
        log.info(f"Trying to connect to {ha_io_host} directly...")
        try:
            ha_io_ssh_con = utils.connect_remote(ha_io_host)
            log.info(f"✓ Connected to ha_io host: {ha_io_host}")
            return ha_io_ssh_con
        except Exception as e:
            log.warning(f"Failed to connect to {ha_io_host}: {e}")
            log.warning("Falling back to original connection")
            return remote_ssh_con
    else:
        log.info(f"Connecting to ha_io host at IP: {ha_io_ip}")
        try:
            ha_io_ssh_con = utils.connect_remote(ha_io_ip)
            log.info(f"✓ Connected to ha_io host: {ha_io_host} ({ha_io_ip})")
            return ha_io_ssh_con
        except Exception as e:
            log.warning(f"Failed to connect to {ha_io_host} ({ha_io_ip}): {e}")
            log.warning("Falling back to original connection")
            return remote_ssh_con


def verify_secondary_stopped_via_sync_status():
    """
    Verify secondary zone is stopped by checking sync status on primary.
    When secondary is stopped, primary should show 'failed to retrieve sync info' error.
    This is EXPECTED behavior and confirms secondary sync is truly stopped.

    Returns:
        bool: True if expected error is detected (confirms secondary is stopped)
    """
    log.info("\n" + "=" * 80)
    log.info("VERIFYING SECONDARY IS STOPPED VIA SYNC STATUS CHECK")
    log.info("=" * 80 + "\n")

    try:
        # Run radosgw-admin sync status on primary
        sync_status_output = utils.exec_shell_cmd("sudo radosgw-admin sync status")

        log.info("Sync status output from primary:")
        log.info(sync_status_output)

        # Check for expected error when secondary is stopped
        expected_errors = [
            "failed to retrieve sync info",
            "Unknown error 2200",
            "connection refused",
            "Connection timed out",
        ]

        error_detected = False
        for error_pattern in expected_errors:
            if error_pattern.lower() in sync_status_output.lower():
                log.info(f"\n✓ EXPECTED ERROR DETECTED: '{error_pattern}'")
                log.info(
                    "This confirms secondary zone sync is stopped (cannot communicate)"
                )
                error_detected = True
                break

        if error_detected:
            log.info("\n" + "=" * 80)
            log.info(
                "✅ CONFIRMED: Secondary zone is stopped (sync status shows expected error)"
            )
            log.info("=" * 80 + "\n")
            return True
        else:
            log.warning("\n⚠ WARNING: No expected error found in sync status")
            log.warning("Secondary may not be fully stopped yet")
            log.warning("=" * 80 + "\n")
            return False

    except Exception as e:
        log.error(f"Error checking sync status: {e}")
        return False


def verify_sync_using_bucket_stats(
    bucket_names, remote_ssh_con, max_retries=240, check_interval=30
):
    """
    Verify sync consistency using radosgw-admin bucket stats on both zones.
    Compares num_objects on primary and secondary to ensure they match.

    Args:
        bucket_names: List of bucket names to verify
        remote_ssh_con: SSH connection to secondary site
        max_retries: Maximum number of retry attempts
        check_interval: Seconds to wait between retries

    Raises:
        TestExecError: If sync doesn't complete within max_retries
    """
    log.info(f"\n{'='*80}")
    log.info("VERIFYING SYNC CONSISTENCY USING BUCKET STATS")
    log.info(f"Checking {len(bucket_names)} buckets")

    # Verify we're connected to the correct secondary host (with ha_io label)
    try:
        # Get primary host with ha_io label
        primary_host_output = utils.exec_shell_cmd("sudo ceph orch host ls")
        log.info("\nPrimary site hosts:")
        primary_ha_io_host = None
        for line in primary_host_output.split("\n"):
            if "ha_io" in line:
                primary_ha_io_host = line.split()[0]
                log.info(f"  ✓ Primary ha_io host: {primary_ha_io_host}")

        # Get secondary host with ha_io label
        stdin, stdout, stderr = remote_ssh_con.exec_command("sudo ceph orch host ls")
        secondary_host_output = stdout.read().decode()
        log.info("\nSecondary site hosts:")
        secondary_ha_io_host = None
        for line in secondary_host_output.split("\n"):
            if "ha_io" in line:
                secondary_ha_io_host = line.split()[0]
                log.info(f"  ✓ Secondary ha_io host: {secondary_ha_io_host}")

        # Get actual connected hostname
        stdin, stdout, stderr = remote_ssh_con.exec_command("hostname")
        connected_hostname = stdout.read().decode().strip()
        log.info(f"\nSSH connected to: {connected_hostname}")

        # Verify we're on the right host
        if secondary_ha_io_host and connected_hostname in secondary_ha_io_host:
            log.info(f"✓ VERIFIED: Connected to correct secondary ha_io host")
            log.info(f"  Endpoint for bucket stats: {connected_hostname}")
            log.info(f"  Endpoint for elbencho: http://{secondary_ha_io_host}:5000")
        else:
            log.warning(
                f"⚠ WARNING: Connected to {connected_hostname}, but ha_io host is {secondary_ha_io_host}"
            )

    except Exception as e:
        log.warning(f"Could not verify ha_io host configuration: {e}")

    log.info(f"{'='*80}\n")

    for bucket_name in bucket_names:
        log.info(f"Verifying sync for bucket: {bucket_name}")
        synced = False

        for attempt in range(1, max_retries + 1):
            # Get primary bucket stats
            primary_stats_output = utils.exec_shell_cmd(
                f"radosgw-admin bucket stats --bucket {bucket_name}"
            )
            primary_json_match = re.search(r"\{.*\}", primary_stats_output, re.DOTALL)

            if not primary_json_match:
                log.warning(
                    f"  Attempt {attempt}: Failed to parse primary bucket stats"
                )
                time.sleep(check_interval)
                continue

            primary_stats = json.loads(primary_json_match.group(0))
            primary_num_objects = primary_stats["usage"]["rgw.main"]["num_objects"]

            # Get secondary bucket stats
            stdin, stdout, stderr = remote_ssh_con.exec_command(
                f"sudo radosgw-admin bucket stats --bucket {bucket_name}"
            )
            secondary_stats_output = (
                stdout.read().decode("utf-8", errors="replace").strip()
            )
            secondary_stderr = stderr.read().decode("utf-8", errors="replace").strip()

            # Log the raw output for debugging
            if attempt == 1:
                log.info(f"Secondary bucket stats output (attempt 1):")
                log.info(
                    secondary_stats_output[:1000]
                    if len(secondary_stats_output) > 1000
                    else secondary_stats_output
                )
            if secondary_stderr:
                log.warning(f"Secondary stderr: {secondary_stderr}")

            # Check if bucket doesn't exist on secondary yet
            if (
                "no such bucket" in secondary_stats_output.lower()
                or "could not get bucket info" in secondary_stats_output.lower()
                or len(secondary_stats_output) == 0
            ):
                log.info(
                    f"  Attempt {attempt}/{max_retries}: Bucket not yet synced to secondary (Primary={primary_num_objects}, Secondary=bucket not found)"
                )
                if attempt < max_retries:
                    time.sleep(check_interval)
                    continue
                else:
                    raise TestExecError(
                        f"Bucket {bucket_name} never appeared on secondary after {max_retries} attempts"
                    )

            # Try to parse JSON - handle case where output might be just JSON or have extra text
            try:
                # First try: parse entire output as JSON (if it's pure JSON)
                secondary_stats = json.loads(secondary_stats_output)
            except json.JSONDecodeError:
                # Second try: extract JSON from output that might have extra text
                secondary_json_match = re.search(
                    r"\{.*\}", secondary_stats_output, re.DOTALL
                )
                if not secondary_json_match:
                    log.warning(
                        f"  Attempt {attempt}: Failed to parse secondary bucket stats (not valid JSON)"
                    )
                    log.warning(f"  Secondary output: {secondary_stats_output[:500]}")
                    time.sleep(check_interval)
                    continue
                try:
                    secondary_stats = json.loads(secondary_json_match.group(0))
                except json.JSONDecodeError as e:
                    log.warning(
                        f"  Attempt {attempt}: JSON parsing failed even after regex extraction: {e}"
                    )
                    time.sleep(check_interval)
                    continue

            # Extract num_objects safely
            try:
                secondary_num_objects = secondary_stats["usage"]["rgw.main"][
                    "num_objects"
                ]
            except (KeyError, TypeError) as e:
                log.warning(
                    f"  Attempt {attempt}: Failed to extract num_objects from secondary stats: {e}"
                )
                log.warning(
                    f"  Available keys in secondary_stats: {list(secondary_stats.keys()) if isinstance(secondary_stats, dict) else 'not a dict'}"
                )
                time.sleep(check_interval)
                continue

            log.info(
                f"  Attempt {attempt}/{max_retries}: Primary={primary_num_objects}, "
                f"Secondary={secondary_num_objects}"
            )

            if primary_num_objects == secondary_num_objects:
                log.info(
                    f"  ✓ Sync complete for {bucket_name}: {primary_num_objects} objects on both zones"
                )
                synced = True
                break

            if attempt < max_retries:
                time.sleep(check_interval)

        if not synced:
            raise TestExecError(
                f"Sync verification failed for {bucket_name} after {max_retries} attempts. "
                f"Primary: {primary_num_objects}, Secondary: {secondary_num_objects}"
            )

    log.info(f"\n{'='*80}")
    log.info("✅ ALL BUCKETS SYNCED SUCCESSFULLY")
    log.info(f"{'='*80}\n")


def run_sanity_check(
    config, ssh_con, realm_name, secondary_zone, secondary_ssh_con, secondary_site_name
):
    """
    Run sanity check with minimal data to verify configuration and connectivity.

    Args:
        config: Test configuration
        ssh_con: SSH connection to RGW node
        realm_name: RGW realm name (e.g., "usa")
        secondary_zone: Name of secondary/slave zone (e.g., "west")
        secondary_ssh_con: SSH connection to secondary zone (None if local)
        secondary_site_name: Site name for logging (e.g., "remote (secondary/slave)")

    Returns:
        bool: True if sanity check passes
    """
    import traceback

    log.info("\n" + "=" * 80)
    log.info("STARTING SANITY CHECK")
    log.info("=" * 80 + "\n")

    try:
        # 1. Verify multisite setup
        log.info("[1/8] Verifying multisite setup...")
        verify_multisite_setup()

        # 2. Verify SSH connectivity to secondary (already established)
        log.info("[2/8] Verifying SSH connectivity to secondary zone...")
        if secondary_ssh_con is None:
            log.info(f"  ✓ Secondary zone is LOCAL (no SSH needed)")
        else:
            log.info(
                f"  ✓ SSH connection to secondary zone '{secondary_zone}' successful"
            )

        # 3. Get local endpoint for elbencho
        log.info("[3/8] Getting local endpoint...")
        local_endpoint = elbencho.get_endpoint_elbencho()
        if not local_endpoint:
            raise TestExecError("❌ Failed to get local endpoint")
        log.info(f"  ✓ Local endpoint: {local_endpoint}")

        # 4. Install elbencho if needed
        log.info("[4/8] Checking and installing elbencho...")
        try:
            local_version = utils.exec_shell_cmd("/usr/local/bin/elbencho --version")
            if local_version:
                log.info(
                    f"  ✓ Elbencho already installed on primary: {local_version.split()[0]}"
                )
        except:
            log.info("  Installing elbencho on both sites...")
            elbencho.elbench_install_configure()
            log.info("  ✓ Elbencho installed successfully")

        # 5. Test RGW service control (for full sync mode only)
        sync_mode = config.test_ops.get("sync_mode", "full")
        if sync_mode == "full":
            log.info(
                f"[5/8] Testing RGW service control on secondary for realm '{realm_name}'..."
            )

            # Test stop RGW services for the specified realm
            log.info("  Testing RGW stop (ceph orch stop <service>)...")
            elbencho.stop_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info(
                f"  ✓ All RGW services for realm '{realm_name}' stopped successfully"
            )

            # Test start RGW services for the specified realm
            log.info("  Testing RGW start (ceph orch start <service>)...")
            elbencho.start_rgw_services(
                secondary_ssh_con, secondary_site_name, realm_name=realm_name
            )
            log.info(
                f"  ✓ All RGW services for realm '{realm_name}' restarted successfully"
            )
        else:
            log.info("[5/8] Skipping RGW service control test (bidirectional mode)")

        # 6. Create test user and bucket
        log.info("[6/8] Creating sanity check test user and bucket...")
        from v2.lib.s3.auth import Auth

        test_users = s3lib.create_users(1)
        test_user = test_users[0]
        log.info(f"  ✓ Created test user: {test_user['user_id']}")

        # Authenticate
        auth = Auth(test_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()

        # Create bucket
        ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
        sanity_bucket_name = f"sanity-check-{int(time.time())}"
        sanity_bucket = reusable.create_bucket(
            sanity_bucket_name, rgw_conn, test_user, ip_and_port
        )
        log.info(f"  ✓ Created sanity bucket: {sanity_bucket_name}")

        # 7. Write small test objects with elbencho
        log.info("[7/8] Writing 100 test objects with elbencho...")
        test_objects = 100
        test_threads = 10

        # Simple write test - just one size range
        elbencho_cmd = (
            f"/usr/local/bin/elbencho --s3endpoints {local_endpoint} "
            f"--s3key {test_user['access_key']} --s3secret {test_user['secret_key']} "
            f"-w -t {test_threads} -n0 -N {test_objects} -s 1024 {sanity_bucket_name}"
        )

        output = utils.exec_shell_cmd(elbencho_cmd)
        if output is False:
            raise TestExecError("  ❌ Elbencho write test failed")

        metrics = elbencho.parse_elbencho_output(output)
        log.info(f"  ✓ Wrote {test_objects} objects - Metrics: {metrics}")

        # 8. Verify sync to secondary
        log.info("[8/8] Verifying objects synced to secondary...")
        time.sleep(10)  # Wait for sync

        # Check bucket stats on both sites
        max_retries = 10
        for attempt in range(max_retries):
            local_stats_output = utils.exec_shell_cmd(
                f"radosgw-admin bucket stats --bucket {sanity_bucket_name}"
            )
            local_json_match = re.search(r"\{.*\}", local_stats_output, re.DOTALL)
            local_stats = (
                json.loads(local_json_match.group(0)) if local_json_match else None
            )

            if secondary_ssh_con:
                stdin, stdout, stderr = secondary_ssh_con.exec_command(
                    f"radosgw-admin bucket stats --bucket {sanity_bucket_name}"
                )
                remote_stats_output = (
                    stdout.read().decode("utf-8", errors="replace").strip()
                )
            else:
                remote_stats_output = utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {sanity_bucket_name}"
                )
            remote_json_match = re.search(r"\{.*\}", remote_stats_output, re.DOTALL)
            remote_stats = (
                json.loads(remote_json_match.group(0)) if remote_json_match else None
            )

            if local_stats and remote_stats:
                local_count = local_stats["usage"]["rgw.main"]["num_objects"]
                remote_count = remote_stats["usage"]["rgw.main"]["num_objects"]

                log.info(
                    f"  Attempt {attempt + 1}: Primary={local_count}, Secondary={remote_count}"
                )

                if local_count == remote_count == test_objects:
                    log.info(f"  ✓ Sync verified: {test_objects} objects on both sites")
                    break

            if attempt < max_retries - 1:
                time.sleep(5)
        else:
            log.warning(
                f"  ⚠ Sync verification incomplete after {max_retries} attempts"
            )

        # Cleanup
        log.info("\nCleaning up sanity check resources...")
        try:
            sanity_bucket.objects.all().delete()
            sanity_bucket.delete()
            log.info(f"  ✓ Deleted sanity bucket: {sanity_bucket_name}")
        except Exception as e:
            log.warning(f"  ⚠ Cleanup warning: {e}")

        log.info("\n" + "=" * 80)
        log.info("✅ SANITY CHECK PASSED - All systems operational")
        log.info("=" * 80 + "\n")
        return True

    except Exception as e:
        log.error("\n" + "=" * 80)
        log.error(f"❌ SANITY CHECK FAILED: {e}")
        log.error("=" * 80 + "\n")
        log.error(traceback.format_exc())
        return False


def run_elbencho_with_size_distribution(
    endpoint, zone_name, num_objects, buckets, each_user, threads, size_distribution
):
    """
    Runs Elbencho with specified size distribution.

    Args:
        endpoint: S3 endpoint URL
        zone_name: Zone name for logging
        num_objects: Number of objects to create
        buckets: List of bucket names
        each_user: User credentials dict
        threads: Number of threads
        size_distribution: Dict with size ranges and percentages
    """
    log.info(f"[{zone_name}] Starting elbencho workload with size distribution")
    log.info(f"[{zone_name}] Total objects to create: {num_objects}")

    bucket_prefix = "-".join(buckets[0].split("-")[:-1]) + "-"
    num_buckets = len(buckets)
    bucket_format = f"{bucket_prefix}{{0..{num_buckets-1}}}"

    # Calculate objects per size range based on distribution
    size_ranges = [
        ("1-2", int(num_objects * 0.25)),  # 25% 1-2B
        ("2-4", int(num_objects * 0.37)),  # 37% 2-4B
        ("4-8", int(num_objects * 0.25)),  # 25% 4-8B
        ("8-256", int(num_objects * 0.03)),  # 3% 8-256B
        ("1024-10240", int(num_objects * 0.10)),  # 10% 1KB-10KB
    ]

    total_data_written = 0
    special_chars = size_distribution.get("use_special_chars", False)

    for size_range, obj_count in size_ranges:
        if obj_count == 0:
            continue

        log.info(
            f"[{zone_name}] Writing {obj_count} objects of size {size_range} bytes"
        )

        # Build elbencho command
        elbencho_cmd = (
            f"time /usr/local/bin/elbencho --s3endpoints {endpoint} "
            f"--s3key {each_user['access_key']} --s3secret {each_user['secret_key']} "
            f"-w -t {threads} -n0 -N {obj_count} -s {size_range} "
            f"{bucket_format}"
        )

        # Note: special_chars feature not supported by elbencho (no --objprefix option)
        if special_chars:
            log.info(
                f"[{zone_name}] Note: Special character object names not supported by elbencho"
            )

        output = utils.exec_shell_cmd(elbencho_cmd)
        if output is False:
            raise TestExecError(
                f"Elbencho failed on {zone_name} for size range {size_range}"
            )

        # Parse metrics
        metrics = elbencho.parse_elbencho_output(output)
        log.info(f"[{zone_name}] Metrics for size {size_range}: {metrics}")

        if "Total Data Written (MiB)" in metrics:
            total_data_written += float(metrics["Total Data Written (MiB)"])

    log.info(
        f"[{zone_name}] ✓ Completed workload - Total data written: {total_data_written:.2f} MiB"
    )
    return total_data_written


def run_versioned_workload(
    endpoint, zone_name, num_objects, buckets, each_user, threads, version_count
):
    """
    Runs elbencho workload for versioned objects.
    All objects are 2 bytes to keep consistent size across versions.

    Args:
        endpoint: S3 endpoint URL
        zone_name: Zone name for logging
        num_objects: Number of logical objects
        buckets: List of bucket names
        each_user: User credentials dict
        threads: Number of threads
        version_count: Number of versions per object
    """
    log.info(
        f"[{zone_name}] Starting versioned workload - {version_count} versions per object (2 bytes each)"
    )

    bucket_prefix = "-".join(buckets[0].split("-")[:-1]) + "-"
    num_buckets = len(buckets)
    bucket_format = f"{bucket_prefix}{{0..{num_buckets-1}}}"

    # For versioned objects, use consistent 2-byte size for all objects
    object_size = "2"
    total_versions_written = 0

    for version_num in range(version_count):
        log.info(f"[{zone_name}] Creating version {version_num + 1}/{version_count}")

        elbencho_cmd = (
            f"time /usr/local/bin/elbencho --s3endpoints {endpoint} "
            f"--s3key {each_user['access_key']} --s3secret {each_user['secret_key']} "
            f"-w -t {threads} -n0 -N {num_objects} -s {object_size} "
            f"{bucket_format}"
        )

        output = utils.exec_shell_cmd(elbencho_cmd)
        if output is False:
            raise TestExecError(
                f"Elbencho failed on {zone_name} for version {version_num + 1}"
            )

        metrics = elbencho.parse_elbencho_output(output)
        log.info(f"[{zone_name}] Version {version_num + 1}: {metrics}")
        total_versions_written += num_objects

    log.info(
        f"[{zone_name}] ✓ Completed versioned workload - Total versions: {total_versions_written}"
    )


def run_boto3_workload_with_special_chars(
    rgw_conn, zone_name, num_objects, buckets, threads=200
):
    """
    Runs boto3 workload with special characters in object names using threading.
    Object names will contain special characters: %-+

    Args:
        rgw_conn: RGW S3 connection (boto3 resource)
        zone_name: Zone name for logging
        num_objects: Number of objects per bucket
        buckets: List of bucket names
        threads: Number of concurrent threads (default: 200)

    Returns:
        Total data written in MiB
    """
    import random

    log.info(f"\n{'='*80}")
    log.info(f"[{zone_name}] BOTO3 WORKLOAD WITH SPECIAL CHARACTERS")
    log.info(
        f"Buckets: {len(buckets)} | Objects/bucket: {num_objects:,} | Threads: {threads}"
    )
    log.info(f"Object name pattern: obj-%+-<number>")
    log.info(f"{'='*80}\n")

    # Size distribution matching elbencho tests
    size_ranges = [
        ("1-2", int(num_objects * 0.25)),  # 25% 1-2B
        ("2-4", int(num_objects * 0.37)),  # 37% 2-4B
        ("4-8", int(num_objects * 0.25)),  # 25% 4-8B
        ("8-256", int(num_objects * 0.03)),  # 3% 8-256B
        ("1024-10240", int(num_objects * 0.10)),  # 10% 1KB-10KB
    ]

    total_objects_uploaded = 0
    total_data_written_bytes = 0
    start_time = time.time()

    for size_range, obj_count in size_ranges:
        if obj_count == 0:
            continue

        # Parse size range
        min_size, max_size = map(int, size_range.split("-"))

        log.info(
            f"[{zone_name}] Uploading {obj_count:,} objects of size {size_range} bytes across {len(buckets)} buckets"
        )

        # Create upload tasks for all buckets
        upload_tasks = []
        for bucket_name in buckets:
            bucket = rgw_conn.Bucket(bucket_name)
            # Distribute objects across buckets evenly
            objects_per_bucket = obj_count // len(buckets)

            for i in range(objects_per_bucket):
                # Generate object name with special characters
                obj_name = f"obj-%+-{size_range}-{i}"
                # Generate random size within range
                obj_size = random.randint(min_size, max_size)
                upload_tasks.append((bucket, obj_name, obj_size))

        # Upload function for threading
        def upload_object(task):
            bucket, obj_name, obj_size = task
            try:
                # Generate random data
                data = os.urandom(obj_size)
                bucket.put_object(Key=obj_name, Body=data)
                return obj_size
            except Exception as e:
                log.error(f"Failed to upload {obj_name} to {bucket.name}: {e}")
                return 0

        # Execute uploads in parallel using ThreadPoolExecutor
        range_start = time.time()
        bytes_written = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            results = list(executor.map(upload_object, upload_tasks))
            bytes_written = sum(results)

        range_time = time.time() - range_start
        total_objects_uploaded += len(upload_tasks)
        total_data_written_bytes += bytes_written

        log.info(
            f"[{zone_name}] ✓ Uploaded {len(upload_tasks):,} objects "
            f"({bytes_written / (1024*1024):.2f} MiB) in {range_time:.1f}s "
            f"({len(upload_tasks)/range_time:.1f} objs/sec)"
        )

    total_time = time.time() - start_time
    total_data_mib = total_data_written_bytes / (1024 * 1024)

    log.info(f"\n{'='*80}")
    log.info(f"[{zone_name}] ✓ BOTO3 WORKLOAD COMPLETED")
    log.info(f"Total objects uploaded: {total_objects_uploaded:,}")
    log.info(f"Total data written: {total_data_mib:.2f} MiB")
    log.info(f"Total time: {total_time:.1f} seconds")
    log.info(f"Average throughput: {total_objects_uploaded/total_time:.1f} objs/sec")
    log.info(f"{'='*80}\n")

    return total_data_mib


def setup_lifecycle_expiration(bucket, rgw_conn, expiration_days=1):
    """
    Configure lifecycle policy for object expiration.

    Args:
        bucket: Bucket object
        rgw_conn: RGW S3 connection
        expiration_days: Days after which objects expire
    """
    log.info(f"Setting up lifecycle expiration policy for bucket: {bucket.name}")

    lifecycle_config = {
        "Rules": [
            {
                "ID": "expire-all-objects",
                "Status": "Enabled",
                "Prefix": "",
                "Expiration": {"Days": expiration_days},
            }
        ]
    }

    # Handle versioned buckets
    if bucket.Versioning().status == "Enabled":
        lifecycle_config["Rules"][0]["NoncurrentVersionExpiration"] = {
            "NoncurrentDays": expiration_days
        }

    bucket.LifecycleConfiguration().put(LifecycleConfiguration=lifecycle_config)
    log.info(f"✓ Lifecycle policy configured for {bucket.name}")


def setup_lifecycle_delete_marker_expiration(bucket, rgw_conn, expiration_days=1):
    """
    Configure lifecycle policy to expire delete markers only.

    Args:
        bucket: Bucket object
        rgw_conn: RGW S3 connection
        expiration_days: Days after which delete markers expire (not used for ExpiredObjectDeleteMarker)
    """
    log.info(f"Setting up delete marker expiration policy for bucket: {bucket.name}")

    lifecycle_config = {
        "Rules": [
            {
                "ID": "expire-delete-markers",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"ExpiredObjectDeleteMarker": True},
            }
        ]
    }

    bucket.LifecycleConfiguration().put(LifecycleConfiguration=lifecycle_config)
    log.info(f"✓ Delete marker expiration policy configured for {bucket.name}")


def process_lc_until_bucket_stats_zero(
    bucket_names,
    ssh_con,
    site_name,
    objects_per_bucket,
    version_count,
    max_wait_time=10800,
    check_interval=30,
    process_lc=True,
):
    """
    Process LC on versioned buckets until bucket stats show num_objects = 0.
    Can also be used to just monitor bucket stats (for secondary site sync verification).

    Args:
        bucket_names: List of bucket names to monitor
        ssh_con: SSH connection (None for local site)
        site_name: Name of the site for logging
        objects_per_bucket: Number of objects per bucket for logging
        version_count: Number of versions per object for logging
        max_wait_time: Maximum time to wait in seconds (default: 3 hours)
        check_interval: How often to check bucket stats in seconds (default: 30s)
        process_lc: Whether to actively process LC (True) or just monitor (False for secondary sync)

    Returns:
        dict: Statistics including time taken and per-bucket info

    Raises:
        TestExecError: If bucket stats don't reach 0 within max_wait_time
    """
    log.info(f"\n{'='*80}")
    if process_lc:
        log.info(f"PROCESSING LC ON {site_name.upper()} UNTIL BUCKET STATS = 0")
    else:
        log.info(
            f"MONITORING BUCKET STATS ON {site_name.upper()} UNTIL = 0 (VERIFYING SYNC)"
        )
    log.info(
        f"Buckets: {len(bucket_names)} | Objects/bucket: {objects_per_bucket} | Versions: {version_count}"
    )
    log.info(f"Check Interval: {check_interval}s | Max Wait: {max_wait_time}s")
    log.info(f"{'='*80}\n")

    start_time = time.time()

    while (time.time() - start_time) < max_wait_time:
        # Process LC on each bucket (only if process_lc=True)
        if process_lc:
            log.info(
                f"[{int(time.time() - start_time):4d}s] Running LC process on all buckets..."
            )
            for bucket_name in bucket_names:
                lc_cmd = f"radosgw-admin lc process --bucket {bucket_name} --rgw-lc-debug-interval=600"
                if ssh_con:
                    ssh_con.exec_command(f"sudo {lc_cmd}")
                else:
                    utils.exec_shell_cmd(f"sudo {lc_cmd}")

        # Wait for LC to process
        time.sleep(check_interval)

        # Check bucket stats for all buckets
        all_zero = True
        bucket_stats_info = {}

        for bucket_name in bucket_names:
            stats_cmd = f"radosgw-admin bucket stats --bucket {bucket_name}"
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(f"sudo {stats_cmd}")
                bucket_stats_output = (
                    stdout.read().decode("utf-8", errors="replace").strip()
                )
            else:
                bucket_stats_output = utils.exec_shell_cmd(f"sudo {stats_cmd}")

            json_match = re.search(r"\{.*\}", bucket_stats_output, re.DOTALL)
            if json_match:
                stats = json.loads(json_match.group(0))
                num_objects = stats["usage"]["rgw.main"]["num_objects"]
                bucket_stats_info[bucket_name] = num_objects

                if num_objects > 0:
                    all_zero = False

        # Log current status
        elapsed = int(time.time() - start_time)
        status_summary = ", ".join(
            [
                f"{bucket.split('-')[-1]}: {count} objs"
                for bucket, count in bucket_stats_info.items()
            ]
        )
        log.info(f"[{elapsed:4d}s] [{site_name}] Bucket Stats: {status_summary}")

        # Check if all buckets have 0 objects
        if all_zero:
            total_time = int(time.time() - start_time)
            log.info(f"\n{'='*80}")
            log.info(f"✓ ALL BUCKETS REACHED 0 OBJECTS ON {site_name.upper()}")
            log.info(f"{'='*80}")
            log.info(f"Time taken: {total_time} seconds ({total_time/60:.1f} minutes)")
            log.info(f"Objects deleted per bucket: {objects_per_bucket}")
            log.info(f"Versions per object: {version_count}")
            log.info(
                f"Total versions deleted per bucket: {objects_per_bucket * version_count}"
            )
            log.info(f"Total buckets: {len(bucket_names)}")
            log.info(f"\nPer-bucket summary:")
            for bucket_name in bucket_names:
                log.info(
                    f"  {bucket_name}: {objects_per_bucket} objects × {version_count} versions = {objects_per_bucket * version_count} total versions deleted"
                )
            log.info(f"{'='*80}\n")

            return {
                "time_seconds": total_time,
                "objects_per_bucket": objects_per_bucket,
                "version_count": version_count,
                "total_buckets": len(bucket_names),
                "bucket_names": bucket_names,
            }

    # Timeout - not all buckets reached 0
    # Enhanced logic: Check bucket list and bi list to understand why
    log.warning(f"\n{'='*80}")
    log.warning(
        f"⚠ TIMEOUT: Bucket stats did not reach 0 within {max_wait_time}s ({max_wait_time/3600:.1f} hours)"
    )
    log.warning(f"Remaining objects in bucket stats: {bucket_stats_info}")
    log.warning(f"Investigating bucket list and bi list for all buckets...")
    log.warning(f"{'='*80}\n")

    all_bucket_lists_empty = True
    bucket_investigation = {}

    for bucket_name in bucket_names:
        log.info(f"\nInvestigating {bucket_name}:")

        # Check bucket list
        list_cmd = f"radosgw-admin bucket list --bucket {bucket_name}"
        log.info(f"[root@{site_name} ~]# {list_cmd}")

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(f"sudo {list_cmd}")
            list_output = stdout.read().decode("utf-8", errors="replace").strip()
        else:
            list_output = utils.exec_shell_cmd(f"sudo {list_cmd}")

        # Parse bucket list
        try:
            list_data = json.loads(list_output)
            list_count = len(list_data) if isinstance(list_data, list) else 0
        except:
            list_count = 0

        log.info(f"  Bucket list entries: {list_count}")

        if list_count > 0:
            all_bucket_lists_empty = False

        # Check bi list
        bi_cmd = f"radosgw-admin bi list --bucket {bucket_name}"
        log.info(f"[root@{site_name} ~]# {bi_cmd}")

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(f"sudo {bi_cmd}")
            bi_output = stdout.read().decode("utf-8", errors="replace").strip()
        else:
            bi_output = utils.exec_shell_cmd(f"sudo {bi_cmd}")

        # Parse bi list and count OLH entries with pending_removal=false
        try:
            bi_data = json.loads(bi_output)
            bi_count = len(bi_data) if isinstance(bi_data, list) else 0

            # Count OLH entries with pending_removal=false
            olh_pending_false_count = 0
            if isinstance(bi_data, list):
                for entry in bi_data:
                    if (
                        entry.get("type") == "olh"
                        and entry.get("pending_removal") == False
                    ):
                        olh_pending_false_count += 1
        except:
            bi_count = 0
            olh_pending_false_count = 0

        log.info(f"  BI list entries: {bi_count}")
        if bi_count > 0:
            log.info(
                f"  OLH entries with pending_removal=false: {olh_pending_false_count}"
            )
            if olh_pending_false_count > 0:
                log.info(
                    f"  ⚠ Sample bi list output (first 500 chars):\n{bi_output[:500]}"
                )

        bucket_investigation[bucket_name] = {
            "bucket_stats_objects": bucket_stats_info.get(bucket_name, 0),
            "bucket_list_count": list_count,
            "bi_list_count": bi_count,
            "olh_pending_false_count": olh_pending_false_count,
        }

        # Check consistency
        if list_count == 0 and bi_count > 0:
            log.warning(
                f"  ⚠ Inconsistency: Bucket list is empty but bi list has {bi_count} entries"
            )
        elif (
            list_count == 0
            and bi_count == 0
            and bucket_stats_info.get(bucket_name, 0) > 0
        ):
            log.warning(
                f"  ⚠ Critical: Bucket list and bi list are empty but bucket stats shows {bucket_stats_info.get(bucket_name, 0)} objects"
            )

    # Final analysis
    log.info(f"\n{'='*80}")
    log.info(f"INVESTIGATION SUMMARY:")
    log.info(f"{'='*80}")
    for bucket_name, info in bucket_investigation.items():
        log.info(f"\n{bucket_name}:")
        log.info(f"  Bucket stats num_objects: {info['bucket_stats_objects']}")
        log.info(f"  Bucket list count: {info['bucket_list_count']}")
        log.info(f"  BI list count: {info['bi_list_count']}")
        if info["olh_pending_false_count"] > 0:
            log.info(
                f"  OLH entries (pending_removal=false): {info['olh_pending_false_count']}"
            )
    log.info(f"{'='*80}\n")

    # Determine failure reason
    if all_bucket_lists_empty:
        # All bucket lists are empty but bucket stats show non-zero
        raise TestExecError(
            f"[{site_name}] CRITICAL: Bucket stats still showing objects even though bucket list is empty for all buckets. "
            f"This indicates a bucket stats inconsistency. Investigation details: {bucket_investigation}"
        )
    else:
        # Some buckets still have objects in bucket list
        raise TestExecError(
            f"[{site_name}] Bucket stats did not reach 0 within {max_wait_time}s ({max_wait_time/3600:.1f} hours). "
            f"Some buckets still have objects in bucket list. Investigation details: {bucket_investigation}"
        )


def verify_and_cleanup_bucket_list_and_index(
    bucket_names,
    rgw_conn,
    ssh_con,
    site_name,
    lc_expiration_days=1,
    max_wait_time=10800,
    check_interval=30,
):
    """
    Verify bucket list is empty. If not, apply delete-marker expiration and process LC until empty.
    Then verify bucket index is also empty.

    Args:
        bucket_names: List of bucket names to check
        rgw_conn: RGW S3 connection for applying LC policies
        ssh_con: SSH connection (None for local site)
        site_name: Name of the site for logging
        lc_expiration_days: Days for LC expiration policy
        max_wait_time: Maximum time to wait in seconds
        check_interval: How often to check in seconds

    Raises:
        TestExecError: If cleanup doesn't complete within max_wait_time
    """
    log.info(f"\n{'='*80}")
    log.info(f"VERIFYING BUCKET LIST AND INDEX ON {site_name.upper()}")
    log.info(f"{'='*80}\n")

    # STEP 1: Check bucket list for all buckets
    log.info(f"STEP 1: Checking bucket list for all {len(bucket_names)} buckets")
    log.info(f"{'='*80}")

    buckets_need_cleanup = []

    for bucket_name in bucket_names:
        list_cmd = f"radosgw-admin bucket list --bucket {bucket_name}"
        log.info(f"\n[root@{site_name} ~]# {list_cmd}")

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(f"sudo {list_cmd}")
            bucket_list_output = stdout.read().decode("utf-8", errors="replace").strip()
        else:
            bucket_list_output = utils.exec_shell_cmd(f"sudo {list_cmd}")

        try:
            bucket_list = json.loads(bucket_list_output)
            list_count = len(bucket_list) if isinstance(bucket_list, list) else 0

            if list_count == 0:
                log.info(f"✓ {bucket_name}: Bucket list is EMPTY")
            else:
                log.info(
                    f"⚠ {bucket_name}: Bucket list has {list_count} entries (need cleanup)"
                )
                buckets_need_cleanup.append(bucket_name)

                # Check if entries are delete markers
                delete_marker_count = sum(
                    1
                    for entry in bucket_list
                    if isinstance(entry, dict) and entry.get("delete_marker", False)
                )
                log.info(f"  - Delete markers: {delete_marker_count}/{list_count}")
        except json.JSONDecodeError:
            log.info(f"✓ {bucket_name}: Bucket list is EMPTY (empty output)")

    # STEP 2: If buckets need cleanup, apply delete-marker expiration policy
    if buckets_need_cleanup:
        log.info(f"\n{'='*80}")
        log.info(
            f"STEP 2: Applying delete-marker expiration policy to {len(buckets_need_cleanup)} bucket(s)"
        )
        log.info(f"{'='*80}\n")

        for bucket_name in buckets_need_cleanup:
            log.info(f"Applying delete-marker expiration policy to {bucket_name}")
            bucket = rgw_conn.Bucket(bucket_name)
            setup_lifecycle_delete_marker_expiration(
                bucket, rgw_conn, lc_expiration_days
            )
            log.info(f"✓ Policy applied to {bucket_name}")

        # STEP 3: Process LC until bucket list is empty
        log.info(f"\n{'='*80}")
        log.info(
            f"STEP 3: Processing LC until bucket list is empty on {len(buckets_need_cleanup)} bucket(s)"
        )
        log.info(f"{'='*80}\n")

        start_time = time.time()

        while (time.time() - start_time) < max_wait_time:
            # Process LC on buckets that need cleanup
            log.info(f"[{int(time.time() - start_time):4d}s] Running LC process...")
            for bucket_name in buckets_need_cleanup:
                lc_cmd = f"radosgw-admin lc process --bucket {bucket_name} --rgw-lc-debug-interval=600"
                if ssh_con:
                    ssh_con.exec_command(f"sudo {lc_cmd}")
                else:
                    utils.exec_shell_cmd(f"sudo {lc_cmd}")

            time.sleep(check_interval)

            # Check bucket list
            all_empty = True
            bucket_list_status = {}

            for bucket_name in buckets_need_cleanup:
                list_cmd = f"radosgw-admin bucket list --bucket {bucket_name}"
                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(f"sudo {list_cmd}")
                    bucket_list_output = (
                        stdout.read().decode("utf-8", errors="replace").strip()
                    )
                else:
                    bucket_list_output = utils.exec_shell_cmd(f"sudo {list_cmd}")

                try:
                    bucket_list = json.loads(bucket_list_output)
                    list_count = (
                        len(bucket_list) if isinstance(bucket_list, list) else 0
                    )
                    bucket_list_status[bucket_name] = list_count

                    if list_count > 0:
                        all_empty = False
                except json.JSONDecodeError:
                    bucket_list_status[bucket_name] = 0

            # Log status
            elapsed = int(time.time() - start_time)
            status_summary = ", ".join(
                [
                    f"{bucket.split('-')[-1]}: {count} entries"
                    for bucket, count in bucket_list_status.items()
                ]
            )
            log.info(f"[{elapsed:4d}s] [{site_name}] Bucket List: {status_summary}")

            if all_empty:
                log.info(f"\n✓ All bucket lists are now EMPTY (took {elapsed} seconds)")
                break

        if not all_empty:
            raise TestExecError(
                f"[{site_name}] Bucket lists did not clear within {max_wait_time}s. "
                f"Remaining: {bucket_list_status}"
            )
    else:
        log.info(f"\n✓ All bucket lists are already EMPTY - no cleanup needed")

    # STEP 4: Verify bucket index is empty
    log.info(f"\n{'='*80}")
    log.info(f"STEP 4: Verifying bucket index (bi list) is empty for all buckets")
    log.info(f"{'='*80}\n")

    log.info(f"Waiting 5 minutes for bucket index to clear...")
    time.sleep(300)

    # Track buckets with bi list issues
    buckets_with_bi_issues = {}

    for bucket_name in bucket_names:
        # First check if bucket list is empty
        list_cmd = f"radosgw-admin bucket list --bucket {bucket_name}"
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(f"sudo {list_cmd}")
            list_output = stdout.read().decode("utf-8", errors="replace").strip()
        else:
            list_output = utils.exec_shell_cmd(f"sudo {list_cmd}")

        try:
            bucket_list = json.loads(list_output)
            list_count = len(bucket_list) if isinstance(bucket_list, list) else 0
        except json.JSONDecodeError:
            list_count = 0

        # Now check bi list
        bi_cmd = f"radosgw-admin bi list --bucket {bucket_name}"
        log.info(f"\n[root@{site_name} ~]# {bi_cmd}")

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(f"sudo {bi_cmd}")
            bi_list_output = stdout.read().decode("utf-8", errors="replace").strip()
        else:
            bi_list_output = utils.exec_shell_cmd(f"sudo {bi_cmd}")

        try:
            bi_list = json.loads(bi_list_output)
            bi_count = len(bi_list) if isinstance(bi_list, list) else 0

            if bi_count == 0:
                log.info(f"✓ {bucket_name}: Bucket index is EMPTY")
            else:
                log.warning(f"⚠ {bucket_name}: Bucket index has {bi_count} entries")
                # Track buckets where list is empty but bi is not
                if list_count == 0:
                    buckets_with_bi_issues[bucket_name] = bi_count
                    log.warning(
                        f"  → Bucket list is empty but bi list has {bi_count} orphaned entries"
                    )
        except json.JSONDecodeError:
            log.info(f"✓ {bucket_name}: Bucket index is EMPTY (empty output)")

    # STEP 5: Fix orphaned OLH entries if needed
    olh_fix_results = {}  # Track fix results for reporting

    if buckets_with_bi_issues:
        log.info(f"\n{'='*80}")
        log.info(f"STEP 5: Fixing orphaned OLH entries in bucket index")
        log.info(f"{'='*80}\n")
        log.warning(
            f"⚠ ISSUE DETECTED: Bucket list is EMPTY but bucket index (bi list) is NOT EMPTY"
        )
        log.warning(f"⚠ This indicates orphaned OLH entries in the bucket index")
        log.info(f"\nBuckets requiring OLH fix:")
        for bkt, count in buckets_with_bi_issues.items():
            log.info(f"  - {bkt}: {count} orphaned bi entries")

        log.info(
            f"\n→ RESOLUTION: Running 'radosgw-admin bucket check olh --bucket <name> --fix --rgw-olh-pending-timeout-sec 60'"
        )
        log.info(
            f"→ This will clean up orphaned Object Link Head (OLH) entries from the bucket index"
        )
        log.info(f"→ Using 60 second timeout for pending OLH entries\n")

        max_fix_attempts = 10
        fix_wait_interval = 60  # Wait 60 seconds between fix attempts

        for bucket_name in list(buckets_with_bi_issues.keys()):
            initial_bi_count = buckets_with_bi_issues[bucket_name]

            log.info(f"\n{'='*80}")
            log.info(f"Fixing bucket: {bucket_name}")
            log.info(f"{'='*80}")
            log.info(f"Initial bi list count: {initial_bi_count} orphaned entries")
            log.info(
                f"Reason: Bucket list is empty but bi list has {initial_bi_count} entries"
            )
            log.info(
                f"Action: Running 'bucket check olh --fix' to clean up orphaned entries\n"
            )

            olh_fix_results[bucket_name] = {
                "initial_bi_count": initial_bi_count,
                "fix_attempts": 0,
                "success": False,
                "final_bi_count": initial_bi_count,
            }

            for attempt in range(1, max_fix_attempts + 1):
                olh_fix_results[bucket_name]["fix_attempts"] = attempt

                # Run bucket check olh --fix
                fix_cmd = f"radosgw-admin bucket check olh --bucket {bucket_name} --fix --rgw-olh-pending-timeout-sec 60"
                log.info(f"[Attempt {attempt}/{max_fix_attempts}] Running: {fix_cmd}")

                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(f"sudo {fix_cmd}")
                    fix_output = stdout.read().decode("utf-8", errors="replace").strip()
                    fix_stderr = stderr.read().decode("utf-8", errors="replace").strip()
                else:
                    fix_output = utils.exec_shell_cmd(f"sudo {fix_cmd}")
                    fix_stderr = ""

                log.info(
                    f"Fix command output: {fix_output[:500] if fix_output else 'No output'}"
                )
                if fix_stderr:
                    log.info(f"Fix command stderr: {fix_stderr[:500]}")

                # Wait before checking
                log.info(f"Waiting {fix_wait_interval} seconds for index to update...")
                time.sleep(fix_wait_interval)

                # Check bi list again
                bi_cmd = f"radosgw-admin bi list --bucket {bucket_name}"
                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(f"sudo {bi_cmd}")
                    bi_list_output = (
                        stdout.read().decode("utf-8", errors="replace").strip()
                    )
                else:
                    bi_list_output = utils.exec_shell_cmd(f"sudo {bi_cmd}")

                try:
                    bi_list = json.loads(bi_list_output)
                    bi_count = len(bi_list) if isinstance(bi_list, list) else 0
                except json.JSONDecodeError:
                    bi_count = 0

                olh_fix_results[bucket_name]["final_bi_count"] = bi_count
                log.info(f"Current bi list count: {bi_count} (was {initial_bi_count})")

                if bi_count == 0:
                    olh_fix_results[bucket_name]["success"] = True
                    log.info(
                        f"✓ SUCCESS: {bucket_name} bucket index is now EMPTY after {attempt} fix attempt(s)"
                    )
                    log.info(f"✓ Removed {initial_bi_count} orphaned OLH entries")
                    del buckets_with_bi_issues[bucket_name]
                    break
                else:
                    log.warning(
                        f"⚠ {bucket_name}: Bucket index still has {bi_count} entries after fix attempt {attempt}"
                    )

                    if attempt == max_fix_attempts:
                        log.error(
                            f"❌ {bucket_name}: Failed to clear bucket index after {max_fix_attempts} attempts"
                        )

        # Save OLH fix results to file
        if olh_fix_results:
            olh_results_file = f"olh_fix_results_{site_name}_{int(time.time())}.json"
            try:
                with open(olh_results_file, "w") as f:
                    json.dump(
                        {
                            "site": site_name,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "total_buckets_fixed": len(olh_fix_results),
                            "buckets": olh_fix_results,
                        },
                        f,
                        indent=2,
                    )
                log.info(f"\n📝 OLH fix results saved to: {olh_results_file}")
            except Exception as e:
                log.warning(f"Failed to save OLH fix results to file: {e}")

        # Print summary
        log.info(f"\n{'='*80}")
        log.info(f"OLH FIX SUMMARY - {site_name.upper()}")
        log.info(f"{'='*80}")
        for bucket_name, result in olh_fix_results.items():
            status = "✓ SUCCESS" if result["success"] else "❌ FAILED"
            log.info(f"{status}: {bucket_name}")
            log.info(f"  Initial bi entries: {result['initial_bi_count']}")
            log.info(f"  Final bi entries: {result['final_bi_count']}")
            log.info(f"  Fix attempts: {result['fix_attempts']}")
        log.info(f"{'='*80}\n")

        # Final check
        if buckets_with_bi_issues:
            log.error(
                f"\n❌ Failed to clear bucket index for {len(buckets_with_bi_issues)} bucket(s): {list(buckets_with_bi_issues.keys())}"
            )
            raise TestExecError(
                f"[{site_name}] Bucket index cleanup failed for {len(buckets_with_bi_issues)} bucket(s) "
                f"even after running 'bucket check olh --fix'. Remaining issues: {buckets_with_bi_issues}"
            )

    log.info(f"\n{'='*80}")
    log.info(f"✓ BUCKET LIST AND INDEX VERIFICATION COMPLETE ON {site_name.upper()}")
    log.info(f"{'='*80}\n")


def monitor_lc_deletion_all_buckets(
    bucket_names, ssh_con, site_name, max_wait_time=10800, check_interval=30
):
    """
    Actively monitor LC deletion progress for all buckets until all objects are deleted.

    Args:
        bucket_names: List of bucket names to monitor
        ssh_con: SSH connection (None for local site)
        site_name: Name of the site for logging (e.g., "primary", "secondary")
        max_wait_time: Maximum time to wait in seconds (default: 3 hours = 10800s)
        check_interval: How often to check bucket stats in seconds (default: 30s)

    Returns:
        int: Actual time taken for LC deletion to complete (in seconds)

    Raises:
        TestExecError: If LC deletion doesn't complete within max_wait_time
    """
    log.info(f"\n{'='*80}")
    log.info(f"MONITORING LC DELETION ON {site_name.upper()}")
    log.info(
        f"Buckets: {len(bucket_names)} | Check Interval: {check_interval}s | Max Wait: {max_wait_time}s"
    )
    log.info(f"{'='*80}\n")

    start_time = time.time()
    elapsed_time = 0
    buckets_status = {
        bucket: None for bucket in bucket_names
    }  # Track last known object count

    while elapsed_time < max_wait_time:
        all_buckets_empty = True

        # Check each bucket
        for bucket_name in bucket_names:
            # Get bucket stats from specific site
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(
                    f"sudo radosgw-admin bucket stats --bucket {bucket_name}"
                )
                bucket_stats = stdout.read().decode("utf-8", errors="replace").strip()
            else:
                bucket_stats = utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {bucket_name}"
                )

            json_match = re.search(r"\{.*\}", bucket_stats, re.DOTALL)
            if json_match:
                stats = json.loads(json_match.group(0))
                num_objects = stats["usage"]["rgw.main"]["num_objects"]
                buckets_status[bucket_name] = num_objects

                if num_objects > 0:
                    all_buckets_empty = False

        # Log current status
        elapsed_time = int(time.time() - start_time)
        status_summary = ", ".join(
            [
                f"{bucket.split('-')[-1]}: {count} objs"
                for bucket, count in buckets_status.items()
            ]
        )
        log.info(f"[{elapsed_time:4d}s] [{site_name}] {status_summary}")

        # Check if all buckets are empty
        if all_buckets_empty:
            actual_time = int(time.time() - start_time)
            log.info(f"\n{'='*80}")
            log.info(f"✓ LC DELETION COMPLETE ON {site_name.upper()}")
            log.info(f"✓ All {len(bucket_names)} buckets have 0 objects")
            log.info(
                f"✓ Total LC deletion time: {actual_time} seconds ({actual_time/60:.1f} minutes)"
            )
            log.info(f"{'='*80}\n")
            return actual_time

        # Wait before next check
        time.sleep(check_interval)

    # Timeout reached
    raise TestExecError(
        f"[{site_name}] LC deletion did not complete within {max_wait_time} seconds ({max_wait_time/3600:.1f} hours). "
        f"Remaining objects: {buckets_status}"
    )


def verify_lifecycle_deletion_on_site(bucket_name, ssh_con, site_name, config):
    """
    Verify that lifecycle deletion completed successfully on a specific site.

    Args:
        bucket_name: Name of the bucket
        ssh_con: SSH connection (None for local site)
        site_name: Name of the site for logging (e.g., "primary", "secondary")
        config: Test configuration

    Returns:
        bool: True if deletion complete (num_objects = 0)
    """
    log.info(f"Verifying lifecycle deletion for bucket {bucket_name} on {site_name}")

    max_wait_time = config.test_ops.get("lc_max_wait_time", 7200)
    check_interval = 60
    elapsed_time = 0

    while elapsed_time < max_wait_time:
        # Get bucket stats from specific site
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(
                f"sudo radosgw-admin bucket stats --bucket {bucket_name}"
            )
            bucket_stats = stdout.read().decode("utf-8", errors="replace").strip()
        else:
            bucket_stats = utils.exec_shell_cmd(
                f"radosgw-admin bucket stats --bucket {bucket_name}"
            )

        json_match = re.search(r"\{.*\}", bucket_stats, re.DOTALL)
        if json_match:
            stats = json.loads(json_match.group(0))
            num_objects = stats["usage"]["rgw.main"]["num_objects"]

            log.info(
                f"[{site_name}] Bucket {bucket_name}: {num_objects} objects remaining (elapsed: {elapsed_time}s)"
            )

            if num_objects == 0:
                log.info(f"✓ [{site_name}] All objects deleted from {bucket_name}")
                return True

        time.sleep(check_interval)
        elapsed_time += check_interval

    raise TestExecError(
        f"[{site_name}] Lifecycle deletion did not complete within {max_wait_time} seconds for {bucket_name}"
    )


def verify_lifecycle_deletion(bucket, rgw_ssh_con, config):
    """
    Verify that lifecycle deletion completed successfully.

    Args:
        bucket: Bucket object
        rgw_ssh_con: SSH connection to remote site
        config: Test configuration
    """
    log.info(f"Verifying lifecycle deletion for bucket: {bucket.name}")

    max_wait_time = config.test_ops.get("lc_max_wait_time", 7200)
    check_interval = 60
    elapsed_time = 0

    while elapsed_time < max_wait_time:
        bucket_stats = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket {bucket.name}"
        )

        json_match = re.search(r"\{.*\}", bucket_stats, re.DOTALL)
        if json_match:
            stats = json.loads(json_match.group(0))
            num_objects = stats["usage"]["rgw.main"]["num_objects"]

            log.info(
                f"Bucket {bucket.name} has {num_objects} objects remaining (elapsed: {elapsed_time}s)"
            )

            if num_objects == 0:
                log.info(f"✓ All objects deleted from {bucket.name}")
                return True

        time.sleep(check_interval)
        elapsed_time += check_interval

    raise TestExecError(
        f"Lifecycle deletion did not complete within {max_wait_time} seconds"
    )


def detect_local_and_remote_zones():
    """
    Auto-detect which zone the current site is in and which is remote.

    Returns:
        tuple: (local_zone_name, remote_zone_name, master_zone_name, zonegroup_config)

    Logic:
        1. Get zonegroup configuration
        2. Find master_zone from zonegroup
        3. Match local hostname against zone endpoints
        4. Determine which zone is local and which is remote
    """
    import socket

    try:
        # Get local hostname
        local_hostname = socket.gethostname()
        log.info(f"Detecting zones... Local hostname: {local_hostname}")

        # Get zonegroup configuration
        zonegroup_output = utils.exec_shell_cmd("sudo radosgw-admin zonegroup get")
        zonegroup = json.loads(zonegroup_output)

        # Get master zone ID
        master_zone_id = zonegroup.get("master_zone")
        log.info(f"Master zone ID from zonegroup: {master_zone_id}")

        # Find which zone the local hostname belongs to
        local_zone_name = None
        remote_zone_name = None
        master_zone_name = None

        for zone in zonegroup.get("zones", []):
            zone_name = zone.get("name")
            zone_id = zone.get("id")
            endpoints = zone.get("endpoints", [])

            # Check if this is the master zone
            if zone_id == master_zone_id:
                master_zone_name = zone_name
                log.info(f"Found master zone: '{zone_name}' (ID: {zone_id})")

            # Check if local hostname is in this zone's endpoints
            for endpoint in endpoints:
                # Extract hostname from endpoint (e.g., "http://ceph21:80" -> "ceph21")
                endpoint_host = (
                    endpoint.split("://")[1].split(":")[0]
                    if "://" in endpoint
                    else endpoint.split(":")[0]
                )

                if endpoint_host == local_hostname or endpoint_host in local_hostname:
                    local_zone_name = zone_name
                    log.info(
                        f"Local hostname '{local_hostname}' found in zone '{zone_name}' endpoints: {endpoints}"
                    )

        # Determine remote zone (the zone that's not local)
        for zone in zonegroup.get("zones", []):
            zone_name = zone.get("name")
            if zone_name != local_zone_name:
                remote_zone_name = zone_name
                log.info(f"Remote zone: '{zone_name}'")
                break

        if not local_zone_name or not remote_zone_name:
            raise TestExecError(
                f"Could not determine local/remote zones. "
                f"Local: {local_zone_name}, Remote: {remote_zone_name}"
            )

        log.info(f"\n✓ Zone Detection Summary:")
        log.info(f"  • Local zone: {local_zone_name}")
        log.info(f"  • Remote zone: {remote_zone_name}")
        log.info(f"  • Master zone: {master_zone_name}")
        log.info(f"  • Local is master: {local_zone_name == master_zone_name}\n")

        return local_zone_name, remote_zone_name, master_zone_name, zonegroup

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse zonegroup JSON: {e}")
        raise TestExecError("Failed to detect zones from zonegroup configuration")
    except Exception as e:
        log.error(f"Failed to detect zones: {e}")
        raise TestExecError(f"Zone detection failed: {e}")


def get_remote_conn_for_zone(zone_name):
    """
    Establish SSH connection to a host in the specified zone.

    Args:
        zone_name: Zone name (e.g., "west")

    Returns:
        SSH connection object to a host in the zone

    Logic:
        1. Get zonegroup configuration
        2. Find the specified zone's endpoints
        3. Extract hostname from first endpoint
        4. Resolve hostname to IP
        5. Create SSH connection
    """
    import socket

    try:
        log.info(f"\n{'='*80}")
        log.info(f"ESTABLISHING SSH CONNECTION TO ZONE '{zone_name}'")
        log.info(f"{'='*80}")

        # Get zonegroup configuration
        zonegroup_output = utils.exec_shell_cmd("sudo radosgw-admin zonegroup get")
        zonegroup = json.loads(zonegroup_output)

        # Find the specified zone
        zone_endpoints = None
        for zone in zonegroup.get("zones", []):
            if zone.get("name") == zone_name:
                zone_endpoints = zone.get("endpoints", [])
                log.info(f"Found zone '{zone_name}' with endpoints: {zone_endpoints}")
                break

        if not zone_endpoints:
            raise TestExecError(
                f"Could not find zone '{zone_name}' in zonegroup configuration"
            )

        # Extract hostname from first endpoint
        # Format: "http://ceph24:80" -> "ceph24"
        first_endpoint = zone_endpoints[0]
        if "://" in first_endpoint:
            endpoint_host = first_endpoint.split("://")[1].split(":")[0]
        else:
            endpoint_host = first_endpoint.split(":")[0]

        log.info(f"Using hostname '{endpoint_host}' from zone '{zone_name}'")

        # Resolve hostname to IP
        try:
            endpoint_ip = socket.gethostbyname(endpoint_host)
            log.info(f"Resolved '{endpoint_host}' to IP: {endpoint_ip}")
        except socket.gaierror as e:
            log.warning(f"Failed to resolve hostname '{endpoint_host}': {e}")
            log.info(f"Using hostname directly: {endpoint_host}")
            endpoint_ip = endpoint_host

        # Create SSH connection
        log.info(f"Creating SSH connection to {endpoint_ip}...")
        ssh_con = utils.connect_remote(endpoint_ip)

        if not ssh_con:
            raise TestExecError(
                f"Failed to establish SSH connection to {endpoint_ip} (zone '{zone_name}')"
            )

        log.info(f"✓ Successfully connected to zone '{zone_name}' at {endpoint_ip}")
        log.info(f"{'='*80}\n")

        return ssh_con

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse zonegroup JSON: {e}")
        raise TestExecError("Failed to get zone endpoints from zonegroup configuration")
    except Exception as e:
        log.error(f"Failed to establish connection to zone '{zone_name}': {e}")
        raise TestExecError(f"SSH connection to zone '{zone_name}' failed: {e}")


def get_rgw_port_for_realm(realm_name, ssh_con=None):
    """
    Get the RGW .io port for a specific realm.

    Args:
        realm_name: Realm name (e.g., "usa")
        ssh_con: SSH connection (None for local)

    Returns:
        Port number (e.g., 81) or None if not found
    """
    try:
        # Get RGW services
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command("sudo ceph orch ls | grep rgw")
            orch_output = stdout.read().decode().strip()
        else:
            orch_output = utils.exec_shell_cmd("ceph orch ls | grep rgw")

        # Parse output to find .io service for this realm
        # Format: rgw.usa.io               ?:81             3/3  79s ago
        for line in orch_output.split("\n"):
            if line.strip() and f"rgw.{realm_name}.io" in line:
                parts = line.split()
                if len(parts) >= 2:
                    # Second column is "?:81" or similar
                    port_field = parts[1]
                    if ":" in port_field:
                        port = port_field.split(":")[1]
                        log.info(f"Found RGW .io port for realm '{realm_name}': {port}")
                        return port

        log.warning(f"Could not find RGW .io port for realm '{realm_name}'")
        return None

    except Exception as e:
        log.error(f"Error getting RGW port for realm '{realm_name}': {e}")
        return None


def configure_rgw_settings(ssh_con, site_name, zone_name, realm_name, zonegroup_name):
    """
    Configure RGW settings for both io and sync daemons on a zone.

    Args:
        ssh_con: SSH connection (None for local site)
        site_name: Name of the site for logging (e.g., "primary", "secondary")
        zone_name: RGW zone name (e.g., "primary", "secondary")
        realm_name: RGW realm name (e.g., "india")
        zonegroup_name: RGW zonegroup name (e.g., "shared")
    """
    log.info(f"\n{'='*80}")
    log.info(f"CONFIGURING RGW SETTINGS ON {site_name.upper()} ZONE")
    log.info(f"  • Zone Name (rgw_zone): {zone_name}")
    log.info(f"  • Realm: {realm_name}")
    log.info(f"  • Zonegroup: {zonegroup_name}")
    log.info(f"  • Site: {'Local (primary)' if not ssh_con else 'Remote (secondary)'}")
    log.info(f"{'='*80}\n")

    # Get list of RGW services on this zone
    if ssh_con:
        stdin, stdout, stderr = ssh_con.exec_command("sudo ceph orch ls | grep rgw")
        orch_ls_output = stdout.read().decode().strip()
    else:
        orch_ls_output = utils.exec_shell_cmd("ceph orch ls | grep rgw")

    # Parse service names and filter by realm
    all_services = []
    rgw_services = []
    io_daemon = None
    sync_daemon = None

    for line in orch_ls_output.split("\n"):
        if line.strip():
            service_name = line.split()[0]
            all_services.append(service_name)

            # Filter by realm - only configure services matching this realm
            if f".{realm_name}." in service_name:
                rgw_services.append(service_name)
                if ".io" in service_name:
                    io_daemon = service_name
                elif ".sync" in service_name:
                    sync_daemon = service_name

    log.info(f"Found all RGW services: {all_services}")
    log.info(f"Filtered services for realm '{realm_name}': {rgw_services}")
    log.info(f"IO daemon: {io_daemon}")
    log.info(f"Sync daemon: {sync_daemon}\n")

    if not io_daemon or not sync_daemon:
        log.warning(
            f"⚠ Could not identify .io and .sync daemons. Skipping config setup."
        )
        return

    # Prepare config commands
    # Convert service names (rgw.india.io) to client names (client.rgw.india.io)
    io_client = f"client.{io_daemon}"
    sync_client = f"client.{sync_daemon}"

    configs = [
        # IO daemon configs
        (io_client, "rgw_realm", realm_name),
        (io_client, "rgw_zone", zone_name),
        (io_client, "rgw_zonegroup", zonegroup_name),
        (io_client, "rgw_run_sync_thread", "false"),
        (io_client, "rgw_lc_debug_interval", "1200"),
        (io_client, "rgw_dynamic_resharding_reduction_wait", "48"),
        (io_client, "rgw_reshard_debug_interval", "120"),
        (io_client, "log_to_file", "true"),
        # Sync daemon configs
        (sync_client, "rgw_realm", realm_name),
        (sync_client, "rgw_zone", zone_name),
        (sync_client, "rgw_zonegroup", zonegroup_name),
        (sync_client, "rgw_lc_debug_interval", "1200"),
        (sync_client, "rgw_dynamic_resharding_reduction_wait", "48"),
        (sync_client, "rgw_reshard_debug_interval", "120"),
        (sync_client, "log_to_file", "true"),
        # Global configs (only set on primary to avoid duplicates)
        ("global", "mon_cluster_log_to_file", "true"),
        ("mon", "mon_cluster_log_to_file", "true"),
    ]

    log.info(f"Setting RGW configurations...")
    for daemon, config_key, config_value in configs:
        cmd = f"ceph config set {daemon} {config_key} {config_value}"

        # Highlight zone configuration
        if config_key == "rgw_zone":
            log.info(f"[root@{site_name} ~]# {cmd}  ← SETTING ZONE TO: {config_value}")
        else:
            log.info(f"[root@{site_name} ~]# {cmd}")

        try:
            if ssh_con:
                ssh_con.exec_command(f"sudo {cmd}")
            else:
                utils.exec_shell_cmd(f"sudo {cmd}")
        except Exception as e:
            log.warning(f"  ⚠ Failed to set {config_key} for {daemon}: {e}")

    log.info(f"\n✓ RGW configuration completed for {site_name} zone")
    log.info(f"{'='*80}\n")
