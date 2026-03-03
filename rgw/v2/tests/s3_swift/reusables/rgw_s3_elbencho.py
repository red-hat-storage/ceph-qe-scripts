import json
import logging
import os
import random
import re
import subprocess
import threading
import time

import boto3
import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_accounts as accounts

log = logging.getLogger()


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def get_endpoints_from_zonegroup(zone_name, ssh_con=None):
    """
    Get RGW endpoints for a specific zone from zonegroup configuration.

    Args:
        zone_name: Name of the zone to get endpoints for (e.g., "east", "west")
        ssh_con: SSH connection (None for local, connection object for remote)

    Returns:
        List of endpoint URLs (e.g., ["http://ceph21:80", "http://ceph22:80"])
    """
    import json

    try:
        log.info(
            f"Getting endpoints for zone '{zone_name}' from zonegroup configuration..."
        )

        # Get zonegroup configuration
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(
                "sudo radosgw-admin zonegroup get"
            )
            zonegroup_output = stdout.read().decode()
        else:
            zonegroup_output = utils.exec_shell_cmd("sudo radosgw-admin zonegroup get")

        zonegroup = json.loads(zonegroup_output)

        # Find the zone in the zonegroup
        for zone in zonegroup.get("zones", []):
            if zone.get("name") == zone_name:
                endpoints = zone.get("endpoints", [])
                log.info(
                    f"  Found {len(endpoints)} endpoint(s) for zone '{zone_name}': {endpoints}"
                )
                return endpoints

        log.warning(f"Zone '{zone_name}' not found in zonegroup configuration")
        return []

    except json.JSONDecodeError as e:
        log.error(f"Error parsing zonegroup JSON: {e}")
        return []
    except Exception as e:
        log.error(f"Error getting endpoints for zone '{zone_name}': {e}")
        return []


def get_endpoint_elbencho(zone_name=None):
    """
    Determines the appropriate endpoint for Elbencho.

    Args:
        zone_name: Optional zone name to get endpoint from zonegroup config.
                   If not provided, falls back to ha_io label detection.

    Returns:
        Endpoint URL (e.g., "http://ceph21:5000")
    """
    # Try zonegroup-based endpoint discovery first if zone_name provided
    if zone_name:
        log.info(
            f"Getting local endpoint for zone '{zone_name}' from zonegroup configuration"
        )
        endpoints = get_endpoints_from_zonegroup(zone_name)
        if endpoints:
            # Use first endpoint and change port to 5000 for elbencho
            endpoint = endpoints[0]
            # Parse and replace port
            if ":" in endpoint:
                host_part = (
                    endpoint.split("://")[1].split(":")[0]
                    if "://" in endpoint
                    else endpoint.split(":")[0]
                )
                protocol = "http"
                elbencho_endpoint = f"{protocol}://{host_part}:5000"
            else:
                elbencho_endpoint = f"{endpoint}:5000"
            log.info(f"Local endpoint from zonegroup config: {elbencho_endpoint}")
            return elbencho_endpoint

    # Fallback to ha_io label detection
    log.info("Getting local endpoint based on ha_io label")
    try:
        # Check if current host has ha_io label
        host_output = utils.exec_shell_cmd("sudo ceph orch host ls")
        log.info(f"Local site host list:\n{host_output}")

        for line in host_output.split("\n"):
            if "ha_io" in line:
                local_hostname = line.split()[0]
                local_endpoint = f"http://{local_hostname}:5000"
                log.info(
                    f"Local endpoint determined from ha_io label: {local_endpoint}"
                )
                return local_endpoint

        log.warning("No host with ha_io label found on local site")
    except Exception as e:
        log.error(f"Failed to determine local endpoint: {e}")
    return None


def get_remote_endpoint_elbencho(zone_name=None, ssh_con=None):
    """
    Fetches the endpoint from remote site.

    Args:
        zone_name: Optional zone name to get endpoint from zonegroup config.
                   If not provided, falls back to ha_io label detection.
        ssh_con: SSH connection to remote site (optional, will get it if not provided)

    Returns:
        Endpoint URL (e.g., "http://ceph24:5000")
    """
    # Try zonegroup-based endpoint discovery first if zone_name provided
    if zone_name:
        log.info(
            f"Getting remote endpoint for zone '{zone_name}' from zonegroup configuration"
        )
        # Get zonegroup from local site (it has the full multisite config)
        endpoints = get_endpoints_from_zonegroup(zone_name, ssh_con=None)
        if endpoints:
            # Use first endpoint and change port to 5000 for elbencho
            endpoint = endpoints[0]
            # Parse and replace port
            if ":" in endpoint:
                host_part = (
                    endpoint.split("://")[1].split(":")[0]
                    if "://" in endpoint
                    else endpoint.split(":")[0]
                )
                protocol = "http"
                elbencho_endpoint = f"{protocol}://{host_part}:5000"
            else:
                elbencho_endpoint = f"{endpoint}:5000"
            log.info(f"Remote endpoint from zonegroup config: {elbencho_endpoint}")
            return elbencho_endpoint

    # Fallback to ha_io label detection
    try:
        if not ssh_con:
            ssh_con = reusable.get_remote_conn_in_multisite()

        stdin, stdout, stderr = ssh_con.exec_command("sudo ceph orch host ls")
        cmd_output = stdout.read().decode()

        log.info(f"Remote site host list:\n{cmd_output}")

        for line in cmd_output.split("\n"):
            if "ha_io" in line:
                remote_hostname = line.split()[0]
                remote_endpoint = f"http://{remote_hostname}:5000"
                log.info(
                    f"Remote endpoint determined from ha_io label: {remote_endpoint}"
                )
                return remote_endpoint

        log.warning("No host with ha_io label found on remote site")

    except Exception as e:
        log.error(f"Error fetching remote endpoint: {e}")

    return None


def install_elbencho(node_conn=None):
    """Installs Elbencho if it is not already installed."""
    site_name = "remote" if node_conn else "local"
    log.info(f"Checking if Elbencho is already installed on {site_name} site")

    try:
        if node_conn:
            stdin, stdout, stderr = node_conn.exec_command(
                "/usr/local/bin/elbencho --version"
            )
            output = stdout.read().decode().strip()
        else:
            output = utils.exec_shell_cmd("/usr/local/bin/elbencho --version")

        if output and "elbencho version" in output:
            log.info(
                f"✓ Elbencho already installed on {site_name} site: {output.split()[0]}"
            )
            return
    except Exception as e:
        log.info(
            f"Elbencho not found on {site_name} site, proceeding with installation..."
        )

    log.info(f"Installing Elbencho on {site_name} site...")

    # Change to /tmp directory for download
    cmds = [
        "cd /tmp",
        # Try wget first, fallback to curl if wget fails
        "wget https://github.com/breuner/elbencho/releases/download/v3.0-25/elbencho-static-x86_64.tar.gz -O /tmp/elbencho-static-x86_64.tar.gz || curl -L -o /tmp/elbencho-static-x86_64.tar.gz https://github.com/breuner/elbencho/releases/download/v3.0-25/elbencho-static-x86_64.tar.gz",
        # Verify download
        "ls -lh /tmp/elbencho-static-x86_64.tar.gz",
        # Extract
        "cd /tmp && tar -xf elbencho-static-x86_64.tar.gz",
        # Verify extraction
        "ls -lh /tmp/elbencho",
        # Move to /usr/local/bin/ (try with sudo, fallback to without)
        "sudo mv /tmp/elbencho /usr/local/bin/ 2>/dev/null || mv /tmp/elbencho /usr/local/bin/",
        # Make executable
        "sudo chmod +x /usr/local/bin/elbencho 2>/dev/null || chmod +x /usr/local/bin/elbencho",
        # Verify installation
        "/usr/local/bin/elbencho --version",
        # Cleanup
        "rm -f /tmp/elbencho-static-x86_64.tar.gz",
    ]

    for i, cmd in enumerate(cmds, 1):
        log.info(f"  [{i}/{len(cmds)}] Executing: {cmd[:80]}...")
        try:
            if node_conn:
                stdin, stdout, stderr = node_conn.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                if exit_status != 0 and "verify" not in cmd.lower():
                    log.error(f"Command failed with exit code {exit_status}")
                    log.error(f"STDERR: {error}")
                    log.error(f"STDOUT: {output}")
                    raise TestExecError(
                        f"Failed to install Elbencho on {site_name} site. Command '{cmd}' failed."
                    )

                if output:
                    log.debug(f"Output: {output}")
            else:
                result = utils.exec_shell_cmd(cmd)
                if result is False and "verify" not in cmd.lower():
                    raise TestExecError(
                        f"Failed to install Elbencho on {site_name} site. Command '{cmd}' failed."
                    )
                if result:
                    log.debug(f"Output: {result[:200]}")
        except Exception as e:
            # If this is a verification command, it's okay to fail
            if "verify" in cmd.lower() or "ls -lh" in cmd:
                log.warning(f"Verification command failed (non-critical): {e}")
                continue
            else:
                log.error(f"Failed to execute command: {cmd}")
                log.error(f"Error: {e}")
                raise TestExecError(
                    f"Failed to install Elbencho on {site_name} site: {e}"
                )

    log.info(f"✓ Elbencho installation complete on {site_name} site")

    # Final verification
    try:
        if node_conn:
            stdin, stdout, stderr = node_conn.exec_command(
                "/usr/local/bin/elbencho --version"
            )
            version_output = stdout.read().decode().strip()
        else:
            version_output = utils.exec_shell_cmd("/usr/local/bin/elbencho --version")

        if version_output:
            log.info(f"✓ Verified: {version_output.split()[0]}")
    except Exception as e:
        log.error(f"Failed to verify Elbencho installation: {e}")
        raise TestExecError(
            f"Elbencho installation verification failed on {site_name} site"
        )


def elbench_install_configure():
    """Installs and configures Elbencho on the client and remote node if applicable."""
    install_elbencho()
    if utils.is_cluster_multisite():
        log.info("Cluster is multisite, installing Elbencho on remote node")
        try:
            remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
            install_elbencho(remote_site_ssh_con)
        except Exception as e:
            log.error(f"Failed to install Elbencho on remote site: {e}")


def run_elbencho(
    endpoint, zone_name, num_objects, buckets, each_user, threads, object_size
):
    """Runs Elbencho with specified parameters."""
    log.info(
        f"[{zone_name}] Running Elbencho workload for {num_objects} objects on buckets {buckets}"
    )
    bucket_prefix = "-".join(buckets[0].split("-")[:-1]) + "-"
    num_buckets = len(buckets)
    bucket_format = f"{bucket_prefix}{{0..{num_buckets-1}}}"
    elbencho_cmd = (
        f"time /usr/local/bin/elbencho --s3endpoints {endpoint} --s3key {each_user['access_key']} --s3secret {each_user['secret_key']} "
        f"-w -t {threads} -n0 -N {num_objects} -s {object_size} {bucket_format}"
    )
    output = utils.exec_shell_cmd(elbencho_cmd)
    if output is False:
        log.error(f"Elbencho execution failed on {zone_name}")
        return
    metrics = parse_elbencho_output(output)
    log.info(f"[{zone_name}] Performance metrics: {metrics}")


def parse_elbencho_output(output):
    """Parses Elbencho output and extracts performance metrics."""
    log.info("Parsing Elbencho output")
    if not isinstance(output, str):
        log.error("Invalid output received from Elbencho command.")
        return {}
    metrics = {}
    lines = output.split("\n")
    for line in lines:
        if "Throughput MiB/s" in line:
            metrics["Throughput"] = line.split()[-1]
        elif "IOPS" in line:
            metrics["IOPS"] = line.split()[-1]
        elif "Total MiB" in line:
            metrics["Total Data Written (MiB)"] = line.split()[-1]
    return metrics


def stop_rgw_sync_services(ssh_con=None, site_name="secondary"):
    """
    Stop RGW sync services on a site (for full sync testing).
    Uses 'ceph orch ls | grep sync' to find sync services and 'ceph orch stop <service>' to stop them.

    Args:
        ssh_con: SSH connection to the site (None for local)
        site_name: Name of the site for logging
    """
    log.info(f"Stopping RGW sync services on {site_name} site")
    try:
        # Get list of all services and filter for sync services
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command("sudo ceph orch ls")
            orch_ls_output = stdout.read().decode()
        else:
            orch_ls_output = utils.exec_shell_cmd("sudo ceph orch ls")

        log.info(f"Looking for sync services in orchestrator services list...")

        # Parse output to find sync services
        sync_services = []
        for line in orch_ls_output.split("\n"):
            if "sync" in line.lower() and "rgw" in line.lower():
                # Extract service name (first column)
                parts = line.split()
                if parts:
                    service_name = parts[0]
                    sync_services.append(service_name)
                    log.info(f"  Found sync service: {service_name}")

        if not sync_services:
            log.warning(f"No RGW sync services found on {site_name} site")
            return

        # Stop each sync service
        stopped_count = 0
        for service_name in sync_services:
            log.info(f"Stopping sync service: {service_name}")

            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(
                    f"sudo ceph orch stop {service_name}"
                )
                output = stdout.read().decode()
                error = stderr.read().decode()
            else:
                output = utils.exec_shell_cmd(f"sudo ceph orch stop {service_name}")
                error = ""

            if error and "error" in error.lower():
                log.warning(f"  Warning while stopping {service_name}: {error}")
            else:
                log.info(f"  ✓ Stopped {service_name}")
                stopped_count += 1

        log.info(f"✓ Stopped {stopped_count} RGW sync services on {site_name} site")
        log.info(f"Monitoring daemons until all are stopped (max 90 seconds)...")

        # Active monitoring instead of blind wait
        max_wait = 90
        check_interval = 5
        elapsed = 0

        while elapsed < max_wait:
            # Check if all daemons are stopped
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(
                    "sudo ceph orch ps --daemon-type rgw --format json"
                )
                daemons_output = stdout.read().decode()
            else:
                daemons_output = utils.exec_shell_cmd(
                    "sudo ceph orch ps --daemon-type rgw --format json"
                )

            import json

            all_daemons = json.loads(daemons_output)

            # Check sync daemons
            sync_daemons_running = []
            for daemon in all_daemons:
                if "sync" in daemon.get("service_name", "").lower():
                    if daemon.get("status_desc") == "running":
                        sync_daemons_running.append(daemon.get("daemon_name"))

            if not sync_daemons_running:
                log.info(f"✓ All sync daemons stopped after {elapsed} seconds")
                break
            else:
                log.info(
                    f"  [{elapsed}s] Still running: {', '.join(sync_daemons_running[:3])}{'...' if len(sync_daemons_running) > 3 else ''}"
                )
                time.sleep(check_interval)
                elapsed += check_interval

        if elapsed >= max_wait:
            log.warning(f"⚠ Reached max wait time ({max_wait}s), proceeding anyway")

    except Exception as e:
        log.error(f"Error stopping RGW sync services on {site_name}: {e}")
        raise TestExecError(f"Failed to stop RGW sync services on {site_name}")


def stop_rgw_services(
    ssh_con=None, site_name="secondary", max_retries=5, realm_name=None
):
    """
    Stop RGW services on a site with retry logic until all are actually stopped.
    Uses 'ceph orch ls | grep rgw' to find services and 'ceph orch stop <service>' to stop them.

    Args:
        ssh_con: SSH connection to the site (None for local)
        site_name: Name of the site for logging
        max_retries: Maximum number of stop attempts (default: 5)
        realm_name: Optional realm name to filter services (e.g., "usa" will only stop rgw.usa.*)

    Raises:
        TestExecError: If services don't stop after max_retries attempts
    """
    if realm_name:
        log.info(
            f"Stopping RGW services for realm '{realm_name}' on {site_name} site (with retry until stopped)"
        )
    else:
        log.info(
            f"Stopping ALL RGW services on {site_name} site (with retry until stopped)"
        )
    import json

    for attempt in range(1, max_retries + 1):
        try:
            log.info(f"\n{'='*80}")
            log.info(f"STOP ATTEMPT {attempt}/{max_retries}")
            log.info(f"{'='*80}")

            # Get list of RGW services using ceph orch ls | grep rgw
            list_cmd = "ceph orch ls | grep rgw"
            log.info(f"\n[root@{site_name} ~]# {list_cmd}")

            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(f"sudo {list_cmd}")
                orch_ls_output = stdout.read().decode()
            else:
                orch_ls_output = utils.exec_shell_cmd(f"sudo {list_cmd}")

            # Parse service names from output and filter by realm if specified
            rgw_services = []
            all_services = []
            for line in orch_ls_output.split("\n"):
                if line.strip():
                    # Service name is the first column
                    parts = line.split()
                    if parts:
                        service_name = parts[0]
                        all_services.append(service_name)

                        # Filter by realm if specified
                        if realm_name:
                            # Check if service name contains the realm (e.g., rgw.usa.io, rgw.usa.sync)
                            if f".{realm_name}." in service_name:
                                rgw_services.append(service_name)
                                log.info(
                                    f"  Found RGW service for realm '{realm_name}': {service_name}"
                                )
                            else:
                                log.info(
                                    f"  Skipping RGW service (different realm): {service_name}"
                                )
                        else:
                            rgw_services.append(service_name)
                            log.info(f"  Found RGW service: {service_name}")

            if not all_services:
                log.info(f"✓ No RGW services found on {site_name} site")
                return

            if realm_name and not rgw_services:
                log.info(
                    f"✓ No RGW services found for realm '{realm_name}' on {site_name} site"
                )
                log.info(f"  (Found {len(all_services)} service(s) for other realms)")
                return

            log.info(f"\nFound {len(rgw_services)} RGW service(s) to stop")

            # Stop each RGW service
            for service_name in rgw_services:
                stop_cmd = f"ceph orch stop {service_name}"
                log.info(f"\n[root@{site_name} ~]# {stop_cmd}")

                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(f"sudo {stop_cmd}")
                    output = stdout.read().decode().strip()
                else:
                    output = utils.exec_shell_cmd(f"sudo {stop_cmd}")

                # Log the output
                if output:
                    for line in output.split("\n"):
                        if line.strip():
                            log.info(line)

            log.info(f"\n✓ Issued stop command to {len(rgw_services)} RGW service(s)")
            log.info(f"Waiting 90 seconds for all RGW daemons to fully stop...")
            time.sleep(90)

            # Verify all RGW daemons are stopped
            verify_cmd = "ceph orch ps --daemon-type rgw --format json"
            log.info(f"\n[root@{site_name} ~]# {verify_cmd}")

            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(f"sudo {verify_cmd}")
                rgw_daemons = stdout.read().decode()
            else:
                rgw_daemons = utils.exec_shell_cmd(f"sudo {verify_cmd}")

            daemons = json.loads(rgw_daemons)
            all_running = [d for d in daemons if d.get("status_desc") == "running"]

            # Filter running daemons by realm if specified
            if realm_name:
                still_running = [
                    d
                    for d in all_running
                    if f".{realm_name}." in d.get("daemon_name", "")
                ]
            else:
                still_running = all_running

            if not still_running:
                log.info(f"\n{'='*80}")
                if realm_name:
                    log.info(
                        f"✓ SUCCESS: All RGW services for realm '{realm_name}' stopped on {site_name} site after {attempt} attempt(s)"
                    )
                else:
                    log.info(
                        f"✓ SUCCESS: All RGW services stopped on {site_name} site after {attempt} attempt(s)"
                    )
                log.info(f"{'='*80}\n")
                return
            else:
                log.warning(
                    f"\n⚠ {len(still_running)} RGW daemon(s) still running after attempt {attempt}:"
                )
                for daemon in still_running:
                    log.warning(
                        f"  - {daemon['daemon_name']} (status: {daemon.get('status_desc')})"
                    )

                if attempt < max_retries:
                    log.info(f"Will retry stopping in next attempt...")
                else:
                    log.error(f"\n{'='*80}")
                    log.error(
                        f"❌ FAILED: Could not stop all RGW services after {max_retries} attempts"
                    )
                    log.error(f"{'='*80}\n")
                    raise TestExecError(
                        f"Failed to stop all RGW services on {site_name} after {max_retries} attempts. "
                        f"{len(still_running)} daemon(s) still running: {[d['daemon_name'] for d in still_running]}"
                    )

        except json.JSONDecodeError as e:
            log.error(f"Error parsing daemon list: {e}")
            if attempt >= max_retries:
                raise TestExecError(
                    f"Failed to stop RGW services on {site_name}: JSON parsing error"
                )
        except Exception as e:
            log.error(f"Error stopping RGW services on {site_name}: {e}")
            if attempt >= max_retries:
                raise TestExecError(f"Failed to stop RGW services on {site_name}: {e}")


def start_rgw_sync_services(ssh_con=None, site_name="secondary", realm_name=None):
    """
    Start RGW sync services on a site (after full sync testing).
    Uses 'ceph orch ls | grep sync' to find sync services and 'ceph orch start <service>' to start them.

    Args:
        ssh_con: SSH connection to the site (None for local)
        site_name: Name of the site for logging
        realm_name: Optional realm name to filter services (e.g., "usa" will only start rgw.usa.sync)
    """
    if realm_name:
        log.info(
            f"Starting RGW sync services for realm '{realm_name}' on {site_name} site"
        )
    else:
        log.info(f"Starting RGW sync services on {site_name} site")
    try:
        # Get list of all services and filter for sync services
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command("sudo ceph orch ls")
            orch_ls_output = stdout.read().decode()
        else:
            orch_ls_output = utils.exec_shell_cmd("sudo ceph orch ls")

        log.info(f"Looking for sync services in orchestrator services list...")

        # Parse output to find sync services
        sync_services = []
        all_sync_services = []
        for line in orch_ls_output.split("\n"):
            if "sync" in line.lower() and "rgw" in line.lower():
                # Extract service name (first column)
                parts = line.split()
                if parts:
                    service_name = parts[0]
                    all_sync_services.append(service_name)

                    # Filter by realm if specified
                    if realm_name:
                        if f".{realm_name}." in service_name:
                            sync_services.append(service_name)
                            log.info(
                                f"  Found sync service for realm '{realm_name}': {service_name}"
                            )
                        else:
                            log.info(
                                f"  Skipping sync service (different realm): {service_name}"
                            )
                    else:
                        sync_services.append(service_name)
                        log.info(f"  Found sync service: {service_name}")

        if not all_sync_services:
            log.warning(f"No RGW sync services found on {site_name} site")
            return

        if realm_name and not sync_services:
            log.warning(
                f"No RGW sync services found for realm '{realm_name}' on {site_name} site"
            )
            log.info(
                f"  (Found {len(all_sync_services)} sync service(s) for other realms)"
            )
            return

        # Start each sync service
        started_count = 0
        for service_name in sync_services:
            log.info(f"Starting sync service: {service_name}")

            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(
                    f"sudo ceph orch start {service_name}"
                )
                output = stdout.read().decode()
                error = stderr.read().decode()
            else:
                output = utils.exec_shell_cmd(f"sudo ceph orch start {service_name}")
                error = ""

            if error and "error" in error.lower():
                log.warning(f"  Warning while starting {service_name}: {error}")
            else:
                log.info(f"  ✓ Started {service_name}")
                started_count += 1

        log.info(f"✓ Started {started_count} RGW sync services on {site_name} site")
        log.info(
            f"Waiting 90 seconds for RGW sync services to fully start and initialize..."
        )
        time.sleep(90)  # Wait for services to fully start and sync to initialize

    except Exception as e:
        log.error(f"Error starting RGW sync services on {site_name}: {e}")
        raise TestExecError(f"Failed to start RGW sync services on {site_name}")


def start_rgw_services(
    ssh_con=None, site_name="secondary", max_retries=5, realm_name=None
):
    """
    Start RGW services on a site with retry logic until all are actually running.
    Uses 'ceph orch ls | grep rgw' to find services and 'ceph orch start <service>' to start them.

    Args:
        ssh_con: SSH connection to the site (None for local)
        site_name: Name of the site for logging
        max_retries: Maximum number of start attempts (default: 5)
        realm_name: Optional realm name to filter services (e.g., "usa" will only start rgw.usa.*)

    Raises:
        TestExecError: If services don't start after max_retries attempts
    """
    if realm_name:
        log.info(
            f"Starting RGW services for realm '{realm_name}' on {site_name} site (with retry until running)"
        )
    else:
        log.info(
            f"Starting ALL RGW services on {site_name} site (with retry until running)"
        )
    import json

    for attempt in range(1, max_retries + 1):
        try:
            log.info(f"\n{'='*80}")
            log.info(f"START ATTEMPT {attempt}/{max_retries}")
            log.info(f"{'='*80}")

            # Get list of RGW services using ceph orch ls | grep rgw
            list_cmd = "ceph orch ls | grep rgw"
            log.info(f"\n[root@{site_name} ~]# {list_cmd}")

            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(f"sudo {list_cmd}")
                orch_ls_output = stdout.read().decode()
            else:
                orch_ls_output = utils.exec_shell_cmd(f"sudo {list_cmd}")

            # Parse service names from output and filter by realm if specified
            rgw_services = []
            all_services = []
            for line in orch_ls_output.split("\n"):
                if line.strip():
                    # Service name is the first column
                    parts = line.split()
                    if parts:
                        service_name = parts[0]
                        all_services.append(service_name)

                        # Filter by realm if specified
                        if realm_name:
                            if f".{realm_name}." in service_name:
                                rgw_services.append(service_name)
                                log.info(
                                    f"  Found RGW service for realm '{realm_name}': {service_name}"
                                )
                            else:
                                log.info(
                                    f"  Skipping RGW service (different realm): {service_name}"
                                )
                        else:
                            rgw_services.append(service_name)
                            log.info(f"  Found RGW service: {service_name}")

            if not all_services:
                log.info(f"✓ No RGW services found on {site_name} site")
                return

            if realm_name and not rgw_services:
                log.info(
                    f"✓ No RGW services found for realm '{realm_name}' on {site_name} site"
                )
                log.info(f"  (Found {len(all_services)} service(s) for other realms)")
                return

            log.info(f"\nFound {len(rgw_services)} RGW service(s) to start")

            # Start each RGW service
            for service_name in rgw_services:
                start_cmd = f"ceph orch start {service_name}"
                log.info(f"\n[root@{site_name} ~]# {start_cmd}")

                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(f"sudo {start_cmd}")
                    output = stdout.read().decode().strip()
                else:
                    output = utils.exec_shell_cmd(f"sudo {start_cmd}")

                # Log the output
                if output:
                    for line in output.split("\n"):
                        if line.strip():
                            log.info(line)

            log.info(f"\n✓ Issued start command to {len(rgw_services)} RGW service(s)")
            log.info(f"Waiting 90 seconds for all RGW daemons to fully start...")
            time.sleep(90)

            # Verify all RGW daemons are running
            verify_cmd = "ceph orch ps --daemon-type rgw --format json"
            log.info(f"\n[root@{site_name} ~]# {verify_cmd}")

            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(f"sudo {verify_cmd}")
                rgw_daemons = stdout.read().decode()
            else:
                rgw_daemons = utils.exec_shell_cmd(f"sudo {verify_cmd}")

            daemons = json.loads(rgw_daemons)
            all_stopped = [d for d in daemons if d.get("status_desc") != "running"]

            # Filter stopped daemons by realm if specified
            if realm_name:
                still_stopped = [
                    d
                    for d in all_stopped
                    if f".{realm_name}." in d.get("daemon_name", "")
                ]
            else:
                still_stopped = all_stopped

            if not still_stopped:
                log.info(f"\n{'='*80}")
                if realm_name:
                    log.info(
                        f"✓ SUCCESS: All RGW services for realm '{realm_name}' started on {site_name} site after {attempt} attempt(s)"
                    )
                else:
                    log.info(
                        f"✓ SUCCESS: All RGW services started on {site_name} site after {attempt} attempt(s)"
                    )
                log.info(f"{'='*80}\n")
                return
            else:
                log.warning(
                    f"\n⚠ {len(still_stopped)} RGW daemon(s) still not running after attempt {attempt}:"
                )
                for daemon in still_stopped:
                    log.warning(
                        f"  - {daemon['daemon_name']} (status: {daemon.get('status_desc')})"
                    )

                if attempt < max_retries:
                    log.info(f"Will retry starting in next attempt...")
                else:
                    log.error(f"\n{'='*80}")
                    log.error(
                        f"❌ FAILED: Could not start all RGW services after {max_retries} attempts"
                    )
                    log.error(f"{'='*80}\n")
                    raise TestExecError(
                        f"Failed to start all RGW services on {site_name} after {max_retries} attempts. "
                        f"{len(still_stopped)} daemon(s) still not running: {[d['daemon_name'] for d in still_stopped]}"
                    )

        except json.JSONDecodeError as e:
            log.error(f"Error parsing daemon list: {e}")
            if attempt >= max_retries:
                raise TestExecError(
                    f"Failed to start RGW services on {site_name}: JSON parsing error"
                )
        except Exception as e:
            log.error(f"Error starting RGW services on {site_name}: {e}")
            if attempt >= max_retries:
                raise TestExecError(f"Failed to start RGW services on {site_name}: {e}")


def verify_rgw_sync_services_status(
    ssh_con=None,
    expected_status="running",
    site_name="site",
    max_retries=6,
    retry_interval=10,
):
    """
    Verify RGW sync services are in expected status with retry logic.

    Args:
        ssh_con: SSH connection to the site (None for local)
        expected_status: Expected status (running/stopped)
        site_name: Name of the site for logging
        max_retries: Maximum number of verification attempts (default: 6)
        retry_interval: Seconds to wait between retries (default: 10)

    Returns:
        bool: True if all sync services are in expected status
    """
    log.info(f"Verifying RGW sync services are {expected_status} on {site_name}")

    for attempt in range(1, max_retries + 1):
        try:
            # Get list of all services
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command("sudo ceph orch ls")
                orch_ls_output = stdout.read().decode()
            else:
                orch_ls_output = utils.exec_shell_cmd("sudo ceph orch ls")

            # Find sync services
            sync_services = []
            for line in orch_ls_output.split("\n"):
                if "sync" in line.lower() and "rgw" in line.lower():
                    parts = line.split()
                    if parts:
                        service_name = parts[0]
                        sync_services.append(service_name)

            if not sync_services:
                log.warning(f"No RGW sync services found on {site_name} site")
                return False

            # Get daemon status for sync services
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(
                    "sudo ceph orch ps --format json"
                )
                orch_ps_output = stdout.read().decode()
            else:
                orch_ps_output = utils.exec_shell_cmd("sudo ceph orch ps --format json")

            import json

            all_daemons = json.loads(orch_ps_output)

            # Check status of sync service daemons
            all_match = True
            mismatched_daemons = []

            for service_name in sync_services:
                service_daemons = [
                    d for d in all_daemons if d.get("service_name") == service_name
                ]

                if not service_daemons:
                    log.warning(f"No daemons found for sync service: {service_name}")
                    all_match = False
                    continue

                for daemon in service_daemons:
                    daemon_status = daemon.get("status_desc", "unknown")
                    daemon_name = daemon.get("daemon_name", "unknown")

                    if expected_status == "running" and daemon_status != "running":
                        mismatched_daemons.append(f"{daemon_name} is {daemon_status}")
                        all_match = False
                    elif expected_status == "stopped" and daemon_status == "running":
                        mismatched_daemons.append(f"{daemon_name} is still running")
                        all_match = False

            if all_match:
                log.info(
                    f"✓ All RGW sync services are {expected_status} on {site_name}"
                )
                return True
            else:
                if attempt < max_retries:
                    log.info(
                        f"Attempt {attempt}/{max_retries}: Some daemons not {expected_status} yet:"
                    )
                    for daemon_info in mismatched_daemons:
                        log.info(f"  - {daemon_info}")
                    log.info(f"Waiting {retry_interval} seconds before retry...")
                    time.sleep(retry_interval)
                else:
                    log.warning(
                        f"After {max_retries} attempts, some RGW sync daemons are not {expected_status}:"
                    )
                    for daemon_info in mismatched_daemons:
                        log.warning(f"  - {daemon_info}")
                    return False

        except Exception as e:
            log.error(
                f"Error verifying RGW sync status on {site_name} (attempt {attempt}): {e}"
            )
            if attempt < max_retries:
                log.info(f"Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)
            else:
                return False

    return False


def verify_rgw_services_status(
    ssh_con=None, expected_status="running", site_name="site"
):
    """
    Verify RGW services are in expected status.

    Args:
        ssh_con: SSH connection to the site (None for local)
        expected_status: Expected status (running/stopped)
        site_name: Name of the site for logging

    Returns:
        bool: True if all services are in expected status
    """
    log.info(f"Verifying RGW services are {expected_status} on {site_name}")
    try:
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(
                "sudo ceph orch ps --daemon-type rgw --format json"
            )
            rgw_daemons = stdout.read().decode()
        else:
            rgw_daemons = utils.exec_shell_cmd(
                "sudo ceph orch ps --daemon-type rgw --format json"
            )

        import json

        daemons = json.loads(rgw_daemons)

        for daemon in daemons:
            daemon_status = daemon["status_desc"]
            if expected_status == "running" and daemon_status != "running":
                log.warning(
                    f"Daemon {daemon['daemon_name']} is {daemon_status}, expected running"
                )
                return False
            elif expected_status == "stopped" and daemon_status == "running":
                log.warning(
                    f"Daemon {daemon['daemon_name']} is running, expected stopped"
                )
                return False

        log.info(f"✓ All RGW services are {expected_status} on {site_name}")
        return True

    except Exception as e:
        log.error(f"Error verifying RGW status on {site_name}: {e}")
        return False


def verify_bucket_sync(buckets):
    """Checks bucket stats on both local and remote sites to verify sync consistency."""
    max_retries = 480  # Retry up to 480 times (4 hours)
    sleep_interval = 30  # Sleep interval in seconds
    start_time = time.time()  # Track start time

    for bucket in buckets:
        if "tenant" in bucket:
            tenant_name, bucket_short_name = bucket.split(".", 1)
            bucket = f"{tenant_name}/{bucket}"

            for attempt in range(1, max_retries + 1):

                # Fetch local bucket stats
                local_stats_output = utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {bucket}"
                )
                log.info(f"Raw local stats output for {bucket}: {local_stats_output}")

                # Extract JSON part from local stats
                local_json_match = re.search(r"\{.*\}", local_stats_output, re.DOTALL)
                local_stats = (
                    json.loads(local_json_match.group(0)) if local_json_match else None
                )

                # Fetch remote bucket stats
                remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
                stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                    f"radosgw-admin bucket stats --bucket {bucket}"
                )
                remote_stats_output = stdout.read().decode().strip()
                log.info(f"Raw remote stats output for {bucket}: {remote_stats_output}")

                # Extract JSON part from remote stats
                remote_json_match = re.search(r"\{.*\}", remote_stats_output, re.DOTALL)
                remote_stats = (
                    json.loads(remote_json_match.group(0))
                    if remote_json_match
                    else None
                )

                if not local_stats or not remote_stats:
                    raise SyncFailedError(
                        f"Failed to fetch valid JSON stats for bucket: {bucket}"
                    )

                # Compare num_objects and size_actual across sites
                if (
                    local_stats["usage"]["rgw.main"]["num_objects"]
                    != remote_stats["usage"]["rgw.main"]["num_objects"]
                ):
                    log.info(
                        f"Waiting for bucket sync for {bucket} in {attempt}, sleep for {sleep_interval} secs and retry"
                    )
                    time.sleep(sleep_interval)
                else:
                    log.info(
                        f"sync got consistent for {bucket} in {attempt} attempts with a sleep of {sleep_interval} secs ."
                    )
                    break  # No need to check further, already a mismatch
            if (attempt > max_retries) and (mismatched_buckets):
                raise SyncFailedError(
                    f"sync status is not consistent across sites for the bucket {bucket}"
                )
            else:
                log.info(f"sync is consistent for {bucket}")


def elbencho_run_put_workload(each_user, user_buckets, config):
    """Runs an Elbencho PUT workload on an RGW S3 user with parallel execution."""
    log.info("Starting Elbencho PUT workload")
    elbench_install_configure()
    objects_per_bucket = config.test_ops.get("objects_per_bucket")
    object_size = config.test_ops.get("object_size")
    threads = config.test_ops.get("threads")
    is_multisite = utils.is_cluster_multisite()
    local_endpoint = get_endpoint_elbencho()
    remote_endpoint = get_remote_endpoint_elbencho() if is_multisite else None
    log.info(
        f"the local endpoint is {local_endpoint} and the remote endpoint is {remote_endpoint}"
    )
    objects_per_site = objects_per_bucket // 2 if is_multisite else objects_per_bucket

    for version in range(config.test_ops.get("version_count", 1)):
        log.info(f"Running workload version {version + 1}")
        threads_list = []
        threads_list.append(
            threading.Thread(
                target=run_elbencho,
                args=(
                    local_endpoint,
                    "primary",
                    objects_per_site,
                    user_buckets,
                    each_user,
                    threads,
                    object_size,
                ),
            )
        )
        if is_multisite and remote_endpoint:
            threads_list.append(
                threading.Thread(
                    target=run_elbencho,
                    args=(
                        remote_endpoint,
                        "secondary",
                        objects_per_site,
                        user_buckets,
                        each_user,
                        threads,
                        object_size,
                    ),
                )
            )

        for t in threads_list:
            t.start()
        for t in threads_list:
            t.join()

    if config.test_ops.get("test_bucket_sync", False) is True:
        verify_bucket_sync(user_buckets)

    log.info("PUT workload completed.")
