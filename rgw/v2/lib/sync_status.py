import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError

log = logging.getLogger(__name__)


def restart_rgw_services_and_retry(ssh_con=None):
    """
    Restart RGW services on both primary and secondary zones when metadata sync is stuck.

    Steps:
    1. Get zonegroup map to identify primary and secondary zones
    2. SSH to both nodes
    3. Restart RGW services using ceph orch restart
    4. Wait for services to come back up
    """
    log.info("=" * 80)
    log.info("Attempting to restart RGW services to recover from stuck metadata sync")
    log.info("=" * 80)

    try:
        # Get zonegroup map to identify zones and endpoints
        log.info("Getting zonegroup map to identify primary and secondary zones")
        zonegroup_cmd = "radosgw-admin zonegroup get"
        zonegroup_output = utils.exec_shell_cmd(zonegroup_cmd)
        zonegroup_data = json.loads(zonegroup_output)

        zones = zonegroup_data.get("zones", [])
        if len(zones) < 2:
            log.warning("Less than 2 zones found - skipping secondary zone restart")

        # Extract zone information
        primary_zone = None
        secondary_zone = None

        for zone in zones:
            zone_name = zone.get("name", "")
            endpoints = zone.get("endpoints", [])

            if "primary" in zone_name.lower() or zone.get("id") == zonegroup_data.get(
                "master_zone"
            ):
                primary_zone = {"name": zone_name, "endpoints": endpoints}
            elif "secondary" in zone_name.lower():
                secondary_zone = {"name": zone_name, "endpoints": endpoints}

        log.info(f"Primary zone: {primary_zone}")
        log.info(f"Secondary zone: {secondary_zone}")

        # Restart RGW services on primary zone
        if primary_zone:
            log.info(f"Restarting RGW services on primary zone: {primary_zone['name']}")
            restart_rgw_on_node(None, primary_zone["name"])  # Local node
        else:
            log.warning("Primary zone not identified")

        # Restart RGW services on secondary zone
        if secondary_zone and ssh_con:
            log.info(
                f"Restarting RGW services on secondary zone: {secondary_zone['name']}"
            )
            restart_rgw_on_node(ssh_con, secondary_zone["name"])
        elif secondary_zone:
            log.warning("Secondary zone found but no SSH connection provided")
        else:
            log.warning("Secondary zone not identified")

        log.info("=" * 80)
        log.info("RGW service restart completed on all zones")
        log.info("=" * 80)

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse zonegroup data: {e}")
        raise
    except Exception as e:
        log.error(f"Failed to restart RGW services: {e}")
        raise


def restart_rgw_on_node(ssh_con, zone_name):
    """
    Restart RGW service on a specific node.

    Args:
        ssh_con: SSH connection object (None for local node)
        zone_name: Name of the zone (used to identify RGW service)
    """
    try:
        # Get list of RGW services
        log.info(f"Getting RGW services for zone: {zone_name}")
        list_cmd = "ceph orch ls | grep rgw"

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(list_cmd)
            services_output = stdout.read().decode()
            services_error = stderr.read().decode()
            if services_error and "grep" not in services_error:
                log.warning(f"Error listing RGW services: {services_error}")
        else:
            services_output = utils.exec_shell_cmd(list_cmd)

        log.info(f"RGW services output: {services_output}")

        # Extract service name from output
        # Expected format: rgw.shared.pri  (from "ceph orch ls | grep rgw")
        service_name = None
        for line in services_output.splitlines():
            if "rgw" in line.lower():
                # Extract first word which is the service name
                parts = line.split()
                if parts:
                    service_name = parts[0]
                    break

        if not service_name:
            log.error(f"Could not find RGW service name for zone {zone_name}")
            return

        log.info(f"Found RGW service: {service_name}")

        # Restart the RGW service
        restart_cmd = f"ceph orch restart {service_name}"
        log.info(f"Executing: {restart_cmd}")

        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(restart_cmd)
            restart_output = stdout.read().decode()
            restart_error = stderr.read().decode()

            if restart_error:
                log.warning(f"Restart command stderr: {restart_error}")
            if restart_output:
                log.info(f"Restart command output: {restart_output}")
        else:
            restart_output = utils.exec_shell_cmd(restart_cmd)
            log.info(f"Restart command output: {restart_output}")

        log.info(f"✓ Successfully restarted RGW service: {service_name}")

    except Exception as e:
        log.error(f"Failed to restart RGW on node for zone {zone_name}: {e}")
        raise


def sync_status(retry=30, delay=60, ssh_con=None, return_while_sync_inprogress=False):
    """
    verify multisite sync status
    """
    log.info("check sync status")
    cmd = "sudo radosgw-admin sync status"
    if ssh_con:
        log.info("Enter ssh-conn")
        stdin, stdout, stderr = ssh_con.exec_command(cmd)
        cmd_error = stderr.read().decode()
        if len(cmd_error) != 0:
            log.error(f"error: {cmd_error}")
        check_sync_status = stdout.read().decode()
    else:
        log.info("Enter non-ssh-conn")
        check_sync_status = utils.exec_shell_cmd(cmd)
    if not check_sync_status:
        raise AssertionError("Sync status output is empty")
    log.info(f"sync status op is: {check_sync_status}")

    # check for 'failed' or 'ERROR' in sync status.
    if "failed" in check_sync_status or "ERROR" in check_sync_status:
        log.info("checking for any sync error")

        # Wait for 70 seconds before rechecking
        log.info(
            "Detected 'failed' in sync status. Waiting for 70 seconds before rechecking..."
        )
        time.sleep(70)

        # Recheck sync status after waiting
        if ssh_con:
            stdin, stdout, stderr = ssh_con.exec_command(cmd)
            check_sync_status = stdout.read().decode()
        else:
            check_sync_status = utils.exec_shell_cmd(cmd)

        log.info(f"Rechecked sync status after wait: {check_sync_status}")

        if "failed" in check_sync_status or "ERROR" in check_sync_status:
            cmd = "sudo radosgw-admin sync error list"
            sync_error_list = utils.exec_shell_cmd(cmd)
            raise SyncFailedError("sync status is in failed or errored state!")
        else:
            log.info(
                "Sync status recovered after waiting, proceeding with verification."
            )

    log.info(
        f"check if sync is in progress, if sync is in progress retry {retry} times with {delay} secs of sleep between each retry"
    )
    if "behind" in check_sync_status or "recovering" in check_sync_status:
        log.info("sync is in progress")
        if return_while_sync_inprogress:
            return "sync_progress"
        log.info(f"sleep of {delay} secs for sync to complete")
        for retry_count in range(retry):
            time.sleep(delay)
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(cmd)
                check_sync_status = stdout.read().decode()
            else:
                check_sync_status = utils.exec_shell_cmd(cmd)
            log.info(f"sync status op is: {check_sync_status}")
            if "behind" in check_sync_status or "recovering" in check_sync_status:
                log.info(f"sync is still in progress. sleep for {delay}secs and retry")
            else:
                log.info("sync completed")
                break

        if (retry_count > retry) and (
            "behind" in check_sync_status or "recovering" in check_sync_status
        ):
            raise SyncFailedError(
                f"sync looks slow or stuck. with {retry} retries and sleep of {delay}secs between each retry"
            )

    # check metadata sync status - wait 5 minutes, then restart, then wait 5 more minutes
    if "metadata is behind" in check_sync_status:
        log.warning(
            "metadata is behind on shards - waiting 5 minutes before attempting RGW restart"
        )

        # Wait for up to 5 minutes (5 retries × 60 seconds = 300 seconds)
        metadata_retry = 5
        metadata_delay = 60

        for metadata_retry_count in range(metadata_retry):
            log.info(
                f"Waiting {metadata_delay} seconds for metadata sync to catch up (attempt {metadata_retry_count + 1}/{metadata_retry})"
            )
            time.sleep(metadata_delay)

            # Recheck sync status
            if ssh_con:
                stdin, stdout, stderr = ssh_con.exec_command(cmd)
                check_sync_status = stdout.read().decode()
            else:
                check_sync_status = utils.exec_shell_cmd(cmd)

            log.info(f"Metadata sync status: {check_sync_status}")

            # Check if metadata caught up
            if "metadata is behind" not in check_sync_status:
                log.info("✓ Metadata sync caught up successfully")
                break
        else:
            # After 5 minutes, metadata is still stuck - attempt RGW restart
            log.warning(
                "Metadata sync still stuck after 5 minutes - restarting RGW services"
            )
            try:
                # Attempt to restart RGW services
                restart_rgw_services_and_retry(ssh_con)

                # Wait for services to restart and stabilize
                log.info(
                    "Waiting 5 minutes for RGW services to stabilize and metadata sync to catch up"
                )
                time.sleep(300)

                # Recheck sync status after restart
                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(cmd)
                    check_sync_status = stdout.read().decode()
                else:
                    check_sync_status = utils.exec_shell_cmd(cmd)

                log.info(f"Sync status after RGW restart: {check_sync_status}")

                # If still stuck, raise exception
                if "metadata is behind" in check_sync_status:
                    raise Exception(
                        "metadata sync looks slow or stuck even after RGW service restart."
                    )
                else:
                    log.info("✓ Metadata sync recovered after RGW service restart")
            except Exception as e:
                log.error(f"Failed to recover from metadata sync stuck: {e}")
                raise Exception(
                    f"metadata sync looks slow or stuck. Recovery attempt failed: {e}"
                )

    # check status for complete sync
    if "data is caught up with source" in check_sync_status:
        log.info("sync status complete")
    elif "archive" in check_sync_status or "not syncing from zone" in check_sync_status:
        log.info("data from archive zone does not sync to source zone as per design")
    else:
        raise SyncFailedError("sync is either slow or stuck")

    # check for cluster health status and omap if any
    ceph_status = check_ceph_status()


def check_ceph_status():
    """
    get the ceph cluster status and health
    """
    log.info("get ceph status")
    ceph_status = utils.exec_shell_cmd(cmd="sudo ceph status")
    if "HEALTH_ERR" in ceph_status or "large omap objects" in ceph_status:
        raise Exception(
            "ceph status is either in HEALTH_ERR or we have large omap objects."
        )
    else:
        log.info("ceph status - HEALTH_OK")
