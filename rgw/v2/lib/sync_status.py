import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError

log = logging.getLogger(__name__)


def sync_status(retry=25, delay=60, ssh_con=None, return_while_sync_inprogress=False):
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
            # Sync loop terminated after max retries - verify if error persists for 120 seconds
            log.info(
                "Sync loop terminated after max retries. Verifying if error persists for 120 seconds..."
            )

            # Check if sync error persists for 120 seconds (with 10 second intervals)
            error_persists = True
            verification_retries = 12  # 12 retries * 10 seconds = 120 seconds

            for verify_count in range(verification_retries):
                log.info(
                    f"Verification attempt {verify_count + 1}/{verification_retries} - waiting 10 seconds..."
                )
                time.sleep(10)

                # Re-check sync status
                if ssh_con:
                    stdin, stdout, stderr = ssh_con.exec_command(cmd)
                    check_sync_status = stdout.read().decode()
                else:
                    check_sync_status = utils.exec_shell_cmd(cmd)

                log.info(
                    f"Sync status verification {verify_count + 1}:\n{check_sync_status}"
                )

                # If sync is no longer behind or recovering, error has cleared
                if (
                    "behind" not in check_sync_status
                    and "recovering" not in check_sync_status
                ):
                    log.info("Sync error cleared during verification period!")
                    error_persists = False
                    break

            # After 120 seconds verification, check RGW status
            log.info("Checking RGW status after sync timeout verification...")
            check_rgw_status_after_sync_timeout(ssh_con)

            if error_persists:
                raise SyncFailedError(
                    f"sync looks slow or stuck. Error persisted for 120 seconds after {retry} retries with {delay}secs sleep between each retry"
                )
            else:
                log.info("Sync recovered during verification period. Continuing...")

    # check metadata sync status
    if "metadata is behind" in check_sync_status:
        raise Exception("metadata sync looks slow or stuck.")

    # check status for complete sync
    if "data is caught up with source" in check_sync_status:
        log.info("sync status complete")
    elif "archive" in check_sync_status or "not syncing from zone" in check_sync_status:
        log.info("data from archive zone does not sync to source zone as per design")
    else:
        raise SyncFailedError("sync is either slow or stuck")

    # check for cluster health status and omap if any
    ceph_status = check_ceph_status()


def check_rgw_status_after_sync_timeout(ssh_con=None):
    """
    Check RGW status when sync loop terminates with timeout (e.g., 2200 seconds)
    Verifies if RGW is running and checks cluster health

    Parameters:
        ssh_con: SSH connection object for remote execution
    """
    log.info("=" * 80)
    log.info("Checking RGW status after sync timeout")
    log.info("=" * 80)

    # Check if RGW daemons are running
    log.info("Checking RGW daemon status with ceph orch ps")
    cmd_orch_ps = "ceph orch ps --daemon-type rgw"
    if ssh_con:
        stdin, stdout, stderr = ssh_con.exec_command(cmd_orch_ps)
        rgw_ps_output = stdout.read().decode()
    else:
        rgw_ps_output = utils.exec_shell_cmd(cmd_orch_ps)

    log.info(f"RGW daemon status:\n{rgw_ps_output}")

    # Check RGW service status
    log.info("Checking RGW service status with ceph orch ls")
    cmd_orch_ls = "ceph orch ls --service-type rgw"
    if ssh_con:
        stdin, stdout, stderr = ssh_con.exec_command(cmd_orch_ls)
        rgw_ls_output = stdout.read().decode()
    else:
        rgw_ls_output = utils.exec_shell_cmd(cmd_orch_ls)

    log.info(f"RGW service status:\n{rgw_ls_output}")

    # Check cluster health
    log.info("Checking cluster health with ceph -s")
    cmd_ceph_s = "ceph -s"
    if ssh_con:
        stdin, stdout, stderr = ssh_con.exec_command(cmd_ceph_s)
        ceph_s_output = stdout.read().decode()
    else:
        ceph_s_output = utils.exec_shell_cmd(cmd_ceph_s)

    log.info(f"Cluster health status:\n{ceph_s_output}")

    # Analyze RGW status
    if rgw_ps_output and "running" in rgw_ps_output.lower():
        log.info("RGW daemons are in running state")
    else:
        log.error("RGW daemons are NOT in running state")

    if "HEALTH_ERR" in str(ceph_s_output):
        log.error("Cluster is in HEALTH_ERR state")
    elif "HEALTH_WARN" in str(ceph_s_output):
        log.warning("Cluster is in HEALTH_WARN state")
    else:
        log.info("Cluster health is OK")

    log.info("=" * 80)


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
