import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError

log = logging.getLogger(__name__)


def sync_status(retry=25, delay=60, ssh_con=None):
    """
    verify multisite sync status
    """
    log.info("check sync status")
    cmd = "sudo radosgw-admin sync status"
    if ssh_con:
        log.info("Enter ssh-conn")
        stdin, stdout, stderr = ssh_con.exec_command(cmd)
        check_sync_status = stdout.read().decode()
    else:
        log.info("Enter non-ssh-conn")
        check_sync_status = utils.exec_shell_cmd(cmd)
    log.info(f"sync status op is: {check_sync_status}")
    # check for 'failed' or 'ERROR' in sync status.
    if "failed" in check_sync_status or "ERROR" in check_sync_status:
        log.info("checking for any sync error")
        cmd = "sudo radosgw-admin sync error list"
        sync_error_list = utils.exec_shell_cmd(cmd)
        raise SyncFailedError("sync status is in failed or errored state!")
    else:
        log.info("No errors or failures in sync status")

    log.info(
        f"check if sync is in progress, if sync is in progress retry {retry} times with {delay} secs of sleep between each retry"
    )
    if "behind" in check_sync_status or "recovering" in check_sync_status:
        log.info("sync is in progress")
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
