import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError

log = logging.getLogger(__name__)


def sync_status(retry=10, delay=60):
    """
    verify multisite sync status
    """
    log.info("check sync status")
    ceph_version = utils.exec_shell_cmd("ceph version").split()[4]
    if ceph_version == "pacific":
        cmd = " ceph orch ps | grep rgw"
        out = utils.exec_shell_cmd(cmd)
        rgw_process_name = out.split()[0]
        out = utils.exec_shell_cmd(
            f"ceph config set client.{rgw_process_name} rgw_sync_lease_period 120"
        )
        cmd = " ceph orch ls | grep rgw"
        out = utils.exec_shell_cmd(cmd)
        rgw_name = out.split()[0]
        utils.exec_shell_cmd(f"ceph orch restart {rgw_name}")
    cmd = "sudo radosgw-admin sync status"
    check_sync_status = utils.exec_shell_cmd(cmd)

    # check for 'failed' or 'ERROR' in sync status.
    if "failed" in check_sync_status or "ERROR" in check_sync_status:
        log.info("checking for any sync error")
        cmd = "sudo radosgw-admin sync error list"
        sync_error_list = utils.exec_shell_cmd(cmd)
        raise SyncFailedError("sync status is in failed or errored state!")
    else:
        log.info("No errors or failures in sync status")

    log.info(
        f"check if sync is in progress, if sync is in progress retry {retry} times with {delay}secs of sleep between each retry"
    )
    if "behind" in check_sync_status or "recovering" in check_sync_status:
        log.info("sync is in progress")
        log.info(f"sleep of {delay} secs for sync to complete")
        for retry_count in range(retry):
            time.sleep(delay)
            cmd = "sudo radosgw-admin sync status"
            check_sync_status = utils.exec_shell_cmd(cmd)
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
    elif (
        "archive" in check_sync_status and "not syncing from zone" in check_sync_status
    ):
        log.info("data from archive zone does not sync to source zone as per design")
    else:
        raise SyncFailedError("sync is either slow or stuck")
