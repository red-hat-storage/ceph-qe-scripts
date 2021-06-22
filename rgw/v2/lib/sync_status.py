import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError

log = logging.getLogger()


def sync_status(retry=5, delay=30):
    """
    verify multisite sync status
    """
    log.info("check sync status")
    cmd = "sudo radosgw-admin sync status"
    check_sync_status = utils.exec_shell_cmd(cmd)

    # check for 'failed' or 'ERROR' in sync status.
    if "failed|ERROR" in check_sync_status:
        log.info("checking for any sync error")
        cmd = "sudo radosgw-admin sync error list"
        sync_error_list = utils.exec_shell_cmd(cmd)
        raise SyncFailedError("sync status is in failed or errored state!")
    else:
        log.info("No errors or failures in sync status")

    log.info(
        f"check if sync is in progress, if sync is in progress retry {retry} times with {delay}secs of sleep between each retry"
    )
    if "behind" in check_sync_status:
        log.info("sync is in progress")
        log.info("sleep of 30 secs for sync to complete")
        for retry_count in range(retry):
            time.sleep(delay)
            cmd = "sudo radosgw-admin sync status"
            check_sync_status = utils.exec_shell_cmd(cmd)
            if "behind" in check_sync_status:
                log.info(f"sync is still in progress. sleep for {delay}secs and retry")
            else:
                log.info("sync completed")
                break

        if (retry_count > retry) and "behind" in check_sync_status:
            raise SyncFailedError(
                f"sync is still in progress. with {retry} retries and sleep of {delay}secs between each retry"
            )

    # check status for complete sync
    if "data is caught up with source" in check_sync_status:
        log.info("sync status complete")
    else:
        raise SyncFailedError("sync is either in progress or stuck")
