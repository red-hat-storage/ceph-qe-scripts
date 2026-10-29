"""
test_sync_status_misleading_caught_up.py

Verify radosgw-admin sync status does not report
"metadata is caught up with master" when the local zone is on an older
realm epoch / period than the metadata master.

Tracker: https://tracker.ceph.com/issues/81763
Polarion: CEPH-83633030

Run on VICTIM zone client (ceph-ter) after suite has:
  1) stopped tertiary RGW
  2) promoted secondary + period commit

Usage: test_sync_status_misleading_caught_up.py -c <input_yaml>
<input_yaml>
    multisite_configs/test_sync_status_misleading_caught_up.yaml
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import argparse
import json
import logging
import time
import traceback

import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()


def radosgw_admin(cmd, ssh_con=None):
    """Run radosgw-admin. Returns (stdout, rc).

    Remote: prefer sudo radosgw-admin; fall back to cephadm shell.
    """
    if ssh_con:

        def _remote(remote_cmd):
            log.info(f"[remote] $ {remote_cmd}")
            _, stdout, stderr = ssh_con.exec_command(remote_cmd)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            rc = stdout.channel.recv_exit_status()
            if out.strip():
                for line in out.strip().splitlines():
                    log.info(f"    {line}")
            if err.strip():
                for line in err.strip().splitlines():
                    log.warning(f"    {line}")
            return out, rc

        out, rc = _remote(f"sudo radosgw-admin {cmd}")
        if rc == 0 and out.strip():
            return out, rc
        log.warning(
            "remote sudo radosgw-admin failed (rc=%s); trying cephadm shell", rc
        )
        return _remote(f"sudo cephadm shell -- radosgw-admin {cmd}")
    out = utils.exec_shell_cmd(f"sudo radosgw-admin {cmd}")
    if out is False or out is None:
        return "", 1
    return out, 0


def get_metadata_sync_period_epoch(ssh_con=None):
    """Return (period_id, realm_epoch) from metadata sync status JSON."""
    out, rc = radosgw_admin("metadata sync status --format json", ssh_con)
    if rc != 0 or not out:
        return None, None
    try:
        data = json.loads(out.strip())
    except (TypeError, json.JSONDecodeError):
        return None, None
    info = data.get("sync_status", {}).get("info", {})
    return info.get("period"), info.get("realm_epoch")


def assert_sync_status_no_false_caught_up(
    label, sync_out, master_epoch, sync_epoch, expect_fixed=True, state2=False
):
    """Fail if sync status reports caught-up while on an older realm epoch."""
    caught_up_msg = "metadata is caught up with master"
    diff_period_msg = "master is on a different period"

    if not sync_out or not sync_out.strip():
        raise TestExecError(f"{label}: sync status output is empty")

    caught_up = caught_up_msg in sync_out
    diff_period = diff_period_msg in sync_out
    epoch_lag = (
        sync_epoch is not None
        and master_epoch is not None
        and sync_epoch < master_epoch
    )

    log.info(
        f"{label}: caught_up={caught_up} diff_period={diff_period} "
        f"master_epoch={master_epoch} sync_epoch={sync_epoch}"
    )

    if master_epoch is None or sync_epoch is None:
        raise TestExecError(
            f"{label}: could not read master_epoch={master_epoch} "
            f"sync_epoch={sync_epoch} for comparison"
        )

    if not expect_fixed:
        if caught_up and epoch_lag:
            log.warning(f"{label}: BUG_REPRODUCED — false caught-up with epoch lag")
        else:
            log.info(f"{label}: no false caught-up detected")
        return

    if caught_up and epoch_lag:
        raise TestExecError(
            f"{label}: sync status incorrectly reports '{caught_up_msg}' "
            f"while victim sync_epoch={sync_epoch} < master_epoch={master_epoch}"
        )
    if state2 and caught_up and diff_period:
        raise TestExecError(
            f"{label}: sync status reports both '{diff_period_msg}' and "
            f"'{caught_up_msg}'"
        )
    if epoch_lag and not caught_up:
        log.info(f"{label}: FIXED — lagging zone not reported as caught up")
    else:
        log.info(f"{label}: assertion checks passed")


def test_exec(config, ssh_con):
    ops = config.test_ops or {}
    promote_zone_name = ops.get("promote_zone", "secondary")
    access_key = ops.get("system_access_key", "3way123")
    secret_key = ops.get("system_secret_key", "3way123")
    port = int(ops.get("master_endpoint_port", 80))
    expect_fixed = ops.get("expect_fixed", True)

    if not utils.is_cluster_multisite():
        raise TestExecError("multisite required for sync-status epoch lag test")

    zone_names, realm_name = reusable.get_multisite_info()
    log.info(f"zones={zone_names} realm={realm_name}")
    if promote_zone_name not in zone_names.split(","):
        raise TestExecError(
            f"promote zone '{promote_zone_name}' missing from {zone_names}"
        )

    # Master epoch from promote zone (local period get is stale until realm pull)
    promote_ip = utils.get_rgw_ip_zone(promote_zone_name)
    if not promote_ip:
        raise TestExecError(f"could not resolve RGW IP for zone '{promote_zone_name}'")
    log.info(f"SSH to promote zone '{promote_zone_name}' at {promote_ip}")
    promote_ssh = utils.connect_remote(promote_ip)
    try:
        out, rc = radosgw_admin("period get --format json", promote_ssh)
        if rc != 0 or not out:
            raise TestExecError(
                f"master realm_epoch unavailable from promote zone '{promote_zone_name}'"
            )
        try:
            text = out.strip()
            try:
                period_data = json.loads(text)
            except json.JSONDecodeError:
                # cephadm shell may prepend banners before JSON
                start, end = text.find("{"), text.rfind("}")
                period_data = json.loads(text[start : end + 1])
        except (TypeError, json.JSONDecodeError, ValueError) as e:
            raise TestExecError(f"invalid period get JSON from promote zone: {e}")
        master_period = period_data.get("id")
        master_epoch = period_data.get("realm_epoch")
        if master_epoch is None:
            raise TestExecError(
                f"master realm_epoch unavailable from promote zone '{promote_zone_name}'"
            )
        log.info(f"master period={master_period} epoch={master_epoch}")

        log.info("State 1 — sync status on victim (no realm pull yet)")
        sync_out, rc = radosgw_admin("sync status")
        if rc != 0 and not (sync_out or "").strip():
            raise TestExecError(f"State 1: sync status failed rc={rc}")
        sync_period, sync_epoch = get_metadata_sync_period_epoch()
        assert_sync_status_no_false_caught_up(
            "State 1", sync_out, master_epoch, sync_epoch, expect_fixed, state2=False
        )

        log.info("realm pull on victim (gateway still down)")
        pull_url = f"http://{promote_ip}:{port}"
        out, rc = radosgw_admin(
            f"realm pull --url {pull_url} "
            f"--access-key {access_key} --secret {secret_key}"
        )
        if rc != 0:
            raise TestExecError(f"realm pull failed rc={rc}: {out}")
        time.sleep(3)

        log.info("State 2 — sync status after realm pull")
        sync_out, rc = radosgw_admin("sync status")
        if rc != 0 and not (sync_out or "").strip():
            raise TestExecError(f"State 2: sync status failed rc={rc}")
        sync_period, sync_epoch = get_metadata_sync_period_epoch()
        assert_sync_status_no_false_caught_up(
            "State 2", sync_out, master_epoch, sync_epoch, expect_fixed, state2=True
        )

        log.info(
            f"epoch check: master period={master_period} epoch={master_epoch}; "
            f"victim sync period={sync_period} epoch={sync_epoch}"
        )
        if (
            sync_epoch is not None
            and master_epoch is not None
            and sync_epoch >= master_epoch
        ):
            raise TestExecError(
                "victim sync epoch is not behind master — scenario did not stick; "
                "ensure victim RGW was stopped before period commit"
            )
    finally:
        try:
            promote_ssh.close()
        except Exception:
            pass


if __name__ == "__main__":
    test_info = AddTestInfo(
        "RGW sync status misleading 'caught up' with different period"
    )
    test_info.started_info()
    try:
        parser = argparse.ArgumentParser(
            description="RGW sync status misleading caught-up regression"
        )
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
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
