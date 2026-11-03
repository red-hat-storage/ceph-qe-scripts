"""
test_stale_period_datalog_drop.py

Verify a zone that returns on a stale local period does not silently drop
datalog entries for buckets created on the new master during the outage.

Usage: test_stale_period_datalog_drop.py -c <input_yaml>
<input_yaml>
    multisite_configs/test_stale_period_datalog_drop.yaml

Operation :
    1. Delay period push on Zone B (rgw_period_push_interval)
    2. Stop Zone A RGW and wait until those services are stopped
    3. Promote Zone B to metadata master and commit period
    4. Create bucket + objects on Zone B during the outage
    5. Start Zone A and wait until it serves radosgw-admin on the stale period
    6. Hold the configured race window so Zone A can read datalog while stale
    7. Realm pull on Zone A, retrying until it succeeds, then restart RGWs
       and wait until the pulled period is loaded
    8. Wait for objects on Zone A (fixed); missing = silent datalog drop
    9. Cleanup always runs: start Zone A, delete data while Zone B is master,
       restore Zone A as master, clear the push interval, restart Zone B

Requires multisite with at least two zones. SSL from live endpoint.

Cluster helpers live in this module. They are the failover and restore
sequence for this test, not shared RGW utilities.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def _shell(cmd, ssh_con=None):
    """Run a shell command locally or over ssh. Returns (output, rc)."""
    log.info(f"{'[remote] ' if ssh_con else ''}$ {cmd}")
    if ssh_con:
        _, stdout, stderr = ssh_con.exec_command(cmd)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        if err.strip():
            for line in err.strip().splitlines():
                log.warning(f"    {line}")
        if rc != 0 and err.strip():
            if out.strip():
                return out.rstrip() + "\n" + err, rc
            return err, rc
        return out, rc
    out = utils.exec_shell_cmd(cmd)
    if out is False or out is None:
        return "", 1
    return out, 0


def _parse_json_text(text):
    if not text:
        return None
    raw = text.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start_obj, end_obj = raw.find("{"), raw.rfind("}")
        start_list, end_list = raw.find("["), raw.rfind("]")
        if start_list != -1 and (start_obj == -1 or start_list < start_obj):
            start, end = start_list, end_list
        else:
            start, end = start_obj, end_obj
        if start == -1 or end <= start:
            return None
        return json.loads(raw[start : end + 1])


def _get_rgw_service_names(ssh_con=None):
    """RGW service names from ceph orch on this test's local or peer cluster."""
    out, rc = _shell("sudo ceph orch ls --service-type rgw -f json", ssh_con)
    if rc != 0:
        return []
    try:
        services = _parse_json_text(out) or []
    except (TypeError, json.JSONDecodeError, ValueError):
        return []
    names = []
    for svc in services:
        name = svc.get("service_name")
        if name and name not in names:
            names.append(name)
    return names


def _radosgw_admin(cmd, ssh_con=None):
    """Run radosgw-admin for this test. Returns (output, rc)."""
    if ssh_con:
        out, rc = _shell(f"sudo radosgw-admin {cmd}", ssh_con)
        if rc == 0:
            return out, rc
        log.warning(
            "remote sudo radosgw-admin failed (rc=%s); trying cephadm shell", rc
        )
        out2, rc2 = _shell(f"sudo cephadm shell -- radosgw-admin {cmd}", ssh_con)
        if rc2 == 0:
            return out2, rc2
        return out, rc
    return _shell(f"sudo radosgw-admin {cmd}", None)


def _promote_zone_master(ssh_con, zone_name, zonegroup):
    """Promote zone_name and commit the period from the given site."""
    out, rc = _radosgw_admin(f"zone modify --rgw-zone={zone_name} --master", ssh_con)
    if rc != 0:
        raise TestExecError(f"zone modify --master {zone_name} failed: {out}")
    out, rc = _radosgw_admin(
        f"zonegroup modify --rgw-zonegroup={zonegroup} --master "
        f"--rgw-zone={zone_name}",
        ssh_con,
    )
    if rc != 0:
        raise TestExecError(f"zonegroup modify --master {zone_name} failed: {out}")
    out, rc = _radosgw_admin("period update --commit --yes-i-really-mean-it", ssh_con)
    if rc != 0:
        raise TestExecError(f"period update --commit after promote failed: {out}")


def _parse_realm_epoch(period_out):
    try:
        data = _parse_json_text(period_out)
    except (TypeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data.get("realm_epoch")


def _zone_is_master(zone_name, ssh_con=None):
    out, rc = _radosgw_admin("zonegroup get --format json", ssh_con)
    if rc != 0:
        return False
    try:
        data = _parse_json_text(out)
    except (TypeError, json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    for zone in data.get("zones") or []:
        if zone.get("name") == zone_name and zone.get("master"):
            return True
    return False


def _objects_present_in_bucket(s3_client, bucket_name, keys):
    try:
        listed = reusable.get_object_list(bucket_name, s3_client)
    except Exception as exc:
        log.warning(f"list objects on {bucket_name} failed: {exc}")
        return False
    return all(key in listed for key in keys)


def _rgw_daemons(ssh_con=None):
    out, rc = _shell("sudo ceph orch ps --daemon_type rgw -f json", ssh_con)
    if rc != 0:
        return []
    try:
        daemons = _parse_json_text(out) or []
    except (TypeError, json.JSONDecodeError, ValueError):
        return []
    return daemons if isinstance(daemons, list) else []


def _services_are(services, want_running, ssh_con=None):
    daemons = _rgw_daemons(ssh_con)
    for service in services:
        owned = [d for d in daemons if d.get("service_name") == service]
        running = [d for d in owned if str(d.get("status_desc")) == "running"]
        if want_running:
            if not owned or running != owned:
                return False
        elif running:
            return False
    return True


def _wait_until(description, timeout, interval, predicate):
    """Poll until predicate is true. Raises TestExecError on timeout."""
    deadline = time.time() + timeout
    last_error = None
    while True:
        try:
            if predicate():
                log.info(f"ready: {description}")
                return
        except Exception as exc:
            last_error = exc
            log.warning(f"waiting for {description}: {exc}")
        remaining = deadline - time.time()
        if remaining <= 0:
            raise TestExecError(
                f"timed out after {timeout}s waiting for {description}"
                + (f": {last_error}" if last_error else "")
            )
        time.sleep(min(interval, remaining))


def _wait_for_services(services, want_running, timeout, interval, ssh_con=None):
    state = "running" if want_running else "stopped"
    _wait_until(
        f"RGW services {services} to be {state}",
        timeout,
        interval,
        lambda: _services_are(services, want_running, ssh_con),
    )


def _wait_for_admin(timeout, interval, ssh_con=None):
    def _ready():
        _, rc = _radosgw_admin("sync status", ssh_con)
        return rc == 0

    _wait_until("radosgw-admin sync status", timeout, interval, _ready)


def _realm_pull(pull_url, access_key, secret_key, timeout, interval):
    cmd = (
        f"realm pull --url {pull_url} "
        f"--access-key {access_key} --secret {secret_key}"
    )
    last_out = ""

    def _pulled():
        nonlocal last_out
        last_out, rc = _radosgw_admin(cmd)
        return rc == 0

    try:
        _wait_until("realm pull from the promoted zone", timeout, interval, _pulled)
    except TestExecError:
        raise TestExecError(f"realm pull failed: {last_out}")


def _stop_services(services):
    for service in services:
        reusable.bring_down_all_rgws_in_the_site(service)


def _start_services(services):
    for service in services:
        reusable.bring_up_all_rgws_in_the_site(service)


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    ops = config.test_ops or {}
    zone_a = ops.get("zone_a", "primary")
    zone_b = ops.get("zone_b", "secondary")
    push_interval = int(ops.get("push_interval_secs", 120))
    race_window = int(ops.get("race_window_secs", 15))
    sync_wait = int(ops.get("sync_wait_secs", 180))
    sync_poll = int(ops.get("sync_poll_secs", 10))
    access_key = ops.get("system_access_key", "3way123")
    secret_key = ops.get("system_secret_key", "3way123")
    port = int(ops.get("master_endpoint_port", 80))
    expect_fixed = ops.get("expect_fixed", True)
    service_timeout = max(sync_wait, 180)

    if not utils.is_cluster_multisite():
        raise TestExecError("multisite required for stale-period datalog drop test")
    if not utils.is_cluster_primary():
        raise TestExecError(
            f"run this test on Zone A ({zone_a}); local site is not metadata master"
        )

    zone_names, realm_name = reusable.get_multisite_info()
    log.info(f"zones={zone_names} realm={realm_name}")
    for zone in (zone_a, zone_b):
        if zone not in zone_names.split(","):
            raise TestExecError(f"zone '{zone}' missing from {zone_names}")

    zone_a_services = ops.get("zone_a_services")
    if not zone_a_services:
        zone_a_services = _get_rgw_service_names()
    if isinstance(zone_a_services, str):
        zone_a_services = [zone_a_services]
    if not zone_a_services:
        raise TestExecError("no RGW services found on Zone A via ceph orch ls")
    log.info(f"Zone A RGW services: {zone_a_services}")

    detected = aws_reusable.get_endpoint(ssh_con, ssl=None, haproxy=False)
    use_ssl = detected.startswith("https://")
    log.info(f"ssl={use_ssl} haproxy={config.haproxy}")

    zone_b_ip = utils.get_rgw_ip_zone(zone_b)
    if not zone_b_ip:
        raise TestExecError(f"could not resolve RGW IP for zone '{zone_b}'")
    scheme = "https" if use_ssl else "http"
    zone_b_endpoint = f"{scheme}://{zone_b_ip}:{port}"
    log.info(f"Zone B endpoint={zone_b_endpoint}")

    state = {
        "push_set": False,
        "master_changed": False,
        "zone_a_down": False,
        "user_info": None,
        "bucket": None,
        "bucket_name": None,
        "zone_b_ssh": None,
        "zone_b_services": [],
        "zonegroup": ops.get("zonegroup"),
    }
    object_keys = []
    ceph_conf = CephConfOp()

    def _restore_cluster():
        # Each step is isolated so one cleanup failure cannot skip the rest.
        if state["zone_a_down"]:
            try:
                log.info(f"ensure Zone A services {zone_a_services} are up")
                _start_services(zone_a_services)
                _wait_for_services(zone_a_services, True, service_timeout, sync_poll)
                state["zone_a_down"] = False
            except Exception as exc:
                log.warning(f"Zone A start during cleanup failed: {exc}")

        bucket = state["bucket"]
        bucket_name = state["bucket_name"]
        user_info = state["user_info"]
        zone_b_ssh = state["zone_b_ssh"]
        if ops.get("delete_bucket_object", True) and bucket is not None:
            try:
                reusable.delete_objects(bucket, gc_verification=False)
                reusable.delete_bucket(bucket)
            except Exception as exc:
                log.warning(f"bucket cleanup via Zone B resource: {exc}")
                if bucket_name:
                    try:
                        reusable.force_delete_bucket_from_secondary(
                            bucket_name, expected_objects=0
                        )
                    except Exception as exc2:
                        log.warning(f"force delete on secondary failed: {exc2}")

        removed = False
        if config.user_remove and user_info:
            uid = user_info["user_id"]
            try:
                if zone_b_ssh is not None and state["master_changed"]:
                    log.info(f"remove user {uid} on Zone B (current master)")
                    out, rc = _radosgw_admin(
                        f"user rm --purge-keys --purge-data --uid={uid}",
                        zone_b_ssh,
                    )
                    removed = rc == 0
                    if not removed:
                        log.warning(f"user rm on Zone B rc={rc}: {out}")
                else:
                    reusable.remove_user(user_info)
                    removed = True
            except Exception as exc:
                log.warning(f"user cleanup: {exc}")

        zonegroup = state["zonegroup"]
        if state["master_changed"] and zonegroup:
            restored = False
            try:
                log.info(f"restore Zone A ({zone_a}) as metadata master (local)")
                _promote_zone_master(None, zone_a, zonegroup)
                _wait_until(
                    f"zonegroup master to be {zone_a}",
                    service_timeout,
                    sync_poll,
                    lambda: _zone_is_master(zone_a),
                )
                restored = True
            except Exception as exc:
                log.warning(f"local restore master failed: {exc}")
                if zone_b_ssh is not None:
                    try:
                        log.info(f"retry restore master for {zone_a} via Zone B")
                        _promote_zone_master(zone_b_ssh, zone_a, zonegroup)
                        _wait_until(
                            f"zonegroup master to be {zone_a}",
                            service_timeout,
                            sync_poll,
                            lambda: _zone_is_master(zone_a),
                        )
                        restored = True
                    except Exception as exc2:
                        log.warning(f"restore master to {zone_a} failed: {exc2}")
            if restored:
                state["master_changed"] = False
            if config.user_remove and user_info and not removed:
                uid = user_info["user_id"]
                try:
                    log.info(f"remove user {uid} on restored master")
                    _radosgw_admin(
                        f"user rm --purge-keys --purge-data --uid={uid} "
                        f"--yes-i-really-mean-it"
                    )
                except Exception as exc:
                    log.warning(f"user rm after master restore failed: {exc}")

        if state["push_set"] and zone_b_ssh is not None:
            try:
                whos = [f"client.{svc}" for svc in state["zone_b_services"]] or [
                    "client.rgw"
                ]
                log.info(f"clear period push overrides on {whos}")
                for who in whos:
                    for key in (
                        "rgw_period_push_interval",
                        "rgw_period_push_interval_max",
                    ):
                        utils.remote_exec_shell_cmd(
                            zone_b_ssh, f"sudo ceph config rm {who} {key}"
                        )
                for service in state["zone_b_services"]:
                    _shell(f"sudo ceph orch restart {service}", zone_b_ssh)
                if state["zone_b_services"]:
                    _wait_for_services(
                        state["zone_b_services"],
                        True,
                        service_timeout,
                        sync_poll,
                        zone_b_ssh,
                    )
                state["push_set"] = False
            except Exception as exc:
                log.warning(f"clear period push interval failed: {exc}")

        if zone_b_ssh is not None:
            try:
                zone_b_ssh.close()
            except Exception:
                pass
            state["zone_b_ssh"] = None

    try:
        state["zone_b_ssh"] = reusable.get_remote_conn_in_multisite()
        state["zone_b_services"] = _get_rgw_service_names(state["zone_b_ssh"])
        if not state["zone_b_services"]:
            raise TestExecError("no RGW services found on Zone B via ceph orch ls")
        log.info(f"Zone B RGW services: {state['zone_b_services']}")

        period_out, _ = _radosgw_admin("period get --format json")
        initial_epoch = _parse_realm_epoch(period_out)
        log.info(f"initial realm_epoch={initial_epoch}")

        if not state["zonegroup"]:
            zg_out, zg_rc = _radosgw_admin("zonegroup get --format json")
            if zg_rc == 0:
                try:
                    parsed = _parse_json_text(zg_out)
                    state["zonegroup"] = (
                        parsed.get("name") if isinstance(parsed, dict) else None
                    )
                except (TypeError, json.JSONDecodeError, ValueError, AttributeError):
                    state["zonegroup"] = None
        if not state["zonegroup"]:
            raise TestExecError("could not determine zonegroup name")
        log.info(f"zonegroup={state['zonegroup']}")

        log.info(f"delay period push on {zone_b} ({push_interval}s)")
        ceph_conf.set_to_ceph_conf(
            "global",
            "rgw_period_push_interval",
            push_interval,
            set_to_all=True,
            remote_ssh_con=state["zone_b_ssh"],
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            "rgw_period_push_interval_max",
            push_interval,
            set_to_all=True,
            remote_ssh_con=state["zone_b_ssh"],
        )
        state["push_set"] = True

        state["user_info"] = s3lib.create_users(config.user_count or 1)[0]
        log.info(f"user: {state['user_info']['user_id']}")

        log.info(f"stop Zone A services {zone_a_services}")
        state["zone_a_down"] = True
        _stop_services(zone_a_services)
        _wait_for_services(zone_a_services, False, service_timeout, sync_poll)

        # Set before the call so a failure halfway through zone modify still
        # restores the original master during cleanup.
        state["master_changed"] = True
        log.info(f"promote Zone B ({zone_b}) to metadata master")
        _promote_zone_master(state["zone_b_ssh"], zone_b, state["zonegroup"])
        _wait_until(
            f"zonegroup master to be {zone_b}",
            service_timeout,
            sync_poll,
            lambda: _zone_is_master(zone_b, state["zone_b_ssh"]),
        )
        new_period, _ = _radosgw_admin("period get --format json", state["zone_b_ssh"])
        new_epoch = _parse_realm_epoch(new_period)
        log.info(f"post-promote realm_epoch={new_epoch}")
        if (
            initial_epoch is not None
            and new_epoch is not None
            and new_epoch <= initial_epoch
        ):
            raise TestExecError(
                f"realm epoch did not advance after promote "
                f"({initial_epoch} -> {new_epoch})"
            )

        user_info = state["user_info"]
        auth_b = Auth(
            user_info,
            ssl=use_ssl,
            haproxy=False,
            endpoint_ip=zone_b_ip,
            endpoint_port=port,
        )
        rgw_b = auth_b.do_auth()
        s3_b = auth_b.do_auth_using_client()

        if not config.mapped_sizes:
            config.mapped_sizes = utils.make_mapped_sizes(config)
        mapped = list(config.mapped_sizes.items())
        if len(mapped) < 1:
            raise TestExecError("objects_count must be >= 1")

        bucket_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=0)
        state["bucket_name"] = bucket_name
        log.info(f"create bucket {bucket_name} on Zone B during Zone A outage")
        bucket = reusable.create_bucket_sync_init(bucket_name, rgw_b, user_info)
        state["bucket"] = bucket

        for oc, size in mapped:
            config.obj_size = size
            key = utils.gen_s3_object_name(bucket.name, oc)
            reusable.upload_object(key, bucket, TEST_DATA_PATH, config, user_info)
            object_keys.append(key)
            log.info(f"uploaded {key} size={size} on Zone B")

        if not _objects_present_in_bucket(s3_b, bucket_name, object_keys):
            raise TestExecError(
                f"objects missing on Zone B after upload; "
                f"listed={reusable.get_object_list(bucket_name, s3_b)}"
            )

        log.info(f"start Zone A services {zone_a_services} (stale local period)")
        _start_services(zone_a_services)
        _wait_for_services(zone_a_services, True, service_timeout, sync_poll)
        _wait_for_admin(service_timeout, sync_poll)
        state["zone_a_down"] = False
        # Intentional stale-period window, not a readiness sleep. Zone A is
        # already up and answering admin commands before this starts.
        log.info(f"hold race window {race_window}s for Zone A datalog read")
        time.sleep(race_window)

        sync_out, _ = _radosgw_admin("sync status")
        log.info(f"Zone A sync status after restart:\n{sync_out}")
        errors, _ = _radosgw_admin("sync error list --format json")
        log.info(f"Zone A sync error list after race window: {errors}")

        auth_a = reusable.get_auth(user_info, ssh_con, use_ssl, config.haproxy)
        s3_a = auth_a.do_auth_using_client()
        early_ok = _objects_present_in_bucket(s3_a, bucket_name, object_keys)
        log.info(f"Zone A objects present after race window: {early_ok}")

        pull_url = f"{scheme}://{zone_b_ip}:{port}"
        log.info(f"realm pull on Zone A from {pull_url}")
        _realm_pull(pull_url, access_key, secret_key, service_timeout, sync_poll)

        log.info(f"restart Zone A services {zone_a_services} to load pulled period")
        state["zone_a_down"] = True
        _stop_services(zone_a_services)
        _wait_for_services(zone_a_services, False, service_timeout, sync_poll)
        _start_services(zone_a_services)
        _wait_for_services(zone_a_services, True, service_timeout, sync_poll)
        _wait_for_admin(service_timeout, sync_poll)
        if new_epoch is not None:

            def _epoch_loaded():
                out, rc = _radosgw_admin("period get --format json")
                if rc != 0:
                    return False
                epoch = _parse_realm_epoch(out)
                return epoch is not None and epoch >= new_epoch

            _wait_until(
                f"local realm epoch >= {new_epoch}",
                service_timeout,
                sync_poll,
                _epoch_loaded,
            )
        state["zone_a_down"] = False
        sync_out, _ = _radosgw_admin("sync status")
        log.info(f"Zone A sync status after period reload:\n{sync_out}")

        auth_a = reusable.get_auth(user_info, ssh_con, use_ssl, config.haproxy)
        s3_a = auth_a.do_auth_using_client()

        log.info(f"wait up to {sync_wait}s for outage objects on Zone A")
        deadline = time.time() + sync_wait
        synced = False
        while time.time() < deadline:
            synced = _objects_present_in_bucket(s3_a, bucket_name, object_keys)
            if synced:
                break
            time.sleep(sync_poll)
        final_errors, _ = _radosgw_admin("sync error list --format json")
        log.info(f"Zone A sync error list after wait: {final_errors}")
        log.info(f"Zone A objects present after wait: {synced}")

        if expect_fixed:
            if not synced:
                listed = []
                try:
                    listed = reusable.get_object_list(bucket_name, s3_a)
                except Exception:
                    pass
                raise TestExecError(
                    f"objects written on Zone B during Zone A outage never "
                    f"synced to Zone A after period update; "
                    f"expected={object_keys} listed={listed}; "
                    f"sync_errors={final_errors}"
                )
            log.info(
                "FIXED: outage bucket/objects present on Zone A after period update"
            )
        else:
            if not synced:
                log.warning(
                    "BUG_REPRODUCED: objects missing on Zone A after period update"
                )
            else:
                log.info("objects present on Zone A (no silent drop observed)")

        crash_info = reusable.check_for_crash()
        if crash_info:
            raise TestExecError(
                f"ceph crash found after stale-period test: {crash_info}"
            )
    finally:
        _restore_cluster()


if __name__ == "__main__":
    test_info = AddTestInfo("RGW stale-period datalog drop for outage-created buckets")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW stale-period datalog drop regression"
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
