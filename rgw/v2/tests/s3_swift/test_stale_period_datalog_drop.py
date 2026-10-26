"""
test_stale_period_datalog_drop.py

Verify a zone that returns on a stale local period does not silently drop
datalog entries for buckets created on the new master during the outage.

Usage: test_stale_period_datalog_drop.py -c <input_yaml>
<input_yaml>
    multisite_configs/test_stale_period_datalog_drop.yaml

Operation :
    1. Delay period push on Zone B (rgw_period_push_interval)
    2. Stop Zone A RGW (ceph orch stop)
    3. Promote Zone B to metadata master and commit period
    4. Create bucket + objects on Zone B during the outage
    5. Start Zone A (stale local period); wait race window for datalog read
    6. Realm pull on Zone A; restart RGWs so daemons load the new period
    7. Wait for objects on Zone A (fixed); missing = silent datalog drop
    8. Cleanup: delete data/user on Zone B, restore Zone A as master, clear push

Requires multisite with at least two zones. SSL from live endpoint
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

    if not utils.is_cluster_multisite():
        raise TestExecError("multisite required for stale-period datalog drop test")
    if not utils.is_cluster_primary():
        raise TestExecError(
            f"run this test on Zone A ({zone_a}); local site is not metadata master"
        )

    zone_names, realm_name = reusable.get_multisite_info()
    log.info(f"zones={zone_names} realm={realm_name}")
    for z in (zone_a, zone_b):
        if z not in zone_names.split(","):
            raise TestExecError(f"zone '{z}' missing from {zone_names}")

    # Discover local RGW orch services (works for .io/.sync split or single service)
    zone_a_services = ops.get("zone_a_services")
    if not zone_a_services:
        zone_a_services = reusable.get_rgw_service_names()
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

    push_set = False
    promoted = False
    zone_a_down = False
    user_info = None
    bucket = None
    bucket_name = None
    object_keys = []
    zone_b_ssh = None
    zone_b_services = []
    zonegroup = ops.get("zonegroup")
    ceph_conf = CephConfOp()

    try:
        # Capture Zone B SSH before topology changes (exec_on_secondary breaks after pull)
        zone_b_ssh = reusable.get_remote_conn_in_multisite()
        zone_b_services = reusable.get_rgw_service_names(zone_b_ssh)
        if not zone_b_services:
            raise TestExecError("no RGW services found on Zone B via ceph orch ls")
        log.info(f"Zone B RGW services: {zone_b_services}")

        period_out, _ = reusable.radosgw_admin("period get --format json")
        initial_epoch = reusable.parse_realm_epoch(period_out)
        log.info(f"initial realm_epoch={initial_epoch}")

        if not zonegroup:
            zg_out, _ = reusable.radosgw_admin("zonegroup get --format json")
            try:
                zonegroup = json.loads(zg_out.strip()).get("name")
            except (TypeError, json.JSONDecodeError, AttributeError):
                zonegroup = None
        if not zonegroup:
            raise TestExecError("could not determine zonegroup name")
        log.info(f"zonegroup={zonegroup}")

        log.info(f"delay period push on {zone_b} ({push_interval}s)")
        # set_to_all applies to every RGW daemon discovered on Zone B
        ceph_conf.set_to_ceph_conf(
            "global",
            "rgw_period_push_interval",
            push_interval,
            set_to_all=True,
            remote_ssh_con=zone_b_ssh,
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            "rgw_period_push_interval_max",
            push_interval,
            set_to_all=True,
            remote_ssh_con=zone_b_ssh,
        )
        push_set = True

        user_info = s3lib.create_users(config.user_count or 1)[0]
        log.info(f"user: {user_info['user_id']}")

        log.info(f"stop Zone A services {zone_a_services}")
        for svc in zone_a_services:
            reusable.bring_down_all_rgws_in_the_site(svc)
        zone_a_down = True
        time.sleep(2)

        log.info(f"promote Zone B ({zone_b}) to metadata master")
        reusable.promote_zone_master(zone_b_ssh, zone_b, zonegroup)
        promoted = True
        new_period, _ = reusable.radosgw_admin("period get --format json", zone_b_ssh)
        new_epoch = reusable.parse_realm_epoch(new_period)
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
        log.info(f"create bucket {bucket_name} on Zone B during Zone A outage")
        bucket = reusable.create_bucket_sync_init(bucket_name, rgw_b, user_info)

        for oc, size in mapped:
            config.obj_size = size
            key = utils.gen_s3_object_name(bucket.name, oc)
            reusable.upload_object(key, bucket, TEST_DATA_PATH, config, user_info)
            object_keys.append(key)
            log.info(f"uploaded {key} size={size} on Zone B")

        if not reusable.objects_present_in_bucket(s3_b, bucket_name, object_keys):
            raise TestExecError(
                f"objects missing on Zone B after upload; "
                f"listed={reusable.get_object_list(bucket_name, s3_b)}"
            )

        log.info(f"start Zone A services {zone_a_services} (stale local period)")
        for svc in zone_a_services:
            reusable.bring_up_all_rgws_in_the_site(svc)
        zone_a_down = False
        log.info(f"wait race window {race_window}s for Zone A datalog read")
        time.sleep(race_window)

        sync_out, _ = reusable.radosgw_admin("sync status")
        log.info(f"Zone A sync status after restart:\n{sync_out}")
        errors, _ = reusable.radosgw_admin("sync error list --format json")
        log.info(f"Zone A sync error list after race window: {errors}")

        auth_a = reusable.get_auth(user_info, ssh_con, use_ssl, config.haproxy)
        s3_a = auth_a.do_auth_using_client()
        early_ok = reusable.objects_present_in_bucket(s3_a, bucket_name, object_keys)
        log.info(f"Zone A objects present after race window: {early_ok}")

        pull_url = f"{scheme}://{zone_b_ip}:{port}"
        log.info(f"realm pull on Zone A from {pull_url}")
        pull_out, pull_rc = reusable.radosgw_admin(
            f"realm pull --url {pull_url} "
            f"--access-key {access_key} --secret {secret_key}"
        )
        if pull_rc != 0:
            log.warning(f"realm pull failed rc={pull_rc}: {pull_out}; continuing")

        # Running RGWs keep the stale in-memory period after realm pull until
        # reload; bounce them so metadata/data sync use Zone B as master.
        # Race window above already exercised the stale-period datalog path.
        log.info(f"restart Zone A services {zone_a_services} to load pulled period")
        for svc in zone_a_services:
            reusable.bring_down_all_rgws_in_the_site(svc)
        for svc in zone_a_services:
            reusable.bring_up_all_rgws_in_the_site(svc)
        time.sleep(10)
        sync_out, _ = reusable.radosgw_admin("sync status")
        log.info(f"Zone A sync status after period reload:\n{sync_out}")

        # Re-auth after bounce (endpoint/service may have moved briefly).
        auth_a = reusable.get_auth(user_info, ssh_con, use_ssl, config.haproxy)
        s3_a = auth_a.do_auth_using_client()

        # Poll object presence (pass criterion). Do not use wait_till_bucket_synced:
        # when the silent-drop bug hits, the bucket is missing on Zone A and
        # `bucket sync status` fails, which is the failure mode under test.
        log.info(f"wait up to {sync_wait}s for outage objects on Zone A")
        deadline = time.time() + sync_wait
        synced = False
        while time.time() < deadline:
            synced = reusable.objects_present_in_bucket(s3_a, bucket_name, object_keys)
            if synced:
                break
            time.sleep(sync_poll)
        final_errors, _ = reusable.radosgw_admin("sync error list --format json")
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
        if zone_a_down:
            try:
                log.info(f"ensure Zone A services {zone_a_services} are up")
                for svc in zone_a_services:
                    reusable.bring_up_all_rgws_in_the_site(svc)
            except Exception as e:
                log.warning(f"Zone A start during cleanup failed: {e}")
        # Delete data / user while Zone B is still metadata master, then restore.
        if ops.get("delete_bucket_object", True) and bucket is not None:
            try:
                reusable.delete_objects(bucket, gc_verification=False)
                reusable.delete_bucket(bucket)
            except Exception as e:
                log.warning(f"bucket cleanup via Zone B resource: {e}")
                if bucket_name:
                    try:
                        reusable.force_delete_bucket_from_secondary(
                            bucket_name, expected_objects=0
                        )
                    except Exception as e2:
                        log.warning(f"force delete on secondary failed: {e2}")
        if config.user_remove and user_info:
            uid = user_info["user_id"]
            removed = False
            try:
                if zone_b_ssh is not None:
                    log.info(f"remove user {uid} on Zone B (current master)")
                    out, rc = reusable.radosgw_admin(
                        f"user rm --purge-keys --purge-data --uid={uid}",
                        zone_b_ssh,
                    )
                    removed = rc == 0
                    if not removed:
                        log.warning(f"user rm on Zone B rc={rc}: {out}")
                else:
                    reusable.remove_user(user_info)
                    removed = True
            except Exception as e:
                log.warning(f"user cleanup: {e}")
            if not removed:
                try:
                    log.info(f"force-remove user {uid} locally")
                    reusable.radosgw_admin(
                        f"user rm --purge-keys --purge-data --uid={uid} "
                        f"--yes-i-really-mean-it"
                    )
                except Exception as e2:
                    log.warning(f"forced local user rm failed: {e2}")
        if promoted and zonegroup:
            # Prefer local restore: Zone B SSH often cannot load zone=primary
            # (`failed to load zone: ENOENT`) after the failover topology change.
            try:
                log.info(f"restore Zone A ({zone_a}) as metadata master (local)")
                reusable.promote_zone_master(None, zone_a, zonegroup)
            except Exception as e:
                log.warning(f"local restore master failed: {e}")
                if zone_b_ssh is not None:
                    try:
                        log.info(f"retry restore master for {zone_a} via Zone B")
                        reusable.promote_zone_master(zone_b_ssh, zone_a, zonegroup)
                    except Exception as e2:
                        log.warning(f"restore master to {zone_a} failed: {e2}")
        if push_set and zone_b_ssh is not None:
            try:
                whos = [f"client.{svc}" for svc in zone_b_services] or ["client.rgw"]
                log.info(f"clear period push overrides on {whos}")
                for who in whos:
                    for key in (
                        "rgw_period_push_interval",
                        "rgw_period_push_interval_max",
                    ):
                        utils.remote_exec_shell_cmd(
                            zone_b_ssh, f"sudo ceph config rm {who} {key}"
                        )
            except Exception as e:
                log.warning(f"clear period push interval failed: {e}")
        if zone_b_ssh is not None:
            try:
                zone_b_ssh.close()
            except Exception:
                pass


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
