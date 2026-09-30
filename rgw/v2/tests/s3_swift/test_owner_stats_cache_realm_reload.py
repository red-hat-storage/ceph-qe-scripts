"""
test_owner_stats_cache_realm_reload.py

Verify no SIGSEGV in RGWOwnerStatsCache::init_refresh() after realm reload
(dangling DoutPrefix from RGWRealmReloader::reload()).

Tracker: https://tracker.ceph.com/issues/80315
Fix PR:  https://github.com/ceph/ceph/pull/70583

Usage: test_owner_stats_cache_realm_reload.py -c <input_yaml>

<input_yaml>
    configs/test_owner_stats_cache_realm_reload.yaml

Operation (expects fixed build / QE regression):
    1. Create user, enable user-scoped quota, create bucket
    2. Control PUT before realm reload (must succeed)
    3. Shorten rgw_bucket_quota_ttl via admin socket (no restart)
    4. Realm reload: radosgw-admin period update --commit
    5. Wait for TTL expiry; two PUTs (both must succeed on fixed build)
    6. Verify RGW daemons healthy and no new crashes
    7. Cleanup; restore default quota TTL

Requires multisite (realm/zonegroup/zone) so period update triggers reload.
If the cluster is not multisite, the test skips with a warning and passes.
SSL from live endpoint via aws.reusable.get_endpoint (http/80 → non-SSL;
https/443|444 → SSL; other ports from frontends). Optional verify_tls.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import argparse
import logging
import time
import traceback

import requests
import urllib3
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError, EndpointConnectionError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import quota_management as quota_mgmt
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import rgw_daemons_status

log = logging.getLogger()
TEST_DATA_PATH = None
DEFAULT_QUOTA_TTL = "600"


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Multisite gate first so non-MS / no-realm exits before endpoint/SSL work
    try:
        _, realm_name = reusable.get_multisite_info()
    except Exception as e:
        log.warning(
            f"not a multisite cluster (get_multisite_info failed: {e}); skipping owner-stats-cache realm reload test"
        )
        return
    if not realm_name:
        log.warning(
            "not a multisite cluster (no realm); skipping owner-stats-cache realm reload test"
        )
        return
    log.info(f"multisite realm: {realm_name}")

    # Detect SSL from live RGW port/frontends (not config.ssl); haproxy=False
    # so port rules apply before Auth/haproxy overrides the listen port.
    detected_endpoint = aws_reusable.get_endpoint(ssh_con, ssl=None, haproxy=False)
    use_ssl = detected_endpoint.startswith("https://")
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, use_ssl)

    ttl = int(config.test_ops.get("rgw_bucket_quota_ttl", 15))
    wait_secs = int(config.test_ops.get("quota_ttl_wait_secs", ttl + 2))
    user_max_size = config.test_ops.get("user_quota_max_size", "1G")
    verify_tls = bool(use_ssl) and bool(config.test_ops.get("verify_tls", False))
    if use_ssl and not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    log.info(f"ssl={use_ssl} haproxy={config.haproxy} verify_tls={verify_tls}")

    user_info = s3lib.create_users(config.user_count or 1)[0]
    log.info(f"user: {user_info['user_id']}")
    quota_mgmt.set_quota("user", user_info, max_size=user_max_size)
    quota_mgmt.toggle_quota("enable", "user", user_info)

    auth = reusable.get_auth(user_info, ssh_con, use_ssl, config.haproxy)
    rgw_conn = auth.do_auth()
    endpoint = auth.endpoint_url
    if not endpoint:
        scheme = "https" if use_ssl else "http"
        endpoint = (
            f"{scheme}://{ip_and_port.replace('https://', '').replace('http://', '')}"
        )
    log.info(f"RGW endpoint (ssl={use_ssl}): {endpoint}")

    bucket_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=0)
    if config.haproxy:
        bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info)
    else:
        bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info, ip_and_port)
    log.info(f"bucket: {bucket.name}")

    ttl_set = False
    try:
        if not config.mapped_sizes:
            config.mapped_sizes = utils.make_mapped_sizes(config)
        mapped = list(config.mapped_sizes.items())
        if len(mapped) < 3:
            raise TestExecError(
                f"objects_count must be >= 3 (control + 2 trigger PUTs), got {len(mapped)}"
            )

        log.info("control PUT before realm reload (must succeed on all builds)")
        oc0, size0 = mapped[0]
        config.obj_size = size0
        control_key = utils.gen_s3_object_name(bucket.name, oc0)
        try:
            reusable.upload_object(
                control_key, bucket, TEST_DATA_PATH, config, user_info
            )
        except Exception as e:
            raise TestExecError(f"control PUT failed: {e}")
        log.info(f"control PUT ok: {control_key} size={size0}")

        log.info(f"shorten rgw_bucket_quota_ttl to {ttl}s via asok")
        set_out = reusable.admin_daemon_config(
            "set", "rgw_bucket_quota_ttl", ttl, ssh_con=ssh_con
        )
        if set_out is False:
            raise TestExecError(f"asok config set rgw_bucket_quota_ttl={ttl} failed")
        got = reusable.admin_daemon_config(
            "get", "rgw_bucket_quota_ttl", ssh_con=ssh_con
        )
        log.info(f"asok config get rgw_bucket_quota_ttl: {got}")
        if got is False or str(ttl) not in str(got):
            raise TestExecError(
                f"asok config verify failed for rgw_bucket_quota_ttl={ttl}, got={got}"
            )
        ttl_set = True

        log.info("trigger realm reload via period update --commit")
        reusable.period_update_commit()

        log.info(f"wait {wait_secs}s for quota cache TTL expiry")
        time.sleep(wait_secs)

        log.info("PUT 1 after TTL (synchronous quota path; must succeed)")
        oc1, size1 = mapped[1]
        config.obj_size = size1
        trigger1_key = utils.gen_s3_object_name(bucket.name, oc1)
        try:
            reusable.upload_object(
                trigger1_key, bucket, TEST_DATA_PATH, config, user_info
            )
        except (ClientError, EndpointConnectionError, Exception) as e:
            raise TestExecError(f"PUT 1 after realm reload failed: {e}")
        log.info(f"PUT 1 ok: {trigger1_key} size={size1}")

        time.sleep(1)
        log.info("PUT 2 after TTL (async refresh path; must succeed on fixed build)")
        oc2, size2 = mapped[2]
        config.obj_size = size2
        trigger2_key = utils.gen_s3_object_name(bucket.name, oc2)
        try:
            reusable.upload_object(
                trigger2_key, bucket, TEST_DATA_PATH, config, user_info
            )
        except (ClientError, EndpointConnectionError, Exception) as e:
            raise TestExecError(
                f"PUT 2 after realm reload failed (possible SIGSEGV / dangling "
                f"DoutPrefix in RGWOwnerStatsCache::init_refresh): {e}"
            )
        log.info(f"PUT 2 ok: {trigger2_key} size={size2}")

        log.info("verify RGW daemon health")
        try:
            head = requests.head(endpoint, verify=verify_tls, timeout=10)
            log.info(
                f"endpoint HEAD ({'https' if use_ssl else 'http'}): "
                f"HTTP {head.status_code}"
            )
        except Exception as e:
            raise TestExecError(f"endpoint HEAD failed after PUTs: {e}")
        if not rgw_daemons_status(retry_attempts=3, retry_delay=5):
            raise TestExecError("RGW daemons not healthy after realm reload PUTs")

        crash_info = reusable.check_for_crash()
        if crash_info:
            raise TestExecError(
                f"ceph crash found after owner-stats-cache realm reload: {crash_info}"
            )
        log.info("no crash; both post-reload PUTs succeeded (fixed build)")

    finally:
        if ttl_set:
            try:
                log.info(f"restore rgw_bucket_quota_ttl to {DEFAULT_QUOTA_TTL}")
                reusable.admin_daemon_config(
                    "set",
                    "rgw_bucket_quota_ttl",
                    DEFAULT_QUOTA_TTL,
                    ssh_con=ssh_con,
                )
            except Exception as e:
                log.warning(f"failed to restore rgw_bucket_quota_ttl: {e}")
        if config.test_ops.get("delete_bucket_object", True) and "bucket" in locals():
            try:
                reusable.delete_objects(bucket)
                reusable.delete_bucket(bucket)
            except Exception as e:
                log.warning(f"bucket cleanup: {e}")
        if config.user_remove and "user_info" in locals():
            try:
                reusable.remove_user(user_info)
            except Exception as e:
                log.warning(f"user cleanup: {e}")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW OwnerStatsCache realm reload SIGSEGV regression")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW OwnerStatsCache realm reload regression"
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
