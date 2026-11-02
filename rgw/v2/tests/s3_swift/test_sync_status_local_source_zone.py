"""
Regression for radosgw-admin sync status with local / invalid source zone.
Tracker: https://tracker.ceph.com/issues/81613
Fix PR:  https://github.com/ceph/ceph/pull/72569

Usage: test_sync_status_local_source_zone.py -c <input_yaml>

<input_yaml>
    multisite_configs/test_sync_status_local_source_zone.yaml

Non-MS: skip remaining scenarios and pass. Read-only status commands only;
does not modify realm/zonegroup/zone or sync state.
"""

import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import argparse
import logging
import traceback

import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()

ERR_META_SOURCE_ZONE = "metadata sync does not support --source-zone"
ERR_META_MASTER = "zone is the metadata master"
ERR_MDLOG_HINT = "mdlog status"
ERR_DATA_LOCAL = "source zone is the local zone"
ERR_DATA_MISSING = "source zone not specified"

META_SOURCE_ZONE_KEYWORDS = ("source-zone", "not supported", ERR_META_SOURCE_ZONE)
DATA_LOCAL_CLEAR_KEYWORDS = (
    "local zone",
    "same zone",
    "remote",
    "source zone",
    "not supported",
    "cannot sync",
    "invalid source",
    ERR_DATA_LOCAL,
)
DATA_LOCAL_BUG_KEYWORDS = ("sync.init", "ret=-einval", "ret=-22", "rest connection")


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:
        _, realm_name = reusable.get_multisite_info()
    except Exception as e:
        log.info(
            f"not a multisite cluster (get_multisite_info failed: {e}); skipping remaining scenarios; testcase pass"
        )
        return
    if not realm_name:
        log.info(
            "not a multisite cluster (no realm); skipping remaining scenarios; testcase pass"
        )
        return
    log.info(
        f"multisite cluster detected, realm: {realm_name}; running sync-status local-source-zone scenarios"
    )

    ops = config.test_ops or {}
    scope_parts = []
    for flag, key, env in (
        ("--rgw-zone", "rgw_zone", "RGW_ZONE"),
        ("--rgw-zonegroup", "rgw_zonegroup", "RGW_ZONEGROUP"),
        ("--rgw-realm", "rgw_realm", "RGW_REALM"),
    ):
        val = ops.get(key) or os.environ.get(env, "")
        if val:
            scope_parts.append(f"{flag} {val}")
    scope_flags = " ".join(scope_parts)
    if scope_flags:
        log.info(f"rgw scope flags: {scope_flags}")

    rc, raw = reusable.run_rgw_admin("zone get --format json", scope_flags)
    if rc != 0:
        raise TestExecError(f"step 1 zone get failed (rc={rc}): {raw}")
    try:
        zone = json.loads(raw)
    except json.JSONDecodeError as e:
        raise TestExecError(f"step 1 zone get JSON parse failed: {e}; raw={raw}")
    zone_name = zone.get("name")
    zone_id = zone.get("id")
    if not zone_name or not zone_id:
        raise TestExecError(f"step 1 zone get missing name/id: {zone}")
    zg = json.loads(
        utils.exec_shell_cmd(
            f"radosgw-admin zonegroup get --format json {scope_flags}".strip()
        )
    )
    is_meta_master = zone_id == zg.get("master_zone")
    log.info(
        f"step 1: local zone name={zone_name} id={zone_id} meta_master={is_meta_master}"
    )

    if is_meta_master:
        reusable.expect_rgw_admin_einval(
            "step 2 metadata sync status on meta master",
            "metadata sync status",
            [ERR_META_MASTER, ERR_MDLOG_HINT],
            scope_flags=scope_flags,
            require_all=True,
        )
    else:
        log.info("step 2: secondary zone — metadata sync status should succeed")
        reusable.expect_rgw_admin_success(
            "step 2 metadata sync status on secondary",
            "metadata sync status",
            scope_flags=scope_flags,
        )

    reusable.expect_rgw_admin_einval(
        f"step 3 metadata sync status --source-zone={zone_name}",
        f"metadata sync status --source-zone {zone_name}",
        META_SOURCE_ZONE_KEYWORDS,
        scope_flags=scope_flags,
    )

    reusable.expect_rgw_admin_einval(
        f"step 4 data sync status --source-zone={zone_name}",
        f"data sync status --source-zone {zone_name}",
        DATA_LOCAL_CLEAR_KEYWORDS,
        scope_flags=scope_flags,
        bug_keywords=DATA_LOCAL_BUG_KEYWORDS,
    )

    reusable.expect_rgw_admin_success(
        "step 5a sync status", "sync status", scope_flags=scope_flags
    )
    if is_meta_master:
        reusable.expect_rgw_admin_success(
            "step 5b mdlog status on meta master",
            "mdlog status",
            scope_flags=scope_flags,
        )
    else:
        log.info("step 5b: skip mdlog-status requirement on secondary")

    log.info("step 6: extra status-only --source-zone-id / missing-source checks")
    reusable.expect_rgw_admin_einval(
        "step 6 metadata sync status --source-zone-id",
        f"metadata sync status --source-zone-id {zone_id}",
        META_SOURCE_ZONE_KEYWORDS,
        scope_flags=scope_flags,
    )
    reusable.expect_rgw_admin_einval(
        "step 6 data sync status missing source",
        "data sync status",
        ERR_DATA_MISSING,
        scope_flags=scope_flags,
    )
    reusable.expect_rgw_admin_einval(
        "step 6 data sync status --source-zone-id local",
        f"data sync status --source-zone-id {zone_id}",
        DATA_LOCAL_CLEAR_KEYWORDS,
        scope_flags=scope_flags,
        bug_keywords=DATA_LOCAL_BUG_KEYWORDS,
    )

    log.info(
        f"all sync-status local-source-zone checks passed (zone={zone_name}, meta_master={is_meta_master})"
    )


if __name__ == "__main__":
    test_info = AddTestInfo(
        "RGW radosgw-admin sync status local source zone (EINVAL) regression"
    )
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_path = os.path.join(project_dir, "test_data")
        log.info(f"TEST_DATA_PATH: {test_data_path}")
        if not os.path.exists(test_data_path):
            os.makedirs(test_data_path)
        parser = argparse.ArgumentParser(
            description="RGW sync status local source zone regression"
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
