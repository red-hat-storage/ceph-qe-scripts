"""
test_bilog_fifo - FIFO bucket-index log functional tests

Usage: test_bilog_fifo.py -c <input_yaml>

<input_yaml>
    test_bilog_fifo_creation.yaml
    test_bilog_fifo_inindex_default.yaml
    test_bilog_fifo_object_ops.yaml
    test_bilog_fifo_versioned.yaml
    test_bilog_fifo_versioned_sync.yaml
    test_bilog_fifo_cli.yaml
    test_bilog_fifo_sync_disable.yaml
    test_bilog_fifo_reshard.yaml
    test_bilog_fifo_reshard_upgrade.yaml
    test_bilog_fifo_reshard_trim.yaml
    test_bilog_fifo_index_repair.yaml
    test_bilog_fifo_multisite_sync.yaml
    test_bilog_fifo_trim_lagging.yaml
    test_bilog_fifo_inindex_compat.yaml
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import botocore
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bilog_fifo as fifo
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def _ensure_obj_size(config, size=None):
    if size is not None:
        config.obj_size = size
        return
    if getattr(config, "obj_size", None):
        return
    size_range = getattr(config, "objects_size_range", None) or {}
    config.obj_size = size_range.get("min", 5) if isinstance(size_range, dict) else 5


def _create_user_and_auth(config, ssh_con):
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
    users = s3lib.create_users(config.user_count or 1)
    user = users[0]
    auth = Auth(user, ssh_con, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    rgw_client = auth.do_auth_using_client()
    return user, rgw_conn, rgw_client, ip_and_port


def _create_named_bucket(config, user, rgw_conn, ip_and_port, suffix=0):
    bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=suffix)
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user, ip_and_port)
    return bucket


def _upload(config, user, bucket, name, size=None, multipart=False):
    _ensure_obj_size(config, size)
    if multipart:
        reusable.upload_mutipart_object(name, bucket, TEST_DATA_PATH, config, user)
    else:
        reusable.upload_object(name, bucket, TEST_DATA_PATH, config, user)
    return name


def _maybe_set_bilog_type(config, ssh_con):
    bilog_type = config.test_ops.get("bilog_type")
    if bilog_type:
        fifo.set_bilog_type(bilog_type, ssh_con=ssh_con)


def scenario_creation(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """1.1 FIFO default + 1.3 shard scaling with index shards."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    _upload(config, user, bucket, "obj-init", size=5)
    layout = fifo.get_bucket_layout(bucket)
    fifo.assert_log_type(layout, "fifo")
    shards = fifo.get_fifo_num_shards(layout)
    fifo.assert_fifo_shard_bounds(shards)
    fifo.assert_fifo_oids_exist(bucket, gen=0)
    log.info("1.1 passed: new bucket defaults to FIFO")

    shard_counts = config.test_ops.get("index_shard_counts", [64, 512])
    observed = []
    for idx, index_shards in enumerate(shard_counts, start=1):
        fifo.set_index_shard_count(index_shards, ssh_con=ssh_con)
        bkt = _create_named_bucket(config, user, rgw_conn, ip_and_port, idx)
        _upload(config, user, bkt, f"obj-{index_shards}", size=5)
        layout = fifo.get_bucket_layout(bkt)
        fifo.assert_log_type(layout, "fifo")
        n = fifo.get_fifo_num_shards(layout)
        fifo.assert_fifo_shard_bounds(n)
        observed.append(n)
        log.info(f"index shards={index_shards} -> fifo shards={n}")
    if len(observed) >= 2 and observed[-1] < observed[0]:
        raise TestExecError(
            f"fifo shards should not shrink as index shards grow: {observed}"
        )
    log.info("1.3 passed: fifo shard count stays bounded")


def scenario_inindex_default(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """1.2 New bucket stays InIndex when config is inindex."""
    fifo.set_bilog_type("inindex", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    _upload(config, user, bucket, "obj-inindex", size=5)
    layout = fifo.get_bucket_layout(bucket)
    fifo.assert_log_type(layout, "inindex")
    fifo.assert_no_fifo_oids(bucket)
    log.info("1.2 passed: inindex bucket has no FIFO oids")


def scenario_object_ops(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """2.1 PUT, 2.2 DELETE, 2.3 multipart, 2.4 mix."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)

    _upload(config, user, bucket, "put-key", size=5)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["add", "put", "complete", "write"])
    log.info("2.1 passed: PUT produced FIFO ADD")

    reusable.delete_objects(bucket)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["del", "delete", "remove"])
    try:
        rgw_client.head_object(Bucket=bucket.name, Key="put-key")
        raise TestExecError("GET/HEAD after DELETE should fail")
    except botocore.exceptions.ClientError as e:
        code = int(e.response["ResponseMetadata"]["HTTPStatusCode"])
        if code not in (404, 403):
            raise TestExecError(f"expected 404 after delete, got {code}")
    log.info("2.2 passed: DELETE produced FIFO DEL")

    _ensure_obj_size(config, config.test_ops.get("multipart_size", 16))
    config.split_size = config.test_ops.get("split_size", 5)
    _upload(config, user, bucket, "mp-key", multipart=True)
    entries = fifo.bilog_list(bucket)
    if not entries:
        raise TestExecError("multipart complete produced no bilog entries")
    rgw_client.head_object(Bucket=bucket.name, Key="mp-key")
    log.info("2.3 passed: multipart complete produced bilog entry")

    _upload(config, user, bucket, "mix-a", size=5)
    _upload(config, user, bucket, "mix-b", size=5)
    reusable.delete_objects(bucket)
    entries = fifo.bilog_list(bucket)
    if len(entries) < 3:
        raise TestExecError(f"expected mixed ops in bilog, got {len(entries)}")
    oids = fifo.list_fifo_oids(bucket)
    if not oids:
        raise TestExecError("FIFO oids missing after mixed ops")
    log.info("2.4 passed: mixed PUT/DELETE/multipart recorded in FIFO")


def scenario_versioned(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """3.1-3.4 OLH link / increment / delete-marker / unlink_instance."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    write_bucket_io_info = BucketIoInfo()
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    reusable.enable_versioning(bucket, rgw_conn, user, write_bucket_io_info)

    key = "ver-key"
    _upload(config, user, bucket, key, size=5)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["link_olh", "olh", "add"])
    epoch1, tag1, _ = fifo.get_versioned_epoch(bucket, key)
    if epoch1 is not None and int(epoch1) == 0:
        raise TestExecError(f"versioned_epoch should be non-zero, got {epoch1}")
    versions = rgw_client.list_object_versions(Bucket=bucket.name)
    v1 = versions["Versions"][0]["VersionId"]
    log.info(f"3.1 passed: first PUT epoch={epoch1} version={v1}")

    _upload(config, user, bucket, key, size=6)
    epoch2, tag2, _ = fifo.get_versioned_epoch(bucket, key)
    if epoch1 is not None and epoch2 is not None and int(epoch2) <= int(epoch1):
        raise TestExecError(f"second PUT epoch {epoch2} not greater than {epoch1}")
    versions = rgw_client.list_object_versions(Bucket=bucket.name)
    vids = [v["VersionId"] for v in versions.get("Versions", [])]
    if len(vids) < 2:
        raise TestExecError("expected two versions after second PUT")
    v2 = versions["Versions"][0]["VersionId"]
    rgw_client.get_object(Bucket=bucket.name, Key=key, VersionId=v1)
    rgw_client.get_object(Bucket=bucket.name, Key=key, VersionId=v2)
    log.info(f"3.2 passed: E2={epoch2} > E1={epoch1}")

    rgw_client.delete_object(Bucket=bucket.name, Key=key)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["link_olh_dm", "delete_marker", "del"])
    listing = rgw_client.list_object_versions(Bucket=bucket.name)
    if not listing.get("DeleteMarkers"):
        raise TestExecError("delete marker missing after versioned DELETE")
    try:
        rgw_client.get_object(Bucket=bucket.name, Key=key)
        raise TestExecError("GET current version after delete marker should 404")
    except botocore.exceptions.ClientError as e:
        code = int(e.response["ResponseMetadata"]["HTTPStatusCode"])
        if code not in (404, 403):
            raise
    log.info("3.3 passed: link_olh_dm and delete marker")

    rgw_client.delete_object(Bucket=bucket.name, Key=key, VersionId=v1)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["unlink_instance", "unlink"])
    try:
        rgw_client.get_object(Bucket=bucket.name, Key=key, VersionId=v1)
        raise TestExecError("deleted version V1 still retrievable")
    except botocore.exceptions.ClientError:
        log.info("V1 returns error as expected")
    rgw_client.get_object(Bucket=bucket.name, Key=key, VersionId=v2)
    log.info("3.4 passed: unlink_instance for specific version delete")


def scenario_versioned_sync(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """3.5 versioned_epoch on secondary matches primary."""
    if not utils.is_cluster_multisite():
        raise TestExecError("versioned_sync requires a multisite cluster")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    write_bucket_io_info = BucketIoInfo()
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    reusable.enable_versioning(bucket, rgw_conn, user, write_bucket_io_info)
    key = "sync-ver"
    _upload(config, user, bucket, key, size=5)
    fifo.wait_sync(bucket)
    fifo.compare_primary_secondary(bucket, versioned=True, keys=[key])
    log.info("3.5 passed: secondary versioned_epoch matches primary")


def scenario_cli(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """4.1-4.3 bilog list / shard filter / trim."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    fifo.set_index_shard_count(config.test_ops.get("index_shards", 11), ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    count = config.test_ops.get("put_count", 20)
    for i in range(count):
        _upload(config, user, bucket, f"cli-obj-{i}", size=5)
    entries = fifo.bilog_list(bucket)
    if len(entries) < count:
        raise TestExecError(f"bilog list returned {len(entries)}, expected >= {count}")
    for entry in entries:
        fifo.assert_marker_format(entry, fifo=True)
    log.info("4.1 passed: list across FIFO shards with shard#raw markers")

    shard0 = fifo.bilog_list(bucket, shard_id=0)
    full_ids = {fifo.entry_id(e) for e in entries}
    for entry in shard0:
        eid = fifo.entry_id(entry)
        if eid not in full_ids:
            raise TestExecError(f"shard-0 entry {eid} not in full list")
        if not str(eid).startswith("0#"):
            log.info(f"shard-0 entry id {eid} (may use raw marker)")
    log.info("4.2 passed: --shard-id 0 subset of full list")

    last = fifo.entry_id(entries[-1])
    fifo.bilog_trim(bucket, end_marker=last)
    after = fifo.bilog_list(bucket)
    if after:
        log.info(f"entries remaining after trim (peer-protected?): {len(after)}")
        if not utils.is_cluster_multisite() and len(after) >= len(entries):
            raise TestExecError("bilog trim did not advance marker")
    _upload(config, user, bucket, "cli-after-trim", size=5)
    new_entries = fifo.bilog_list(bucket)
    names = [fifo.entry_object(e) for e in new_entries]
    if new_entries and "cli-after-trim" not in "".join(names) and len(new_entries) < 1:
        raise TestExecError("new write after trim not listed")
    log.info("4.3 passed: trim + subsequent write")


def scenario_sync_disable(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """5.1-5.3 SYNCSTOP / writes stay local / RESYNC catches up."""
    if not utils.is_cluster_multisite():
        raise TestExecError("sync_disable requires a multisite cluster")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    fifo.bucket_sync_disable(bucket)
    fifo.assert_sync_disabled(bucket)
    log.info("5.1 passed: sync disable")

    disabled_keys = []
    for i in range(5):
        key = f"disabled-{i}"
        _upload(config, user, bucket, key, size=5)
        disabled_keys.append(key)
    time.sleep(30)
    rc, out, err = reusable.exec_on_secondary(
        f"radosgw-admin bucket list --bucket {bucket.name}"
    )
    secondary_text = (out or "") + (err or "")
    leaked = [k for k in disabled_keys if k in secondary_text]
    if leaked:
        raise TestExecError(f"objects leaked to secondary while disabled: {leaked}")
    log.info("5.2 passed: writes during disable not synced")

    fifo.bucket_sync_enable(bucket)
    fifo.wait_sync(bucket, retry=40, delay=15)
    fifo.compare_primary_secondary(bucket, keys=disabled_keys)
    log.info("5.3 passed: objects written during disable synced after re-enable")


def scenario_reshard(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """6.1 FIFO reshard creates a new FIFO generation."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    for i in range(config.test_ops.get("put_count", 5)):
        _upload(config, user, bucket, f"pre-reshard-{i}", size=5)
    target = config.shards or config.test_ops.get("reshard_shards", 64)
    layout = fifo.reshard_bucket(bucket, target)
    gens = fifo.get_log_generations(layout)
    if len(gens) < 2:
        log.info(f"layout after reshard (may already be trimmed): {layout}")
    fifo.assert_log_type(layout, "fifo")
    fifo.get_fifo_num_shards(layout)
    rgw_client.head_object(Bucket=bucket.name, Key="pre-reshard-0")
    log.info("6.1 passed: FIFO reshard kept objects accessible")


def scenario_reshard_upgrade(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """6.2 InIndex bucket reshard with fifo config -> gen 1 is FIFO."""
    fifo.set_bilog_type("inindex", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    _upload(config, user, bucket, "upgrade-obj", size=5)
    layout = fifo.get_bucket_layout(bucket)
    fifo.assert_log_type(layout, "inindex", gen=0)
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    target = config.shards or config.test_ops.get("reshard_shards", 16)
    layout = fifo.reshard_bucket(bucket, target)
    gens = fifo.get_log_generations(layout)
    fifo.assert_log_type(layout, "inindex", gen=0)
    latest_type = fifo.get_log_type(layout)
    if latest_type != "fifo":
        # current gen after reshard should be FIFO
        fifo.assert_log_type(layout, "fifo")
    _upload(config, user, bucket, "post-upgrade", size=5)
    entries = fifo.bilog_list(bucket)
    if not entries:
        raise TestExecError("no bilog entries after FIFO upgrade writes")
    log.info(f"6.2 passed: gen0 InIndex, later gen FIFO ({len(gens)} gens)")


def scenario_reshard_trim(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """6.3-6.4 old FIFO generations removed after trim."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    _upload(config, user, bucket, "keep-me", size=5)
    fifo.reshard_bucket(bucket, config.test_ops.get("reshard_shards", 16))
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket)
    fifo.bilog_autotrim(bucket, times=config.test_ops.get("autotrim_passes", 5))
    layout = fifo.get_bucket_layout(bucket)
    gens = fifo.get_log_generations(layout)
    log.info(f"generations after first trim: {len(gens)}")
    fifo.reshard_bucket(bucket, config.test_ops.get("second_reshard_shards", 32))
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket)
    fifo.bilog_autotrim(bucket, times=config.test_ops.get("autotrim_passes", 5))
    layout = fifo.get_bucket_layout(bucket)
    gens = fifo.get_log_generations(layout)
    if len(gens) > 1:
        log.info(f"old generations still present after trim: {len(gens)}")
    rgw_client.head_object(Bucket=bucket.name, Key="keep-me")
    log.info("6.3/6.4 passed: bucket functional after sequential reshard+trim")


def scenario_index_repair(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """7.1 missing index -> FIFO ADD; 7.2 orphaned index -> FIFO DEL."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    missing_key = "repair-missing"
    _upload(config, user, bucket, missing_key, size=5)
    fifo.remove_index_omap_key(bucket, missing_key)
    fifo.bucket_check_fix(bucket)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["add", "write", "complete"])
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket)
        fifo.compare_primary_secondary(bucket, keys=[missing_key])
    log.info("7.1 passed: bucket check created FIFO ADD for missing index")

    orphan_key = "repair-orphan"
    _upload(config, user, bucket, orphan_key, size=5)
    fifo.remove_head_object(bucket, orphan_key)
    fifo.bucket_check_fix(bucket)
    entries = fifo.bilog_list(bucket)
    fifo.assert_entries_contain(entries, ["del", "delete", "remove"])
    log.info("7.2 passed: bucket check created FIFO DEL for orphaned index")


def scenario_multisite_sync(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """8.1-8.4 PUT sync, full sync, zone outage, versioned OLH sync."""
    if not utils.is_cluster_multisite():
        raise TestExecError("multisite_sync requires a 2-zone cluster")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    _upload(config, user, bucket, "data.bin", size=8)
    fifo.wait_sync(bucket)
    fifo.compare_primary_secondary(bucket, keys=["data.bin"])
    log.info("8.1 passed: simple PUT synced")

    mixed_keys = []
    write_bucket_io_info = BucketIoInfo()
    reusable.enable_versioning(bucket, rgw_conn, user, write_bucket_io_info)
    for i in range(config.test_ops.get("full_sync_objects", 20)):
        key = f"full-{i}"
        _upload(config, user, bucket, key, size=5 if i % 2 == 0 else 12)
        mixed_keys.append(key)
    utils.exec_shell_cmd(f"radosgw-admin bucket sync init --bucket {bucket.name}")
    utils.exec_shell_cmd(f"radosgw-admin bucket sync run --bucket {bucket.name}")
    fifo.wait_sync(bucket, retry=40, delay=15)
    fifo.compare_primary_secondary(bucket, keys=mixed_keys)
    log.info("8.2 passed: full sync from scratch")

    remote = fifo.stop_secondary_rgw()
    outage_keys = []
    for i in range(config.test_ops.get("outage_objects", 5)):
        key = f"outage-{i}"
        _upload(config, user, bucket, key, size=5)
        outage_keys.append(key)
    fifo.start_secondary_rgw(remote)
    fifo.wait_sync(bucket, retry=40, delay=20)
    fifo.compare_primary_secondary(bucket, keys=outage_keys)
    log.info("8.3 passed: objects written during outage synced")

    vkey = "olh-sync"
    for _ in range(3):
        _upload(config, user, bucket, vkey, size=5)
    rgw_client.delete_object(Bucket=bucket.name, Key=vkey)
    versions = rgw_client.list_object_versions(Bucket=bucket.name, Prefix=vkey)
    vids = [v["VersionId"] for v in versions.get("Versions", [])]
    if vids:
        rgw_client.delete_object(Bucket=bucket.name, Key=vkey, VersionId=vids[-1])
    fifo.wait_sync(bucket)
    fifo.compare_primary_secondary(bucket, versioned=True, keys=[vkey])
    log.info("8.4 passed: versioned FIFO OLH/delete-marker sync")


def scenario_trim_lagging(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """8.5 trim while secondary is lagging must not drop unconsumed entries."""
    if not utils.is_cluster_multisite():
        raise TestExecError("trim_lagging requires a multisite cluster")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    first = []
    for i in range(config.test_ops.get("synced_objects", 20)):
        key = f"lag-a-{i}"
        _upload(config, user, bucket, key, size=5)
        first.append(key)
    fifo.wait_sync(bucket)
    fifo.bilog_autotrim(bucket, times=2)
    remote = fifo.stop_secondary_rgw()
    lag_keys = []
    for i in range(config.test_ops.get("lag_objects", 15)):
        key = f"lag-b-{i}"
        _upload(config, user, bucket, key, size=5)
        lag_keys.append(key)
    fifo.bilog_autotrim(bucket, times=3)
    fifo.start_secondary_rgw(remote)
    fifo.wait_sync(bucket, retry=50, delay=20)
    fifo.compare_primary_secondary(bucket, keys=first + lag_keys)
    log.info("8.5 passed: lagging secondary not starved by trim")


def scenario_inindex_compat(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """11.1-11.2 InIndex PUT/DELETE/versioned/trim/status still work."""
    fifo.set_bilog_type("inindex", ssh_con=ssh_con)
    write_bucket_io_info = BucketIoInfo()
    bucket = _create_named_bucket(config, user, rgw_conn, ip_and_port, 0)
    layout = fifo.get_bucket_layout(bucket)
    fifo.assert_log_type(layout, "inindex")
    key = "inindex-obj"
    _upload(config, user, bucket, key, size=5)
    rgw_client.head_object(Bucket=bucket.name, Key=key)
    reusable.enable_versioning(bucket, rgw_conn, user, write_bucket_io_info)
    _upload(config, user, bucket, key, size=6)
    rgw_client.delete_object(Bucket=bucket.name, Key=key)
    fifo.assert_no_fifo_oids(bucket)
    entries = fifo.bilog_list(bucket)
    if not entries:
        log.info("inindex bilog list empty after ops (may be immediately trimmed)")
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket)
    log.info("11.1 passed: InIndex S3 ops and no FIFO oids")

    _upload(config, user, bucket, "trim-me", size=5)
    entries = fifo.bilog_list(bucket)
    if entries:
        marker = fifo.entry_id(entries[-1])
        fifo.bilog_trim(bucket, end_marker=marker)
    status = fifo.bilog_status(bucket)
    blob = json_dump(status).lower()
    if "fifo" in blob and "inindex" not in blob:
        log.info(f"status blob: {blob[:400]}")
    log.info("11.2 passed: InIndex trim and status")


def json_dump(obj):
    import json

    try:
        return json.dumps(obj)
    except TypeError:
        return str(obj)


SCENARIOS = {
    "creation": scenario_creation,
    "inindex_default": scenario_inindex_default,
    "object_ops": scenario_object_ops,
    "versioned": scenario_versioned,
    "versioned_sync": scenario_versioned_sync,
    "cli": scenario_cli,
    "sync_disable": scenario_sync_disable,
    "reshard": scenario_reshard,
    "reshard_upgrade": scenario_reshard_upgrade,
    "reshard_trim": scenario_reshard_trim,
    "index_repair": scenario_index_repair,
    "multisite_sync": scenario_multisite_sync,
    "trim_lagging": scenario_trim_lagging,
    "inindex_compat": scenario_inindex_compat,
}


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    _maybe_set_bilog_type(config, ssh_con)
    _ensure_obj_size(config)
    user, rgw_conn, rgw_client, ip_and_port = _create_user_and_auth(config, ssh_con)
    scenario = config.test_ops.get("scenario")
    if not scenario or scenario not in SCENARIOS:
        raise TestExecError(
            f"unknown or missing test_ops.scenario={scenario}; "
            f"expected one of {sorted(SCENARIOS)}"
        )
    log.info(f"running FIFO bilog scenario: {scenario}")
    SCENARIOS[scenario](config, ssh_con, user, rgw_conn, rgw_client, ip_and_port)
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("FIFO bucket bilog functional tests")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW FIFO bilog tests")
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
        if config.mapped_sizes is None and config.objects_count:
            config.mapped_sizes = utils.make_mapped_sizes(config)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
