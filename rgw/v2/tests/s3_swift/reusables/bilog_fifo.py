"""Reusable helpers for FIFO bucket-index log (bilog) tests."""

import json
import logging
import re
import time

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.tests.s3_swift import reusable
from v2.utils.utils import RGWService

log = logging.getLogger()

FIFO_TYPE = "fifo"
ININDEX_TYPE = "inindex"
MARKER_RE = re.compile(r"^\d+#")
BILOG_OID_RE = re.compile(r"\.bilog$")
MIN_FIFO_SHARDS = 7
MAX_FIFO_SHARDS = 21


def _bucket_name(bucket):
    return bucket if isinstance(bucket, str) else bucket.name


def run_json(cmd, allow_empty=True):
    """Run a shell command and parse JSON stdout."""
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"command failed: {cmd}")
    if out is None or str(out).strip() == "":
        if allow_empty:
            return []
        raise TestExecError(f"empty JSON output for: {cmd}")
    text = str(out).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        log.info(f"non-json output for {cmd}: {text[:500]}")
        if allow_empty:
            return []
        raise


def set_bilog_type(bilog_type, ssh_con=None, restart=True):
    """Set rgw_default_bucket_bilog_type and optionally restart RGW."""
    bilog_type = str(bilog_type).lower()
    if bilog_type not in (FIFO_TYPE, ININDEX_TYPE):
        raise TestExecError(f"unsupported bilog type: {bilog_type}")
    log.info(f"setting rgw_default_bucket_bilog_type={bilog_type}")
    ceph_conf = CephConfOp(ssh_con)
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_default_bucket_bilog_type,
        bilog_type,
        ssh_con,
    )
    if restart:
        rgw_service = RGWService()
        if not rgw_service.restart(ssh_con):
            raise TestExecError("RGW service restart failed after bilog type change")
        time.sleep(20)
    return bilog_type


def set_index_shard_count(num_shards, ssh_con=None, restart=True):
    """Set rgw_override_bucket_index_max_shards so new buckets use num_shards."""
    log.info(f"setting rgw_override_bucket_index_max_shards={num_shards}")
    ceph_conf = CephConfOp(ssh_con)
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_override_bucket_index_max_shards,
        str(num_shards),
        ssh_con,
    )
    if restart:
        rgw_service = RGWService()
        if not rgw_service.restart(ssh_con):
            raise TestExecError("RGW restart failed after index shard override")
        time.sleep(15)


def get_bucket_stats(bucket):
    name = _bucket_name(bucket)
    stats = run_json(f"radosgw-admin bucket stats --bucket {name}", allow_empty=False)
    if isinstance(stats, list):
        stats = stats[0]
    return stats


def get_bucket_id(bucket):
    stats = get_bucket_stats(bucket)
    bucket_id = stats.get("id") or stats.get("bucket_id")
    if not bucket_id:
        raise TestExecError(f"could not resolve bucket id for {_bucket_name(bucket)}")
    return bucket_id


def get_bucket_layout(bucket):
    name = _bucket_name(bucket)
    return run_json(f"radosgw-admin bucket layout --bucket {name}", allow_empty=False)


def _layout_root(layout_doc):
    if isinstance(layout_doc, dict) and "layout" in layout_doc:
        return layout_doc["layout"]
    return layout_doc


def get_log_generations(layout_doc):
    root = _layout_root(layout_doc)
    logs = root.get("logs") if isinstance(root, dict) else None
    if not logs:
        raise TestExecError(f"bucket layout has no logs: {layout_doc}")
    return logs


def get_log_gen(layout_doc, gen=None):
    logs = get_log_generations(layout_doc)
    if gen is None:
        return logs[-1]
    for entry in logs:
        if int(entry.get("gen", -1)) == int(gen):
            return entry
    raise TestExecError(f"no log generation {gen} in layout")


def get_log_type(layout_doc, gen=None):
    entry = get_log_gen(layout_doc, gen=gen)
    inner = entry.get("layout", entry)
    log_type = inner.get("type") or inner.get("log_type")
    if not log_type:
        raise TestExecError(f"log type missing in {entry}")
    return str(log_type).lower()


def get_fifo_num_shards(layout_doc, gen=None):
    entry = get_log_gen(layout_doc, gen=gen)
    inner = entry.get("layout", entry)
    fifo = inner.get("fifo") or inner
    num_shards = fifo.get("num_shards")
    if num_shards is None:
        raise TestExecError(f"fifo.num_shards missing in {entry}")
    return int(num_shards)


def assert_log_type(layout_doc, expected, gen=None):
    actual = get_log_type(layout_doc, gen=gen)
    expected = str(expected).lower()
    if actual != expected:
        raise TestExecError(f"expected log type {expected} (gen={gen}), got {actual}")
    log.info(f"log type is {actual} for gen={gen}")
    return actual


def assert_fifo_shard_bounds(
    num_shards, min_shards=MIN_FIFO_SHARDS, max_shards=MAX_FIFO_SHARDS
):
    num_shards = int(num_shards)
    if num_shards < min_shards:
        raise TestExecError(f"fifo shards {num_shards} < min {min_shards}")
    if num_shards > max_shards:
        raise TestExecError(f"fifo shards {num_shards} > max {max_shards}")
    log.info(f"fifo shard count {num_shards} within [{min_shards}, {max_shards}]")
    return num_shards


def get_log_pool():
    """Return the zone log pool name, defaulting to .rgw.log."""
    zone = run_json("radosgw-admin zone get", allow_empty=True)
    if isinstance(zone, dict):
        pool = zone.get("log_pool")
        if isinstance(pool, dict):
            pool = pool.get("name") or pool.get("pool")
        if pool:
            return str(pool)
        pools = zone.get("pools") or {}
        if isinstance(pools, dict) and pools.get("log_pool"):
            return str(pools["log_pool"])
    return ".rgw.log"


def get_index_pool():
    zone = run_json("radosgw-admin zone get", allow_empty=True)
    if isinstance(zone, dict):
        for placement in zone.get("placement_pools", []):
            val = placement.get("val", placement)
            index_pool = val.get("index_pool")
            if index_pool:
                return str(index_pool)
    return "default.rgw.buckets.index"


def get_data_pool():
    zone = run_json("radosgw-admin zone get", allow_empty=True)
    if isinstance(zone, dict):
        for placement in zone.get("placement_pools", []):
            val = placement.get("val", placement)
            storage = val.get("storage_classes", {})
            standard = storage.get("STANDARD") or {}
            data_pool = standard.get("data_pool") or val.get("data_pool")
            if data_pool:
                return str(data_pool)
    return "default.rgw.buckets.data"


def list_pool_objects(pool):
    out = utils.exec_shell_cmd(f"rados -p {pool} ls")
    if out is False or out is None:
        return []
    return [line.strip() for line in str(out).splitlines() if line.strip()]


def list_fifo_oids(bucket, gen=None):
    """List FIFO head/part objects for a bucket in the log pool."""
    bucket_id = get_bucket_id(bucket)
    pool = get_log_pool()
    oids = list_pool_objects(pool)
    matched = []
    gen_part = f"{bucket_id}." if gen is None else f"{bucket_id}.{gen}."
    for oid in oids:
        if gen_part in oid and BILOG_OID_RE.search(oid):
            matched.append(oid)
    log.info(f"FIFO oids for {bucket_id} gen={gen}: {matched}")
    return matched


def assert_fifo_oids_exist(bucket, gen=None):
    oids = list_fifo_oids(bucket, gen=gen)
    if not oids:
        raise TestExecError(
            f"no FIFO .bilog objects in log pool for {_bucket_name(bucket)} gen={gen}"
        )
    return oids


def assert_no_fifo_oids(bucket, gen=None):
    oids = list_fifo_oids(bucket, gen=gen)
    if oids:
        raise TestExecError(
            f"unexpected FIFO objects for {_bucket_name(bucket)} gen={gen}: {oids}"
        )


def bilog_list(bucket, shard_id=None):
    name = _bucket_name(bucket)
    cmd = f"radosgw-admin bilog list --bucket {name}"
    if shard_id is not None:
        cmd += f" --shard-id {shard_id}"
    entries = run_json(cmd, allow_empty=True)
    if isinstance(entries, dict):
        entries = entries.get("entries") or entries.get("bilog") or [entries]
    if entries is None:
        entries = []
    return entries


def bilog_trim(bucket, end_marker=None, start_marker=None):
    name = _bucket_name(bucket)
    cmd = f"radosgw-admin bilog trim --bucket {name}"
    if start_marker:
        cmd += f" --start-marker {start_marker}"
    if end_marker:
        cmd += f" --end-marker {end_marker}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"bilog trim failed: {cmd}")
    return out


def bilog_status(bucket):
    name = _bucket_name(bucket)
    for cmd in (
        f"radosgw-admin bilog status --bucket {name}",
        f"radosgw-admin bucket sync status --bucket {name}",
    ):
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            continue
        try:
            return json.loads(str(out).strip())
        except (json.JSONDecodeError, TypeError):
            return {"raw": str(out)}
    raise TestExecError(f"could not get bilog/sync status for {name}")


def bilog_autotrim(bucket=None, times=3, delay=5):
    """Run bilog trim repeatedly so old generations can be cleaned up."""
    for i in range(times):
        log.info(f"bilog autotrim pass {i + 1}/{times}")
        if bucket is not None:
            entries = bilog_list(bucket)
            if entries:
                marker = entry_id(entries[-1])
                if marker:
                    try:
                        bilog_trim(bucket, end_marker=marker)
                    except TestExecError as e:
                        log.info(
                            f"trim with end-marker failed (may be peer-protected): {e}"
                        )
            try:
                utils.exec_shell_cmd(
                    f"radosgw-admin bilog trim --bucket {_bucket_name(bucket)}"
                )
            except Exception as e:
                log.info(f"unbounded bilog trim: {e}")
        else:
            utils.exec_shell_cmd("radosgw-admin sync trim")
        time.sleep(delay)


def entry_id(entry):
    if not isinstance(entry, dict):
        return str(entry)
    return (
        entry.get("id")
        or entry.get("marker")
        or entry.get("op_id")
        or entry.get("timestamp")
    )


def entry_op(entry):
    if not isinstance(entry, dict):
        return str(entry).lower()
    op = (
        entry.get("op")
        or entry.get("op_type")
        or entry.get("name")
        or entry.get("type")
        or ""
    )
    return str(op).lower()


def entry_object(entry):
    if not isinstance(entry, dict):
        return ""
    return str(
        entry.get("object")
        or entry.get("key")
        or entry.get("name")
        or entry.get("entry", {}).get("object")
        or ""
    )


def assert_marker_format(entry, fifo=True):
    eid = entry_id(entry)
    if eid is None:
        raise TestExecError(f"bilog entry missing id: {entry}")
    eid = str(eid)
    if fifo and not MARKER_RE.match(eid):
        raise TestExecError(f"FIFO marker expected shard#raw, got {eid}")
    return eid


def parse_bilog_ops(entries):
    ops = [entry_op(e) for e in entries]
    log.info(f"bilog ops: {ops}")
    return ops


def find_entries_by_op(entries, substrings):
    if isinstance(substrings, str):
        substrings = [substrings]
    needles = [s.lower() for s in substrings]
    found = []
    for entry in entries:
        op = entry_op(entry)
        blob = json.dumps(entry).lower()
        if any(n in op or n in blob for n in needles):
            found.append(entry)
    return found


def assert_entries_contain(entries, substrings, msg=None):
    found = find_entries_by_op(entries, substrings)
    if not found:
        raise TestExecError(msg or f"no bilog entries matching {substrings}: {entries}")
    return found


def bucket_list_admin(bucket, versions=False):
    name = _bucket_name(bucket)
    cmd = f"radosgw-admin bucket list --bucket {name}"
    entries = run_json(cmd, allow_empty=True)
    if versions:
        return entries
    return entries


def get_versioned_epoch(bucket, key, instance=None):
    entries = bucket_list_admin(bucket)
    for entry in entries:
        name = entry.get("name") or entry.get("key")
        if name != key:
            continue
        inst = entry.get("instance") or entry.get("versioned_epoch")
        if instance is not None and str(entry.get("instance", "")) not in (
            "",
            "null",
            str(instance),
        ):
            if str(entry.get("instance")) != str(instance):
                continue
        epoch = entry.get("versioned_epoch")
        if epoch is None and isinstance(entry.get("meta"), dict):
            epoch = entry["meta"].get("versioned_epoch")
        tag = entry.get("tag") or (entry.get("meta") or {}).get("tag")
        return epoch, tag, entry
    raise TestExecError(f"object {key} not in bucket list of {_bucket_name(bucket)}")


def wait_sync(bucket=None, retry=30, delay=20):
    reusable.check_sync_status(retry=retry, delay=delay)
    if bucket is not None:
        name = _bucket_name(bucket)
        status = utils.exec_shell_cmd(
            f"radosgw-admin bucket sync status --bucket {name}"
        )
        log.info(f"bucket sync status: {status}")


def compare_primary_secondary(bucket, versioned=False, keys=None):
    """Compare object listings (and optional keys/etags) on primary vs secondary."""
    if not utils.is_cluster_multisite():
        log.info("not multisite; skip primary/secondary compare")
        return
    name = _bucket_name(bucket)
    wait_sync(name)
    primary = bucket_list_admin(name)
    rc, out, err = reusable.exec_on_secondary(
        f"radosgw-admin bucket list --bucket {name}"
    )
    if rc != 0:
        raise TestExecError(f"secondary bucket list failed: {err}")
    try:
        secondary = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        raise TestExecError(f"secondary bucket list not json: {out}")
    p_names = sorted(
        [
            e.get("name") or e.get("key")
            for e in primary
            if (e.get("name") or e.get("key"))
        ]
    )
    s_names = sorted(
        [
            e.get("name") or e.get("key")
            for e in secondary
            if (e.get("name") or e.get("key"))
        ]
    )
    if keys is not None:
        for key in keys:
            if key not in p_names:
                raise TestExecError(f"key {key} missing on primary listing")
            if key not in s_names:
                raise TestExecError(f"key {key} missing on secondary listing")
    elif p_names != s_names:
        raise TestExecError(
            f"primary/secondary listing mismatch: {p_names} vs {s_names}"
        )
    if versioned:
        for key in keys or p_names:
            try:
                p_epoch, p_tag, _ = get_versioned_epoch(name, key)
            except TestExecError:
                continue
            s_match = None
            for entry in secondary:
                if (entry.get("name") or entry.get("key")) == key:
                    s_match = entry
                    break
            if s_match is None:
                raise TestExecError(f"versioned key {key} missing on secondary")
            s_epoch = s_match.get("versioned_epoch")
            if s_epoch is None and isinstance(s_match.get("meta"), dict):
                s_epoch = s_match["meta"].get("versioned_epoch")
            s_tag = s_match.get("tag") or (s_match.get("meta") or {}).get("tag")
            if (
                p_epoch is not None
                and s_epoch is not None
                and int(p_epoch) != int(s_epoch)
            ):
                raise TestExecError(
                    f"versioned_epoch mismatch for {key}: {p_epoch} vs {s_epoch}"
                )
            if p_tag and s_tag and p_tag != s_tag:
                raise TestExecError(f"OLH tag mismatch for {key}: {p_tag} vs {s_tag}")
    log.info(f"primary and secondary listings match for {name}")
    return primary, secondary


def bucket_sync_disable(bucket):
    name = _bucket_name(bucket)
    out = utils.exec_shell_cmd(f"radosgw-admin bucket sync disable --bucket {name}")
    if out is False:
        raise TestExecError(f"bucket sync disable failed for {name}")
    return out


def bucket_sync_enable(bucket):
    name = _bucket_name(bucket)
    out = utils.exec_shell_cmd(f"radosgw-admin bucket sync enable --bucket {name}")
    if out is False:
        raise TestExecError(f"bucket sync enable failed for {name}")
    return out


def bucket_sync_status_text(bucket):
    name = _bucket_name(bucket)
    out = utils.exec_shell_cmd(f"radosgw-admin bucket sync status --bucket {name}")
    if out is False:
        raise TestExecError(f"bucket sync status failed for {name}")
    return str(out)


def assert_sync_disabled(bucket):
    status = bucket_sync_status_text(bucket).lower()
    if (
        "disabled" not in status
        and "stopped" not in status
        and "datasync" not in status
    ):
        log.info(f"sync status text: {status}")
    flags = ("disabled", "stopped", "not syncing", "datasync")
    if not any(f in status for f in flags):
        raise TestExecError(f"expected disabled/stopped sync status, got: {status}")
    log.info("bucket sync is disabled/stopped")


def reshard_bucket(bucket, num_shards):
    name = _bucket_name(bucket)
    cmd = (
        f"radosgw-admin bucket reshard --bucket {name} "
        f"--num-shards {num_shards} --yes-i-really-mean-it"
    )
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"reshard failed for {name} to {num_shards}")
    stats = get_bucket_stats(name)
    actual = int(stats.get("num_shards", -1))
    if actual != int(num_shards):
        raise TestExecError(f"reshard did not reach {num_shards} shards, have {actual}")
    return get_bucket_layout(name)


def get_index_oids(bucket):
    bucket_id = get_bucket_id(bucket)
    pool = get_index_pool()
    oids = list_pool_objects(pool)
    return [oid for oid in oids if bucket_id in oid]


def list_index_omap_keys(index_oid, pool=None):
    pool = pool or get_index_pool()
    out = utils.exec_shell_cmd(f"rados -p {pool} listomapkeys {index_oid}")
    if out is False or out is None:
        return []
    return [line.strip() for line in str(out).splitlines() if line.strip()]


def remove_index_omap_key(bucket, object_key):
    """Remove the bucket-index omap key for object_key (object remains on disk)."""
    pool = get_index_pool()
    index_oids = get_index_oids(bucket)
    if not index_oids:
        raise TestExecError(f"no index objects for {_bucket_name(bucket)}")
    removed = False
    for oid in index_oids:
        keys = list_index_omap_keys(oid, pool=pool)
        matches = [k for k in keys if object_key in k or k == object_key]
        for key in matches or keys:
            if object_key not in key:
                continue
            log.info(f"removing omap key {key} from {oid}")
            out = utils.exec_shell_cmd(f"rados -p {pool} rmomapkey {oid} {key}")
            if out is False:
                raise TestExecError(f"rmomapkey failed for {oid} {key}")
            removed = True
    if not removed:
        raise TestExecError(
            f"could not find omap key for {object_key} on {_bucket_name(bucket)}"
        )


def remove_head_object(bucket, object_key):
    """Remove the head rados object while leaving the index entry."""
    name = _bucket_name(bucket)
    out = utils.exec_shell_cmd(
        f"radosgw-admin object stat --bucket {name} --object {object_key}"
    )
    if out is False:
        raise TestExecError(f"object stat failed for {name}/{object_key}")
    stat = json.loads(str(out))
    oid = stat.get("oid") or stat.get("manifest", {}).get("prefix")
    pool = stat.get("pool") or get_data_pool()
    if not oid:
        # fall back to listing data pool for the key
        data_pool = get_data_pool()
        oids = [o for o in list_pool_objects(data_pool) if object_key in o]
        if not oids:
            raise TestExecError(f"could not locate head oid for {object_key}")
        oid = oids[0]
        pool = data_pool
    log.info(f"removing head object {oid} from pool {pool}")
    rm = utils.exec_shell_cmd(f"rados -p {pool} rm {oid}")
    if rm is False:
        raise TestExecError(f"rados rm failed for {pool}/{oid}")


def bucket_check_fix(bucket):
    name = _bucket_name(bucket)
    out = utils.exec_shell_cmd(f"radosgw-admin bucket check --fix --bucket={name}")
    if out is False:
        raise TestExecError(f"bucket check --fix failed for {name}")
    return out


def probe_inject_knobs():
    """Return any ceph config keys that look like RGW fault-injection knobs."""
    out = utils.exec_shell_cmd("ceph config ls")
    if out is False or out is None:
        return []
    keys = []
    for line in str(out).splitlines():
        low = line.lower()
        if "inject" in low and "rgw" in low:
            keys.append(line.strip().split()[0])
        elif "rgw" in low and any(
            x in low for x in ("error_injection", "fault", "injecterr")
        ):
            keys.append(line.strip().split()[0])
    log.info(f"RGW inject knobs: {keys}")
    return keys


def pause_cluster_io():
    out = utils.exec_shell_cmd("ceph osd pause")
    if out is False:
        raise TestExecError("ceph osd pause failed")
    time.sleep(3)


def unpause_cluster_io():
    out = utils.exec_shell_cmd("ceph osd unpause")
    if out is False:
        raise TestExecError("ceph osd unpause failed")
    time.sleep(5)


def get_log_pool_bytes_used():
    out = run_json("ceph df --format json", allow_empty=True)
    pool_name = get_log_pool()
    if not isinstance(out, dict):
        return 0
    for pool in out.get("pools", []):
        name = pool.get("name")
        if name == pool_name or (name and pool_name in str(name)):
            stats = pool.get("stats") or {}
            return int(stats.get("bytes_used") or stats.get("stored") or 0)
    return 0


def scan_rgw_logs_for_fifo_errors():
    out = utils.exec_shell_cmd(
        "sudo ls -t /var/log/ceph/*/ceph-client.rgw* /var/log/ceph/ceph-client.rgw* 2>/dev/null | head -5"
    )
    if out is False or not out:
        log.info("no RGW log files found to scan")
        return []
    errors = []
    for path in str(out).splitlines():
        path = path.strip()
        if not path:
            continue
        grep = utils.exec_shell_cmd(
            f"sudo grep -iE 'fifo push|fifo.*fail|bilog.*error' {path} | tail -20"
        )
        if grep and grep is not False and str(grep).strip():
            errors.append((path, str(grep)))
    return errors


def stop_secondary_rgw():
    if not utils.is_cluster_multisite():
        raise TestExecError("secondary RGW stop requires a multisite cluster")
    from v2.tests.s3_swift.reusables import rgw_s3_elbencho as elbencho

    ssh_con = reusable.get_remote_conn_in_multisite()
    elbencho.stop_rgw_services(ssh_con=ssh_con, site_name="secondary")
    return ssh_con


def start_secondary_rgw(ssh_con=None):
    from v2.tests.s3_swift.reusables import rgw_s3_elbencho as elbencho

    ssh_con = ssh_con or reusable.get_remote_conn_in_multisite()
    elbencho.start_rgw_services(ssh_con=ssh_con, site_name="secondary")


def object_count(bucket):
    stats = get_bucket_stats(bucket)
    usage = stats.get("usage") or {}
    main = usage.get("rgw.main") or {}
    return int(main.get("num_objects") or 0)
