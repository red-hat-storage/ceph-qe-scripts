"""Reusable helpers for FIFO bucket-index log (bilog) tests."""

import json
import logging
import re
import shlex
import time

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.tests.s3_swift import reusable
from v2.utils.utils import RGWService

log = logging.getLogger()

FIFO_TYPE = "fifo"
ININDEX_TYPE = "inindex"
# cls fifo marker::to_string() is "{:0>20}:{:0>20}" (part number, byte offset).
# An unfiltered bilog list returns that string as op_id. --shard-id prefixes
# it with "{shard}#".
FIFO_MARKER_RE = re.compile(r"^[0-9]{20}:[0-9]{20}$")
SHARD_FIFO_MARKER_RE = re.compile(r"^(\d+)#([0-9]{20}:[0-9]{20})$")
# Head is "{bucket_id}.{gen}.{shard}.bilog". Parts are "{head}.{prefix}.{n}".
BILOG_OID_RE = re.compile(r"\.bilog(?:\.|$)")
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


def _json_bool(value):
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    return bool(value)


def enable_zonegroup_log_data(ssh_con=None):
    """Set log_data true on every zone in the zonegroup, then restart RGW."""
    doc = run_json("radosgw-admin zonegroup get", allow_empty=False)
    zones = doc.get("zones") or []
    if not zones:
        raise TestExecError("zonegroup get returned no zones")
    for zone in zones:
        zone["log_data"] = True
        log.info(f"enabling log_data on zone {zone.get('name')}")
    if "log_data" in doc:
        doc["log_data"] = True
    path = "/tmp/bilog_fifo_zonegroup.json"
    with open(path, "w") as handle:
        json.dump(doc, handle)
    out = utils.exec_shell_cmd(f"radosgw-admin zonegroup set --infile {path}")
    if out is False:
        raise TestExecError("zonegroup set failed while enabling log_data")
    period = utils.exec_shell_cmd("radosgw-admin period update --commit")
    if period is False:
        log.info("period update --commit did not apply")
    updated = run_json("radosgw-admin zonegroup get", allow_empty=False)
    for zone in updated.get("zones") or []:
        if not _json_bool(zone.get("log_data")):
            raise TestExecError(
                f"log_data is not true on zone {zone.get('name')} after zonegroup set"
            )
    rgw_service = RGWService()
    if not rgw_service.restart(ssh_con):
        raise TestExecError("RGW restart failed after enabling zonegroup log_data")
    time.sleep(20)
    log.info("zonegroup log_data is true and RGW was restarted")


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


def bare_fifo_marker(entry, shard_id=None):
    """Return the part:offset marker, dropping a --shard-id prefix."""
    eid = entry_id(entry)
    if eid is None:
        raise TestExecError(f"bilog entry missing id: {entry}")
    eid = str(eid)
    if shard_id is None:
        if not FIFO_MARKER_RE.match(eid):
            raise TestExecError(f"FIFO marker expected 20-digit part:offset, got {eid}")
        return eid
    match = SHARD_FIFO_MARKER_RE.match(eid)
    if not match or int(match.group(1)) != int(shard_id):
        raise TestExecError(f"FIFO marker expected {shard_id}#part:offset, got {eid}")
    return match.group(2)


def assert_marker_format(entry, fifo=True, shard_id=None):
    eid = entry_id(entry)
    if eid is None:
        raise TestExecError(f"bilog entry missing id: {entry}")
    if not fifo:
        return str(eid)
    return bare_fifo_marker(entry, shard_id=shard_id)


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


def assert_new_object_op(before, after, object_key, ops):
    """Require a new bilog entry for object_key whose op matches ops.

    Match the op field only. A previous PUT's state=complete must not count.
    """
    if isinstance(ops, str):
        ops = [ops]
    needles = [op.lower() for op in ops]
    before_ids = {entry_id(entry) for entry in before}
    found = []
    for entry in after:
        if entry_object(entry) != object_key:
            continue
        if entry_id(entry) in before_ids:
            continue
        op = entry_op(entry)
        if any(op == needle or needle in op for needle in needles):
            found.append(entry)
    if not found:
        seen = [(entry_object(e), entry_op(e), entry_id(e)) for e in after]
        raise TestExecError(
            f"no new bilog op in {needles} for {object_key}; entries={seen}"
        )
    log.info(f"new bilog entries for {object_key}: {found}")
    return found


def bucket_list_admin(bucket, versions=False):
    name = _bucket_name(bucket)
    cmd = f"radosgw-admin bucket list --bucket {name}"
    entries = run_json(cmd, allow_empty=True)
    if versions:
        return entries
    return entries


def _meta_value(entry, key):
    if not isinstance(entry, dict):
        return None
    if entry.get(key) not in (None, ""):
        return entry.get(key)
    meta = entry.get("meta")
    if isinstance(meta, dict):
        return meta.get(key)
    return None


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


def _secondary_caught_up(text):
    """True when a secondary status shows it has applied the primary."""
    low = text.lower()
    if "behind" in low or "recovering" in low:
        return False
    if (
        "failed to retrieve sync info" in low
        or "failed to fetch" in low
        or "no valid endpoint" in low
    ):
        return False
    return "caught up" in low


def _run_on_secondary(cmd):
    rc, out, err = reusable.exec_on_secondary(cmd)
    log.info(f"secondary rc={rc} cmd={cmd}\nout={out}\nerr={err}")
    return rc, out or "", err or ""


def bucket_full_sync(bucket, source_zone="primary"):
    """Init and run a full bucket sync on the secondary, pulling source_zone."""
    name = _bucket_name(bucket)
    for action in ("init", "run"):
        cmd = (
            f"radosgw-admin bucket sync {action} --bucket {shlex.quote(name)} "
            f"--source-zone {shlex.quote(source_zone)}"
        )
        rc, out, err = _run_on_secondary(cmd)
        if rc != 0:
            raise TestExecError(
                f"bucket sync {action} on secondary failed: {err or out}"
            )


def wait_sync(bucket=None, retry=30, delay=20, source_zone="primary"):
    """Wait until the secondary has applied primary bucket data.

    On the primary, "caught up with source" means the primary has applied
    the secondary. Poll the secondary instead.
    """
    if not utils.is_cluster_multisite():
        reusable.check_sync_status(retry=retry, delay=delay)
        if bucket is not None:
            name = _bucket_name(bucket)
            status = utils.exec_shell_cmd(
                f"radosgw-admin bucket sync status --bucket {name}"
            )
            log.info(f"bucket sync status: {status}")
        return
    name = _bucket_name(bucket) if bucket is not None else None
    last = ""
    for attempt in range(1, retry + 1):
        if name:
            cmd = (
                "radosgw-admin bucket sync status "
                f"--bucket {shlex.quote(name)} "
                f"--source-zone {shlex.quote(source_zone)}"
            )
        else:
            cmd = "radosgw-admin sync status"
        rc, out, err = _run_on_secondary(cmd)
        last = out + err
        if rc == 0 and _secondary_caught_up(last):
            log.info(f"secondary caught up for {name or 'zone'}")
            return last
        log.info(f"secondary sync not caught up ({attempt}/{retry})")
        time.sleep(delay)
    raise TestExecError(f"secondary sync not caught up after {retry} tries: {last}")


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
            p_match = next(
                (e for e in primary if (e.get("name") or e.get("key")) == key),
                None,
            )
            s_match = next(
                (e for e in secondary if (e.get("name") or e.get("key")) == key),
                None,
            )
            if p_match is None or s_match is None:
                raise TestExecError(f"versioned key {key} missing on one zone")
            p_epoch = _meta_value(p_match, "versioned_epoch")
            s_epoch = _meta_value(s_match, "versioned_epoch")
            if (
                p_epoch is not None
                and s_epoch is not None
                and int(p_epoch) != int(s_epoch)
            ):
                raise TestExecError(
                    f"versioned_epoch mismatch for {key}: {p_epoch} vs {s_epoch}"
                )
            p_instance = str(p_match.get("instance") or "")
            s_instance = str(s_match.get("instance") or "")
            if p_instance != s_instance:
                raise TestExecError(
                    f"version id mismatch for {key}: {p_instance} vs {s_instance}"
                )
            p_etag = _meta_value(p_match, "etag")
            s_etag = _meta_value(s_match, "etag")
            if (p_etag or s_etag) and p_etag != s_etag:
                raise TestExecError(f"etag mismatch for {key}: {p_etag} vs {s_etag}")
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


def _rule_val(manifest):
    rules = manifest.get("rules") or []
    if not rules or not isinstance(rules[0], dict):
        return {}
    rule = rules[0]
    val = rule.get("val", rule)
    return val if isinstance(val, dict) else {}


def _part_target(part, default_pool):
    """Return (pool, oid, namespace) for one manifest part, or None."""
    if isinstance(part, str) and part:
        return default_pool, part, None
    if not isinstance(part, dict):
        return None
    oid = part.get("oid")
    ns = part.get("ns") or part.get("namespace") or None
    pool = part.get("pool") or default_pool
    loc = part.get("loc") if isinstance(part.get("loc"), dict) else {}
    key = loc.get("key") if isinstance(loc.get("key"), dict) else {}
    raw = loc.get("raw_obj") if isinstance(loc.get("raw_obj"), dict) else {}
    oid = oid or key.get("name") or raw.get("oid")
    ns = ns or key.get("ns") or raw.get("loc") or None
    pool = raw.get("pool") or pool
    if isinstance(pool, dict):
        pool = pool.get("name") or pool.get("pool") or default_pool
    if not oid:
        return None
    return str(pool), str(oid), ns or None


def _tail_targets(manifest, default_pool):
    """RADOS tails for an object. An inline object has none.

    Implicit tails are "{prefix}{stripe}" in the shadow namespace. The
    manifest prefix itself is not an object name. Stripe 0 is the index head.
    """
    if manifest.get("explicit_objs"):
        targets = []
        for part in manifest.get("objs") or []:
            target = _part_target(part, default_pool)
            if target:
                targets.append(target)
        return targets
    try:
        obj_size = int(manifest.get("obj_size") or 0)
        max_head = int(manifest.get("max_head_size") or 0)
        head_size = int(manifest.get("head_size") or 0)
        stripe = int(_rule_val(manifest).get("stripe_max_size") or 0)
    except (TypeError, ValueError):
        return []
    if obj_size <= max_head or (head_size and head_size >= obj_size):
        return []
    if stripe <= 0:
        stripe = max_head
    prefix = manifest.get("prefix")
    if stripe <= 0 or not prefix:
        return []
    targets = []
    stripe_id = 0
    ofs = max_head
    while ofs < obj_size:
        stripe_id += 1
        targets.append((default_pool, f"{prefix}{stripe_id}", "shadow"))
        ofs += stripe
    return targets


def remove_head_object(bucket, object_key):
    """Remove data-pool tail objects and leave the bucket index entry.

    Objects that fit in the index head have no RADOS object. Callers that
    need those bytes gone remove the index key themselves.
    """
    name = _bucket_name(bucket)
    out = utils.exec_shell_cmd(
        f"radosgw-admin object stat --bucket {name} --object {object_key}"
    )
    if out is False:
        raise TestExecError(f"object stat failed for {name}/{object_key}")
    stat = json.loads(str(out))
    manifest = stat.get("manifest") or {}
    pool = stat.get("pool") or get_data_pool()
    targets = _tail_targets(manifest, pool)
    if not targets:
        log.info(
            f"{object_key} is inline in the bucket index "
            f"(head_size={manifest.get('head_size')}, size={stat.get('size')}); "
            "no data-pool object to remove"
        )
        return []
    for data_pool, oid, ns in targets:
        ns_arg = f" --namespace {shlex.quote(ns)}" if ns else ""
        log.info(f"removing tail object {data_pool}/{ns or '-'}:{oid}")
        rm = utils.exec_shell_cmd(
            f"rados -p {shlex.quote(data_pool)}{ns_arg} rm {shlex.quote(oid)}"
        )
        if rm is False:
            raise TestExecError(f"rados rm failed for {data_pool}/{oid}")
    return targets


def object_reindex(bucket, object_key):
    """Link an existing head object back into the bucket index."""
    name = _bucket_name(bucket)
    cmd = f"radosgw-admin object reindex --bucket {name} --object {object_key}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"object reindex failed for {name}/{object_key}")
    return out


def bucket_check_fix(bucket):
    """Run bucket check on the check_disk_state path."""
    name = _bucket_name(bucket)
    cmd = f"radosgw-admin bucket check --check-objects --fix --bucket={name}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"bucket check --check-objects --fix failed for {name}")
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
