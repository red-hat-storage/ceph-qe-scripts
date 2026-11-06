# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
IBMCEPH-19409: a stale or cancelled bucket-index completion regresses entry.ver.

Source of the checks: apple-ms/IBMCEPH-19409/repro_19409.py.

rgw_bucket_complete_op() (src/cls/rgw/cls_rgw.cc) sets `entry.ver = op.ver` even
for an op it turned into a cancel because its epoch is stale, and for a real
cancel (ver {-1,0}).  The entry's version then goes backwards, so a LATER
completion from an OLDER epoch passes the epoch check and overwrites the newest
entry.  Nothing is pending any more, so no listing repairs it.

The test drives the real `rgw` cls methods (bucket_init_index,
bucket_prepare_op, bucket_complete_op) on a scratch object in the bucket-index
pool with python-rados.  No bucket and no RGW daemon are involved.  The ops are
hand-encoded (layouts: cls_rgw_ops.h, cls_rgw_types.h).

Needs: python3-rados and a ceph.conf with an admin keyring (the admin node).

PASSED  - the newest entry survives every arrival order.
FAILED  - an older completion replaced the newest entry (the bug).
"""

import logging
import struct
import uuid

import pytest

rados = pytest.importorskip("rados", reason="python3-rados is not installed")

log = logging.getLogger(__name__)

POOL_ID = 7  # any non-negative id; the cls code only compares it for equality
ADD, DEL, CANCEL = 0, 1, 2


# ── minimal ceph encoding helpers ───────────────────────────────────────────
def u8(v):
    return struct.pack("<B", v)


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def enc_str(v):
    b = v.encode()
    return u32(len(b)) + b


def envelope(ver, compat, body):
    return u8(ver) + u8(compat) + u32(len(body)) + body


def packed(v):
    v &= 0xFFFFFFFFFFFFFFFF
    if v < 0x80:
        return u8(v)
    if v < 0x100:
        return u8(0x81) + u8(v)
    if v <= 0x10000:
        return u8(0x82) + u16(v)
    if v <= 0x1000000:
        return u8(0x84) + u32(v)
    return u8(0x88) + u64(v)


def key_enc(name, instance=""):
    return envelope(1, 1, enc_str(name) + enc_str(instance))


def ver_enc(pool, epoch):
    return envelope(1, 1, packed(pool) + packed(epoch))


def meta_enc(size):
    body = (
        u8(0)
        + u64(size)
        + u32(1700000000)
        + u32(0)
        + enc_str("etag")
        + enc_str("owner")
        + enc_str("owner")
        + enc_str("")
        + u64(size)
        + enc_str("")
        + enc_str("STANDARD")
        + u8(0)
    )
    return envelope(7, 3, body)


def prepare_op(op, name, tag):
    # rgw_cls_obj_prepare_op v7: op, tag, locator, log_op, key, bilog_flags, zones_trace
    body = u8(op) + enc_str(tag) + enc_str("") + u8(0) + key_enc(name) + u16(0) + u32(0)
    return envelope(7, 5, body)


def complete_op(op, name, tag, pool, epoch, size):
    # rgw_cls_obj_complete_op v9: op, ver.epoch, meta, tag, locator, remove_objs,
    # ver, log_op, key, bilog_flags, zones_trace
    body = (
        u8(op)
        + u64(epoch)
        + meta_enc(size)
        + enc_str(tag)
        + enc_str("")
        + u32(0)
        + ver_enc(pool, epoch)
        + u8(0)
        + key_enc(name)
        + u16(0)
        + u32(0)
    )
    return envelope(9, 7, body)


# ── cls calls and entry decoding ────────────────────────────────────────────
def call(io, oid, method, data):
    try:
        ret, _ = io.execute(oid, "rgw", method, data)
        return ret
    except rados.Error as e:
        return f"ERR({e})"


def read_entry(io, oid, name):
    """dict(epoch, exists, size, pending) of the omap entry, or None if absent."""
    with rados.ReadOpCtx() as rop:
        it, _ = io.get_omap_vals(rop, "", "", 1000)
        io.operate_read_op(rop, oid)
        vals = dict(it)
    raw = vals.get(name)
    if raw is None:
        return None
    p = 6  # skip the envelope: v, compat, len
    n = struct.unpack_from("<I", raw, p)[0]
    p += 4 + n  # key.name
    epoch = struct.unpack_from("<Q", raw, p)[0]
    p += 8  # legacy ver.epoch
    exists = raw[p]
    p += 1
    mlen = struct.unpack_from("<I", raw, p + 2)[0]
    size = struct.unpack_from("<Q", raw, p + 6 + 1)[0]  # meta: category u8, size u64
    p += 6 + mlen
    pending = struct.unpack_from("<I", raw, p)[0]  # pending_map entry count
    return {"epoch": epoch, "exists": bool(exists), "size": size, "pending": pending}


def newest(entry, size, epoch):
    return (
        entry is not None
        and entry["exists"]
        and entry["size"] == size
        and entry["epoch"] == epoch
    )


def key_gone(entry):
    return entry is None or not entry["exists"]


# (id, key, steps, predicate on the final entry, what must hold)
SCENARIOS = [
    (
        "control",
        "k-control",
        [
            ("prepare", ADD, "t1"),
            ("prepare", ADD, "t2"),
            ("prepare", ADD, "t3"),
            ("complete", ADD, "t1", POOL_ID, 1, 100),
            ("complete", ADD, "t2", POOL_ID, 2, 200),
            ("complete", ADD, "t3", POOL_ID, 3, 300),
        ],
        lambda e: newest(e, 300, 3),
        "in-order puts 1,2,3: entry must be epoch 3 / size 300",
    ),
    (
        "stale_complete_keeps_newest",
        "k-stale",
        [
            ("prepare", ADD, "t1"),
            ("prepare", ADD, "t2"),
            ("prepare", ADD, "t3"),
            ("complete", ADD, "t3", POOL_ID, 3, 300),
            ("complete", ADD, "t1", POOL_ID, 1, 100),
            ("complete", ADD, "t2", POOL_ID, 2, 200),
        ],
        lambda e: newest(e, 300, 3),
        "completions arrive 3,1,2: entry must stay epoch 3 / size 300",
    ),
    (
        "cancel_keeps_newest",
        "k-cancel",
        [
            ("prepare", ADD, "t1"),
            ("prepare", ADD, "t2"),
            ("prepare", ADD, "t3"),
            ("complete", ADD, "t3", POOL_ID, 3, 300),
            ("complete", CANCEL, "t2", -1, 0, 0),
            ("complete", ADD, "t1", POOL_ID, 1, 100),
        ],
        lambda e: newest(e, 300, 3),
        "put 3 applied, put 2 cancelled (ver -1,0), put 1 completes: stay epoch 3",
    ),
    (
        "stale_complete_after_delete",
        "k-delete",
        [
            ("prepare", DEL, "d1"),
            ("prepare", ADD, "p2"),
            ("prepare", DEL, "d3"),
            ("complete", DEL, "d3", POOL_ID, 3, 0),
            ("complete", DEL, "d1", POOL_ID, 1, 0),
            ("complete", ADD, "p2", POOL_ID, 2, 200),
        ],
        key_gone,
        "delete(1), put(2), delete(3) arrive 3,1,2: key must NOT be listed",
    ),
]


@pytest.fixture(scope="module")
def ioctx(env):
    conf = env.cfg.get("ceph_conf", "/etc/ceph/ceph.conf")
    cluster = rados.Rados(conffile=conf)
    try:
        cluster.connect()
    except Exception as e:
        pytest.skip(f"cannot connect to the cluster with {conf}: {e!r}")
    try:
        io = cluster.open_ioctx(env.index_pool)
    except Exception as e:
        cluster.shutdown()
        pytest.skip(f"cannot open pool {env.index_pool}: {e!r}")
    log.info("cluster %s pool %s", cluster.get_fsid(), env.index_pool)
    yield io
    io.close()
    cluster.shutdown()


def run_scenario(io, key, steps):
    """Run the steps on a fresh scratch index object; return (oid, final entry)."""
    oid = f".dir.ibmceph19409-{uuid.uuid4().hex[:10]}.0"
    log.info("init index %s -> %s", oid, call(io, oid, "bucket_init_index", b""))
    try:
        for st in steps:
            if st[0] == "prepare":
                _, op, tag = st
                rc = call(io, oid, "bucket_prepare_op", prepare_op(op, key, tag))
                log.info("  prepare  %s tag=%s -> %s", ("ADD", "DEL")[op], tag, rc)
            else:
                _, op, tag, vpool, epoch, size = st
                rc = call(
                    io,
                    oid,
                    "bucket_complete_op",
                    complete_op(op, key, tag, vpool, epoch, size),
                )
                log.info(
                    "  complete %-6s tag=%s ver=(%s,%s) size=%s -> %s",
                    ("ADD", "DEL", "CANCEL")[op],
                    tag,
                    vpool,
                    epoch,
                    size,
                    rc,
                )
            log.info("     entry: %s", read_entry(io, oid, key))
        return read_entry(io, oid, key)
    finally:
        try:
            io.remove_object(oid)
        except rados.Error:
            pass


@pytest.fixture(scope="module")
def harness_ok(ioctx):
    """The control must pass first, or the encoding / harness is wrong."""
    name, key, steps, expect, why = SCENARIOS[0]
    final = run_scenario(ioctx, key, steps)
    if not expect(final):
        pytest.fail(f"harness control failed ({why}): final entry {final}")


@pytest.mark.ibmceph_cls
@pytest.mark.ibmceph_control
@pytest.mark.ibmceph_all
def test_19409_control_in_order(harness_ok):
    """In-order completions leave the newest entry (checks the cls encoding)."""


@pytest.mark.ibmceph_cls
@pytest.mark.ibmceph_all
@pytest.mark.parametrize(
    "name,key,steps,expect,why", SCENARIOS[1:], ids=[s[0] for s in SCENARIOS[1:]]
)
def test_19409_stale_completion_keeps_newest(
    ioctx, harness_ok, name, key, steps, expect, why
):
    """A stale or cancelled completion must not regress the bucket index entry."""
    final = run_scenario(ioctx, key, steps)
    log.info("%s: %s; final entry %s", name, why, final)
    assert expect(
        final
    ), f"BUG IBMCEPH-19409 ({name}): {why}; stale entry kept: {final}"
