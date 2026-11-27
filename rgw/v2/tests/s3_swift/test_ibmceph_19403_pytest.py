# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
test_ibmceph_19403_pytest.py — RGW Overwrite Race Condition Test Suite (Pytest)

Covers all 10 scenarios reproduced under IBMCEPH-19403 epic:

  ibmceph_mpu  : 19405, 19406, 19406v, 19407, 19407bl, 19410
                 (multipart completion races)
  ibmceph_race : 19412, 19414, 19416, 19417
                 (overwrite / bucket-index races)
  ibmceph_cond : 19424
                 (conditional write atomicity)
  ibmceph_all  : all of the above

Test semantics (standard pytest):
  PASSED  — correct behaviour observed, or race window was not caught (inconclusive)
  FAILED  — bug confirmed: the buggy/data-loss condition was reproduced
  SKIPPED — prerequisite for the race was not met (inconclusive, re-run to retry)

Test summary:
  19405   Lock renewal failure + concurrent complete → data loss
  19406   RGW crash between head-write and meta-delete → ghost object
  19406v  Same as 19406 on versioning-SUSPENDED bucket
  19407   Failed meta-delete + retry from second RGW → data loss (SIGKILL)
  19407bl Failed meta-delete + retry → data loss (OSD blocklist method)
  19410   Lifecycle AbortMPU ignores completion lock → premature GC
  19412   DeleteObject racing overwrite deletes new data
  19414   CopyObject-self racing overwrite deletes data
  19416   Stalled write lost from bucket index
  19417   DeleteObject lost RADOS-level ID-tag guard
  19424   8 concurrent conditional PUTs (If-Match) all succeed (at most 1 should)

Usage:
  pytest test_ibmceph_19403_pytest.py -C config.yaml -v
  pytest test_ibmceph_19403_pytest.py -C config.yaml -m ibmceph_mpu
  pytest test_ibmceph_19403_pytest.py -C config.yaml -m ibmceph_race
  pytest test_ibmceph_19403_pytest.py -C config.yaml -m ibmceph_cond
  pytest test_ibmceph_19403_pytest.py -C config.yaml -k "19424"

Config YAML keys (all optional — fall back to env vars / defaults):
  rgw_a_url         : http://10.0.65.65:80
  rgw_b_url         : http://10.0.67.70:80
  access_key        : <S3 access key>
  secret_key        : <S3 secret key>
  data_pool         : primary.rgw.buckets.data
  meta_pool         : primary.rgw.buckets.non-ec
  rgw_a_unit        : systemd unit name for RGW-A (used for SIGKILL)
  rgw_a_ctr_pattern : podman container name substring (default: plxcxh)
  part_size         : 5242880  (5 MiB)
  num_parts         : 8
  bl_lock_ttl       : 30   (lock TTL when using blocklist method for 19407bl)
  bl_secs           : 40   (blocklist duration for 19407bl — must exceed bl_lock_ttl)
"""

import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid

import boto3
import pytest
import yaml
from botocore.config import Config
from botocore.exceptions import ClientError, ResponseStreamingError

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

class _Cfg:
    """Thin wrapper around the YAML config dict with env-var fallbacks."""

    def __init__(self, path):
        data = {}
        if path and os.path.exists(path):
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        self._d = data

    def get(self, key, default=None):
        return self._d.get(key, os.environ.get(key.upper(), default))

    def __getattr__(self, key):
        return self.get(key)


# ---------------------------------------------------------------------------
# Session-scoped cluster fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def cluster_cfg(request):
    path = request.config.getoption("config")
    return _Cfg(path)


@pytest.fixture(scope="session")
def rgw_env(cluster_cfg):
    """
    Single session-scoped object holding all cluster connection details
    and low-level helpers.  Shared across all tests so we don't re-derive
    the container name / asok path on every test.
    """
    env = _RgwEnv(cluster_cfg)
    env.ensure_rgw_a_healthy()   # verify both RGWs reachable before suite starts
    return env


# ---------------------------------------------------------------------------
# Function-scoped fixtures used by individual tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def rgw_a_up(rgw_env):
    """
    Guarantee RGW-A is running at the START of every test.
    Tests that kill RGW-A must not leave it down for the next test.
    """
    rgw_env.ensure_rgw_a_healthy()
    yield
    # post-test: disarm any leftover delay injection
    try:
        rgw_env.asok_set("ms_inject_delay_probability", 0)
        rgw_env.asok_set("ms_inject_delay_max", 0)
        rgw_env.asok_set("rgw_mp_lock_inject_renewal_error", 0)
    except Exception:
        pass
    # restore GC / MPU timers to safe defaults
    rgw_env.reset_gc()
    rgw_env.reset_mp()


# ---------------------------------------------------------------------------
# _RgwEnv — all helpers in one place
# ---------------------------------------------------------------------------

class _Inconclusive(Exception):
    """Raised when preconditions for a race window are not met."""


class _RgwEnv:
    PART_SIZE = 5 * 1024 * 1024
    NUM_PARTS = 8

    def __init__(self, cfg: _Cfg):
        self.rgw_a_url = cfg.get("rgw_a_url", "http://10.0.65.65:80")
        self.rgw_b_url = cfg.get("rgw_b_url", "http://10.0.67.70:80")
        self.access_key = cfg.get("access_key", "QDGQ2R11JYCJF5X4MJIV")
        self.secret_key = cfg.get("secret_key", "4BqntvhPxDCXphzVatqOboNooZDuCNTYIW6X6UV1")
        self.data_pool = cfg.get("data_pool", "primary.rgw.buckets.data")
        self.meta_pool = cfg.get("meta_pool", "primary.rgw.buckets.non-ec")
        self.rgw_a_unit = cfg.get(
            "rgw_a_unit",
            "ceph-bc3b2f76-bef1-11f1-9938-fa163e9ef13f"
            "@rgw.shared.pri.ceph-pri-vim-restore-91-rio86c-node5.plxcxh.service",
        )
        self.ctr_pattern = cfg.get("rgw_a_ctr_pattern", "plxcxh")
        self.part_size = int(cfg.get("part_size", self.PART_SIZE))
        self.num_parts = int(cfg.get("num_parts", self.NUM_PARTS))
        self.bl_lock_ttl = int(cfg.get("bl_lock_ttl", 30))
        self.bl_secs = int(cfg.get("bl_secs", 40))
        self._container = self._find_container()

    # ── container / asok ────────────────────────────────────────────────────

    def _find_container(self):
        r = subprocess.run(["podman", "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True)
        hits = [l for l in r.stdout.strip().splitlines() if self.ctr_pattern in l]
        return hits[0] if hits else None

    def _refresh_asok(self, cname):
        # Pattern is generic — matches any RGW asok containing ctr_pattern,
        # excluding the secondary rgwb socket if present.
        inner = subprocess.check_output(
            ["podman", "exec", cname, "sh", "-c",
             f"ls -t /var/run/ceph/ceph-client.rgw.*{self.ctr_pattern}*.asok"
             " 2>/dev/null | grep -v rgwb | head -1"],
            text=True,
        ).strip()
        if not inner:
            raise RuntimeError("No asok found inside container")
        subprocess.run(["podman", "exec", cname, "ln", "-sf", inner, "/tmp/rgw.asok"],
                       check=True)

    def asok_set(self, key, value):
        cname = self._find_container() or self._container
        subprocess.run(
            ["podman", "exec", cname, "ceph", "--admin-daemon", "/tmp/rgw.asok",
             "config", "set", str(key), str(value)],
            capture_output=True,
        )
        log.debug("asok %s=%s", key, value)

    def asok_get(self, key):
        cname = self._find_container() or self._container
        r = subprocess.run(
            ["podman", "exec", cname, "ceph", "--admin-daemon", "/tmp/rgw.asok",
             "config", "get", str(key)],
            capture_output=True, text=True,
        )
        return r.stdout.strip()

    # ── RGW-A lifecycle ──────────────────────────────────────────────────────

    def kill_rgw_a(self):
        log.info("SIGKILL RGW-A via systemctl")
        subprocess.run(["systemctl", "kill", "--signal=SIGKILL", self.rgw_a_unit],
                       capture_output=True)

    def wait_rgw_a_healthy(self, timeout=120):
        log.info("Waiting for RGW-A to recover…")
        probe = self.s3_client(self.rgw_a_url, timeout=5)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(3)
            st = subprocess.run(
                ["systemctl", "is-active", self.rgw_a_unit],
                capture_output=True, text=True,
            ).stdout.strip()
            if st == "failed":
                log.warning("RGW-A unit in failed state — reset-failed + start")
                subprocess.run(["systemctl", "reset-failed", self.rgw_a_unit],
                               capture_output=True)
                subprocess.run(["systemctl", "start", self.rgw_a_unit],
                               capture_output=True)
                time.sleep(5)
                continue
            cname = self._find_container()
            if not cname:
                continue
            try:
                self._refresh_asok(cname)
            except Exception:
                continue
            try:
                probe.list_buckets()
                self._container = cname
                log.info("RGW-A healthy (%s)", cname)
                time.sleep(2)
                return
            except Exception:
                continue
        raise RuntimeError(f"RGW-A did not become healthy within {timeout}s")

    def ensure_rgw_a_healthy(self):
        """Call before every test — recovers if RGW-A was left down."""
        cname = self._find_container()
        if cname:
            try:
                probe = self.s3_client(self.rgw_a_url, timeout=5)
                probe.list_buckets()
                self._container = cname
                self._refresh_asok(cname)
                return
            except Exception:
                pass
        log.warning("RGW-A not responding — waiting for recovery")
        self.wait_rgw_a_healthy()

    # ── ceph / rados helpers ─────────────────────────────────────────────────

    @staticmethod
    def _run(*args):
        return subprocess.run(list(args), capture_output=True, text=True).stdout.strip()

    def ceph(self, *args):
        return self._run("ceph", *args)

    def rados(self, *args):
        return self._run("rados", *args)

    def rgwadm(self, *args):
        return self._run("radosgw-admin", *args)

    def set_rgw(self, key, value):
        self.ceph("config", "set", "client.rgw", str(key), str(value))

    def reset_gc(self):
        self.set_rgw("rgw_gc_obj_min_wait", "7200")
        self.set_rgw("rgw_gc_processor_period", "3600")

    def reset_mp(self):
        self.set_rgw("rgw_mp_lock_max_time", "600")

    def run_gc(self):
        log.info("GC: sleeping 35 s then processing…")
        time.sleep(35)
        self.rgwadm("gc", "process", "--include-all")
        log.info("GC: sleeping 30 s then processing…")
        time.sleep(30)
        self.rgwadm("gc", "process", "--include-all")
        time.sleep(10)

    def gc_count(self, uid):
        out = subprocess.run(
            ["radosgw-admin", "gc", "list", "--include-all"],
            capture_output=True, text=True,
        ).stdout
        return sum(1 for ln in out.splitlines() if uid[:16] in ln)

    def find_meta(self, uid):
        for ln in self.rados("-p", self.meta_pool, "ls").splitlines():
            ln = ln.strip()
            if uid in ln and ln.endswith(".meta"):
                return ln
        return None

    # ── OSD blocklist helpers (used by 19407bl) ──────────────────────────────

    def get_rgw_a_addrs(self):
        """Return RGW-A RADOS addrs from servicemap matching ctr_pattern."""
        out = subprocess.check_output(["ceph", "status", "-f", "json"], text=True)
        d = json.loads(out)
        daemons = (d.get("servicemap", {}).get("services", {})
                    .get("rgw", {}).get("daemons", {}))
        return [v["addr"] for gid, v in daemons.items()
                if gid != "summary"
                and self.ctr_pattern in v.get("metadata", {}).get("id", "")
                and v.get("addr", "")]

    def blocklist_add(self, addr, secs):
        log.info("blocklisting %s for %ss", addr, secs)
        r = subprocess.run(["ceph", "osd", "blocklist", "add", addr, str(secs)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            log.warning("blocklist add failed: %s", r.stderr.strip())
        return r.returncode == 0

    def blocklist_rm(self, addr):
        subprocess.run(["ceph", "osd", "blocklist", "rm", addr],
                       capture_output=True, text=True)
        log.info("blocklist removed %s", addr)

    def wait_rgw_healthy(self, url, timeout=60):
        """Wait until the given RGW URL accepts list_buckets."""
        cl = self.s3_client(url, timeout=5)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                cl.list_buckets()
                return True
            except Exception:
                time.sleep(2)
        return False

    def break_lock(self, oid):
        raw = self.rados("-p", self.meta_pool, "lock", "info",
                         oid, "RGWCompleteMultipart")
        try:
            lockers = json.loads(raw).get("lockers", [])
        except Exception as e:
            raise _Inconclusive(f"lock parse failed: {e}")
        if not lockers:
            raise _Inconclusive("No locker found at trigger point")
        locker = lockers[0]
        self.rados("-p", self.meta_pool, "lock", "break", oid,
                   "RGWCompleteMultipart", locker["name"],
                   "--lock-cookie", locker["cookie"])
        log.info("lock broken: %s", locker["name"])

    # ── S3 client factory ────────────────────────────────────────────────────

    def s3_client(self, url=None, timeout=400):
        return boto3.client(
            "s3",
            endpoint_url=url or self.rgw_a_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            config=Config(
                signature_version="s3v4",
                read_timeout=timeout,
                retries={"max_attempts": 1},
            ),
        )

    def a(self):
        return self.s3_client(self.rgw_a_url)

    def b(self):
        return self.s3_client(self.rgw_b_url)

    # ── S3 operation helpers ─────────────────────────────────────────────────

    @staticmethod
    def http(fn):
        try:
            r = fn()
            return r["ResponseMetadata"]["HTTPStatusCode"]
        except ClientError as e:
            return e.response["ResponseMetadata"]["HTTPStatusCode"]

    def parts_upload(self, client, bkt, key, uid, n=None):
        n = n or self.num_parts
        parts = []
        for i in range(1, n + 1):
            r = client.upload_part(
                Bucket=bkt, Key=key, UploadId=uid,
                PartNumber=i, Body=b"X" * self.part_size,
            )
            parts.append({"PartNumber": i, "ETag": r["ETag"]})
        return parts

    def do_complete(self, client, bkt, key, uid, parts):
        return self.http(lambda: client.complete_multipart_upload(
            Bucket=bkt, Key=key, UploadId=uid,
            MultipartUpload={"Parts": parts},
        ))

    def check(self, client, bkt, key):
        """Returns (head_status, get_status, bytes_read)."""
        h = self.http(lambda: client.head_object(Bucket=bkt, Key=key))
        try:
            o = client.get_object(Bucket=bkt, Key=key)
            try:
                data = o["Body"].read()
            except (ResponseStreamingError, Exception) as e:
                log.warning("GET streaming error (data corrupted): %s", e)
                return h, 200, 0
            return h, o["ResponseMetadata"]["HTTPStatusCode"], len(data)
        except ClientError as e:
            return h, e.response["ResponseMetadata"]["HTTPStatusCode"], 0

    def wait_head_ok(self, client, bkt, key, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                client.head_object(Bucket=bkt, Key=key)
                return True
            except Exception:
                time.sleep(0.5)
        return False

    def wait_get_ok(self, client, bkt, key, timeout=180):
        exp = self.num_parts * self.part_size
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                o = client.get_object(Bucket=bkt, Key=key)
                data = o["Body"].read()
                if o["ResponseMetadata"]["HTTPStatusCode"] == 200 and len(data) == exp:
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    # ── Shared MPU crash+TTL helper (19406 / 19406v) ─────────────────────────

    def _crash_ttl_retry(self, jid, versioning=False):
        """
        Common body for 19406 and 19406v.
        Returns True  = data loss reproduced
                False = pass (race not triggered)
        Raises _Inconclusive if the required window was not hit.
        """
        a = self.a(); b = self.b()
        bkt = f"ibm{jid}-{uuid.uuid4().hex[:8]}"; key = "mpu-obj"
        armed = []
        try:
            self.set_rgw("rgw_mp_lock_max_time", "120")
            self.set_rgw("rgw_gc_obj_min_wait", "5")
            self.set_rgw("rgw_gc_processor_period", "1")
            a.create_bucket(Bucket=bkt)
            if versioning:
                a.put_bucket_versioning(
                    Bucket=bkt,
                    VersioningConfiguration={"Status": "Enabled"})
                a.put_bucket_versioning(
                    Bucket=bkt,
                    VersioningConfiguration={"Status": "Suspended"})
                log.info("versioning: Enabled→Suspended")
            uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
            parts = self.parts_upload(a, bkt, key, uid)
            log.info("bkt=%s uid=%s", bkt, uid)
            self.asok_set("ms_inject_delay_max", 10);  armed.append(("ms_inject_delay_max", 0))
            self.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
            ra = {}; ev = threading.Event()

            def do_a():
                ev.set()
                ra["s"] = self.do_complete(a, bkt, key, uid, parts)

            t = threading.Thread(target=do_a, daemon=True)
            t.start(); ev.wait()
            log.info("waiting for GET 200 full data (head durably written)…")
            if not self.wait_get_ok(b, bkt, key, 180):
                raise _Inconclusive("GET never returned full data within 180 s")
            oid = self.find_meta(uid)
            if not oid:
                raise _Inconclusive("No .meta OID — A already deleted it before kill")
            log.info("struck (get-ok); .meta present")
            self.kill_rgw_a(); t.join(timeout=10)
            self.wait_rgw_a_healthy()
            h0, g0, _ = self.check(b, bkt, key)
            gc0 = self.gc_count(uid)
            log.info("pre-retry: HEAD=%s GET=%s gc_queue_tails=%s", h0, g0, gc0)
            if g0 != 200:
                raise _Inconclusive(f"pre-retry GET={g0}")
            log.info("waiting 125 s for lock TTL to lapse…")
            time.sleep(125)
            sb = self.do_complete(b, bkt, key, uid, parts)
            gc1 = self.gc_count(uid)
            log.info("retry on rgw.b → %s  post-retry gc_queue_tails=%s (was %s)",
                     sb, gc1, gc0)
            self.run_gc()
            h, g, dl = self.check(b, bkt, key)
            exp = self.num_parts * self.part_size
            loss = h == 200 and (g != 200 or dl != exp)
            log.info("oracle: HEAD=%s GET=%s bytes=%s dataloss=%s", h, g, dl, loss)
            return loss
        finally:
            for k, v in reversed(armed):
                try: self.asok_set(k, v)
                except Exception: pass
            self.reset_mp(); self.reset_gc()
            try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
            except Exception: pass


# ===========================================================================
# MULTIPART COMPLETION RACE TESTS  (marker: ibmceph_mpu)
# ===========================================================================

@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19405_lock_renewal_failure_concurrent_complete(rgw_env):
    """
    IBMCEPH-19405: Lock renewal failure + concurrent CompleteMultipartUpload.

    Injects rgw_mp_lock_inject_renewal_error=-5 so the renewal coroutine
    stops. Arms ms_inject_delay to widen the window. Fires CompleteMultipartUpload
    on RGW-A, waits until HEAD is visible on RGW-B, breaks the lock via RADOS,
    then retries on RGW-B. After GC, expects HEAD 200 GET 404 (data loss).
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19405-{uuid.uuid4().hex[:8]}"; key = "mpu-obj"
    armed = []
    try:
        env.set_rgw("rgw_mp_lock_max_time", "120")
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        env.asok_set("rgw_mp_lock_inject_renewal_error", -5)
        armed.append(("rgw_mp_lock_inject_renewal_error", 0))
        a.create_bucket(Bucket=bkt)
        uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts = env.parts_upload(a, bkt, key, uid)
        log.info("bkt=%s uid=%s", bkt, uid)
        env.asok_set("ms_inject_delay_max", 20);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        ra = {}; ev = threading.Event()

        def do_a():
            ev.set()
            ra["s"] = env.do_complete(a, bkt, key, uid, parts)

        t = threading.Thread(target=do_a, daemon=True)
        t.start(); ev.wait()

        if not env.wait_head_ok(b, bkt, key, 180):
            pytest.skip("HEAD not visible within 180 s — race window not hit")
        oid = env.find_meta(uid)
        if not t.is_alive():
            pytest.skip("RGW-A completed before lock break")
        if not oid:
            pytest.skip("No .meta OID")

        gc0 = env.gc_count(uid)
        log.info("pre-retry gc_queue_tails=%s", gc0)
        env.break_lock(oid)
        env.asok_set("ms_inject_delay_probability", 0)
        env.asok_set("ms_inject_delay_max", 0)
        sb = env.do_complete(b, bkt, key, uid, parts)
        gc1 = env.gc_count(uid)
        log.info("retry rgw.b → %s  post-retry gc_queue_tails=%s (was %s)", sb, gc1, gc0)
        t.join(timeout=400)
        log.info("A=%s", ra.get("s", "?"))
        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        exp = env.num_parts * env.part_size
        log.info("oracle: HEAD=%s GET=%s bytes=%s", h, g, dl)
        if h == 200 and (g != 200 or dl != exp):
            pytest.fail(
                f"IBMCEPH-19405 BUG CONFIRMED: data loss after racing CompleteMultipartUpload"
                f" — HEAD={h} GET={g} bytes={dl}/{exp}"
                f" (gc_queue_tails: {gc0}→{gc1})"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.reset_mp(); env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19406_crash_head_written_ttl_retry(rgw_env):
    """
    IBMCEPH-19406: RGW crash between head write and .meta delete.

    SIGKILLs RGW-A after GET 200 is confirmed (head durable) but .meta still
    present. Waits 125 s for TTL. Retry on RGW-B → data loss after GC.
    """
    try:
        loss = rgw_env._crash_ttl_retry("19406", versioning=False)
    except _Inconclusive as e:
        pytest.skip(str(e))
    if loss:
        pytest.fail(
            "IBMCEPH-19406 BUG CONFIRMED: data loss after crash between head-write"
            " and .meta-delete — HEAD 200 but GET returns 404/corrupt after GC"
        )


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19406v_crash_versioning_suspended(rgw_env):
    """
    IBMCEPH-19406v: Same crash scenario on a versioning-SUSPENDED bucket.

    Identical to 19406 but the bucket is put into Enabled→Suspended state
    before the upload. The retry overwrites the null-version slot.
    """
    try:
        loss = rgw_env._crash_ttl_retry("19406v", versioning=True)
    except _Inconclusive as e:
        pytest.skip(str(e))
    if loss:
        pytest.fail(
            "IBMCEPH-19406v BUG CONFIRMED: data loss on versioning-SUSPENDED bucket"
            " after crash between head-write and .meta-delete — HEAD 200 but GET"
            " returns 404/corrupt after GC"
        )


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19407_immediate_retry_after_meta_delete_failure(rgw_env):
    """
    IBMCEPH-19407: Immediate retry after .meta deletion failure (no TTL wait).

    Uses rgw_mp_lock_inject_delay (set at RGW-A startup via ceph config) to
    deterministically hold RGW-A in sub-window 3b: lock released, .meta not
    yet deleted. This gives a reliable SIGKILL window without GDB/debuginfo.

    Steps per JIRA reproduction:
      1. rgw_mp_lock_max_time=120, upload 8 parts (40 MB total).
      2. Fire CompleteMultipartUpload on RGW-A.
      3. Wait for GET 200 on RGW-B (head written, lock released).
      4. Verify: .meta present, lock cleared (0 lockers), gc_tails=0.
      5. SIGKILL RGW-A — lands in sub-window 3b guaranteed by inject_delay.
      6. Wait for RGW-A recovery.
      7. Retry CompleteMultipartUpload on RGW-B immediately (no TTL wait).
      8. Run GC. Oracle: HEAD 200, GET 404 → BUG CONFIRMED.

    Requires: ceph config set client.rgw rgw_mp_lock_inject_delay 30
              (set before test run so RGW-A starts with it observed)
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19407-{uuid.uuid4().hex[:8]}"; key = "mpu-obj"
    armed = []
    try:
        env.set_rgw("rgw_mp_lock_max_time", "120")
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        a.create_bucket(Bucket=bkt)
        uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        # Upload parts via RGW-B so parts survive RGW-A SIGKILL/restart
        parts = env.parts_upload(b, bkt, key, uid)
        log.info("bkt=%s uid=%s", bkt, uid)

        ra = {}; ev = threading.Event()

        def do_a():
            ev.set()
            ra["s"] = env.do_complete(a, bkt, key, uid, parts)

        t = threading.Thread(target=do_a, daemon=True)
        t.start(); ev.wait()

        # Step 3: wait until head is written, lock released, GET 200 readable on RGW-B.
        # rgw_mp_lock_inject_delay=30 holds RGW-A in the lock-held phase, so poll
        # until lock is actually released (lockers=0) AND GET is readable.
        log.info("waiting for GET 200 + lock released on RGW-B…")
        oid = None
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            # check GET readable
            try:
                o = b.get_object(Bucket=bkt, Key=key)
                data = o["Body"].read()
                if len(data) != env.num_parts * env.part_size:
                    time.sleep(0.5); continue
            except Exception:
                time.sleep(0.5); continue
            # GET ok — check lock state
            oid = env.find_meta(uid)
            if not oid:
                break  # .meta already gone — complete finished
            lock_raw = env.rados("-p", env.meta_pool, "lock", "info",
                                  oid, "RGWCompleteMultipart")
            try:
                lockers = json.loads(lock_raw).get("lockers", [])
            except Exception:
                lockers = ["unknown"]
            if not lockers:
                log.info("sub-window 3b: GET ok + lock released + .meta present")
                break
            time.sleep(0.3)

        if not oid:
            pytest.skip(".meta already deleted before kill — complete too fast")

        gc0 = env.gc_count(uid)
        log.info("pre-kill: .meta=%s lockers=%s gc_tails=%s", bool(oid), len(lockers), gc0)

        if lockers:
            pytest.skip(
                f"lock still held ({len(lockers)} lockers) after 240s — "
                "sub-window 3b not reached; check rgw_mp_lock_inject_delay setting"
            )

        # Step 4: arm ms_inject_delay NOW to stall the upcoming .meta delete_object call
        # (RGW-A is in the gap between lock release and .meta delete)
        env.asok_set("ms_inject_delay_max", 30);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        log.info("ms_inject_delay armed — SIGKILL RGW-A while stalled on .meta delete")

        # Step 5: SIGKILL RGW-A — stalled mid delete_object(.meta) = sub-window 3b
        env.kill_rgw_a(); t.join(timeout=10)

        # Step 6: wait for RGW-A recovery
        env.wait_rgw_a_healthy()

        h0, g0, _ = env.check(b, bkt, key)
        gc0b = env.gc_count(uid)
        oid2 = env.find_meta(uid)
        log.info("post-kill: HEAD=%s GET=%s gc_tails=%s .meta=%s", h0, g0, gc0b, bool(oid2))

        if g0 != 200:
            pytest.skip(f"post-kill GET={g0} (expected 200)")
        if not oid2:
            pytest.skip(".meta gone after restart — RGW cleaned it up on recovery")

        # Step 7: retry CompleteMultipartUpload on RGW-B immediately (no TTL wait)
        log.info("immediate retry CompleteMultipartUpload on RGW-B…")
        sb = env.do_complete(b, bkt, key, uid, parts)
        gc1 = env.gc_count(uid)
        log.info("retry=%s gc_tails=%s (was %s)", sb, gc1, gc0b)

        if sb == 500:
            pytest.skip("retry returned 500 — unexpected lock state on RGW-B")

        # Step 8: run GC and check for data loss
        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        exp = env.num_parts * env.part_size
        log.info("oracle: HEAD=%s GET=%s bytes=%s/%s", h, g, dl, exp)

        if h == 200 and (g != 200 or dl != exp):
            pytest.fail(
                f"IBMCEPH-19407 BUG CONFIRMED: data loss after .meta deletion failure"
                f" + immediate retry from second RGW"
                f" — HEAD={h} GET={g} bytes={dl}/{exp}"
                f" (gc_tails: {gc0}→{gc1})"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.reset_mp(); env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19410_lifecycle_abort_ignores_completion_lock(rgw_env):
    """
    IBMCEPH-19410: Lifecycle AbortMultipartUpload ignores completion lock.

    Same crash setup as 19406. Instead of a retry, fires AbortMultipartUpload
    after TTL lapse (simulating lifecycle expiry). Abort queues all tails for
    GC, destroying the completed object.
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19410-{uuid.uuid4().hex[:8]}"; key = "mpu-obj"
    armed = []
    try:
        env.set_rgw("rgw_mp_lock_max_time", "120")
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        a.create_bucket(Bucket=bkt)
        uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts = env.parts_upload(a, bkt, key, uid)
        log.info("bkt=%s uid=%s", bkt, uid)
        env.asok_set("ms_inject_delay_max", 10);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        ra = {}; ev = threading.Event()

        def do_a():
            ev.set()
            ra["s"] = env.do_complete(a, bkt, key, uid, parts)

        t = threading.Thread(target=do_a, daemon=True)
        t.start(); ev.wait()
        log.info("waiting for GET 200 full data…")
        if not env.wait_get_ok(b, bkt, key, 180):
            pytest.skip("GET never returned full data within 180 s")
        oid = env.find_meta(uid)
        if not oid:
            pytest.skip("No .meta OID")
        log.info("struck; .meta present → SIGKILL")
        env.kill_rgw_a(); t.join(timeout=10)
        env.wait_rgw_a_healthy()
        h0, g0, _ = env.check(b, bkt, key)
        gc0 = env.gc_count(uid)
        oid2 = env.find_meta(uid)
        log.info("pre-abort: HEAD=%s GET=%s gc_tails=%s .meta=%s",
                 h0, g0, gc0, bool(oid2))
        if g0 != 200:
            pytest.skip(f"pre-abort GET={g0}")
        if not oid2:
            pytest.skip(".meta already gone")
        log.info("waiting 125 s for lock TTL to lapse…")
        time.sleep(125)
        sa = env.http(lambda: b.abort_multipart_upload(
            Bucket=bkt, Key=key, UploadId=uid))
        gc1 = env.gc_count(uid)
        log.info("AbortMPU (LC sim) → %s  post-abort gc_tails=%s (was %s)",
                 sa, gc1, gc0)
        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        exp = env.num_parts * env.part_size
        log.info("oracle: HEAD=%s GET=%s bytes=%s", h, g, dl)
        if h == 200 and (g != 200 or dl != exp):
            pytest.fail(
                f"IBMCEPH-19410 BUG CONFIRMED: lifecycle AbortMultipartUpload"
                f" ignored completion lock and destroyed completed object"
                f" — HEAD={h} GET={g} bytes={dl}/{exp}"
                f" (gc_queue_tails: {gc0}→{gc1})"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.reset_mp(); env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


# ===========================================================================
# OVERWRITE / INDEX RACE TESTS  (marker: ibmceph_race)
# ===========================================================================

@pytest.mark.ibmceph_race
@pytest.mark.ibmceph_all
def test_19417_delete_racing_overwrite_no_id_tag_guard(rgw_env):
    """
    IBMCEPH-19417: DeleteObject races overwrite — missing RADOS ID-tag guard.

    Arms delay on RGW-A. Fires DELETE(A) and PUT(B) concurrently (50 ms
    stagger). The delayed DELETE removes the new head written by PUT(B).
    After GC: HEAD 404 GET 404.
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19417-{uuid.uuid4().hex[:8]}"; key = "idtag-obj"
    armed = []
    try:
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        a.create_bucket(Bucket=bkt)
        a.put_object(Bucket=bkt, Key=key, Body=b"orig" * 1024)
        env.asok_set("ms_inject_delay_max", 20);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        ds = {}; bs = {}; ev = threading.Event()

        def do_del():
            ev.set()
            ds["c"] = env.http(lambda: a.delete_object(Bucket=bkt, Key=key))

        def do_put():
            ev.wait(); time.sleep(0.05)
            bs["c"] = env.http(lambda: b.put_object(
                Bucket=bkt, Key=key, Body=b"NEW" * env.part_size))

        td = threading.Thread(target=do_del, daemon=True)
        tp = threading.Thread(target=do_put, daemon=True)
        td.start(); tp.start(); td.join(60); tp.join(60)
        log.info("DELETE(A)=%s PUT(B)=%s", ds.get("c"), bs.get("c"))
        env.asok_set("ms_inject_delay_probability", 0)
        env.asok_set("ms_inject_delay_max", 0)
        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        log.info("After GC: HEAD=%s GET=%s bytes=%s", h, g, dl)
        if bs.get("c") != 200 or ds.get("c") != 204:
            pytest.skip(
                f"Race did not materialise as expected:"
                f" PUT(B)={bs.get('c')} DELETE(A)={ds.get('c')}"
            )
        if h != 200 or g != 200:
            pytest.fail(
                f"IBMCEPH-19417 BUG CONFIRMED: racing DeleteObject wiped newly"
                f" PUT object — HEAD={h} GET={g} bytes={dl}"
                f" (missing RADOS ID-tag guard)"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


@pytest.mark.ibmceph_race
@pytest.mark.ibmceph_all
def test_19412_delete_racing_overwrite_leaks_tail(rgw_env):
    """
    IBMCEPH-19412: DeleteObject racing overwrite leaks the new object's tail.

    Uploads a 2-part MPU object (so there are tail RADOS objects). Arms delay
    on RGW-A. DELETE(A) reads old manifest then stalls; PUT(B) completes with
    a new head. DELETE removes new head and sends old manifest to GC — which
    collects the new object's tail. After GC: HEAD 404 GET 404.
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19412-{uuid.uuid4().hex[:8]}"; key = "race-obj"
    armed = []
    try:
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        a.create_bucket(Bucket=bkt)
        # upload 2-part MPU so there are tail objects to leak
        uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts = []
        for i in range(1, 3):
            r = a.upload_part(Bucket=bkt, Key=key, UploadId=uid,
                              PartNumber=i, Body=b"A" * env.part_size)
            parts.append({"PartNumber": i, "ETag": r["ETag"]})
        a.complete_multipart_upload(Bucket=bkt, Key=key, UploadId=uid,
                                    MultipartUpload={"Parts": parts})
        log.info("uploaded 2-part MPU object")
        env.asok_set("ms_inject_delay_max", 20);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        ds = {}; bs = {}; ev = threading.Event()

        def do_del():
            ev.set()
            ds["c"] = env.http(lambda: a.delete_object(Bucket=bkt, Key=key))

        def do_put():
            ev.wait(); time.sleep(0.05)
            bs["c"] = env.http(lambda: b.put_object(
                Bucket=bkt, Key=key, Body=b"NEW" * env.part_size))

        td = threading.Thread(target=do_del, daemon=True)
        tp = threading.Thread(target=do_put, daemon=True)
        td.start(); tp.start(); td.join(60); tp.join(60)
        log.info("DELETE(A)=%s PUT(B)=%s", ds.get("c"), bs.get("c"))
        env.asok_set("ms_inject_delay_probability", 0)
        env.asok_set("ms_inject_delay_max", 0)
        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        log.info("After GC: HEAD=%s GET=%s bytes=%s", h, g, dl)
        if bs.get("c") != 200 or ds.get("c") != 204:
            pytest.skip(
                f"Race did not materialise as expected:"
                f" PUT(B)={bs.get('c')} DELETE(A)={ds.get('c')}"
            )
        if h != 200 or g != 200:
            pytest.fail(
                f"IBMCEPH-19412 BUG CONFIRMED: racing DeleteObject leaked new"
                f" object's tail and wiped object — HEAD={h} GET={g} bytes={dl}"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


@pytest.mark.ibmceph_race
@pytest.mark.ibmceph_all
def test_19414_copy_to_itself_racing_overwrite_corrupts_data(rgw_env):
    """
    IBMCEPH-19414: CopyObject-to-itself racing overwrite can delete object data.

    Uploads a 2-part MPU. Arms delay on RGW-A. Copy-to-itself reads source
    manifest then stalls; PUT(B) overwrites with new head+tail. Copy writes
    old manifest back into head guarded on new ID tag. GC follows old manifest
    and deletes PUT(B)'s tail. After GC: HEAD 200 GET 404 bytes=0.
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19414-{uuid.uuid4().hex[:8]}"; key = "copy-self"
    armed = []
    try:
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        a.create_bucket(Bucket=bkt)
        uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts = []
        for i in range(1, 3):
            r = a.upload_part(Bucket=bkt, Key=key, UploadId=uid,
                              PartNumber=i, Body=b"O" * env.part_size)
            parts.append({"PartNumber": i, "ETag": r["ETag"]})
        a.complete_multipart_upload(Bucket=bkt, Key=key, UploadId=uid,
                                    MultipartUpload={"Parts": parts})
        log.info("uploaded 2-part source object")
        env.asok_set("ms_inject_delay_max", 20);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        cs = {}; ps = {}; ev = threading.Event()
        put_size = env.part_size * 4

        def do_copy():
            ev.set()
            cs["c"] = env.http(lambda: a.copy_object(
                Bucket=bkt, Key=key,
                CopySource={"Bucket": bkt, "Key": key},
                MetadataDirective="REPLACE",
                Metadata={"x-amz-meta-t": "v"},
            ))

        def do_put():
            ev.wait(); time.sleep(0.1)
            ps["c"] = env.http(lambda: b.put_object(
                Bucket=bkt, Key=key, Body=b"N" * put_size))

        tc = threading.Thread(target=do_copy, daemon=True)
        tp = threading.Thread(target=do_put, daemon=True)
        tc.start(); tp.start(); tc.join(60); tp.join(60)
        log.info("COPY-SELF(A)=%s PUT(B)=%s", cs.get("c"), ps.get("c"))
        env.asok_set("ms_inject_delay_probability", 0)
        env.asok_set("ms_inject_delay_max", 0)
        # run GC twice with extra pause
        env.run_gc()
        time.sleep(5)
        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        log.info("After GC: HEAD=%s GET=%s bytes=%s expected=%s", h, g, dl, put_size)
        if ps.get("c") != 200:
            pytest.skip(f"PUT(B) did not return 200 (got {ps.get('c')}) — race not set up")
        if h == 200 and (g != 200 or dl < put_size):
            pytest.fail(
                f"IBMCEPH-19414 BUG CONFIRMED: CopyObject-self racing overwrite"
                f" corrupted object data — HEAD={h} GET={g} bytes={dl}/{put_size}"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


@pytest.mark.ibmceph_race
@pytest.mark.ibmceph_all
def test_19416_stalled_write_lost_from_bucket_index(rgw_env):
    """
    IBMCEPH-19416: Write stalled past pending-op expiry is lost from bucket index.

    Sets rgw_pending_bucket_index_op_expiration=5 on OSDs. Arms delay (30 s)
    on RGW-A. Starts a PUT in background. After 8 s, triggers ListObjectsV2 on
    RGW-B — this expires the pending op and rewrites the index from the old head.
    After PUT completes: HeadObject shows new ETag but ListObjectsV2 shows old ETag.
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19416-{uuid.uuid4().hex[:8]}"; key = "stalled-obj"
    armed = []
    try:
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")
        env.ceph("config", "set", "osd",
                 "rgw_pending_bucket_index_op_expiration", "5")
        a.create_bucket(Bucket=bkt)
        a.put_object(Bucket=bkt, Key=key, Body=b"old-data")
        old_etag = a.head_object(Bucket=bkt, Key=key)["ETag"].strip('"')
        log.info("old ETag: %s", old_etag)
        env.asok_set("ms_inject_delay_max", 30);  armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1); armed.append(("ms_inject_delay_probability", 0))
        pa = {}; ev = threading.Event()

        def do_stalled_put():
            ev.set()
            pa["c"] = env.http(lambda: a.put_object(
                Bucket=bkt, Key=key, Body=b"new-stalled-data"))

        ta = threading.Thread(target=do_stalled_put, daemon=True)
        ta.start(); ev.wait()
        # wait 8 s then list — pending op is now older than 5 s expiry
        time.sleep(8)
        list_resp = b.list_objects_v2(Bucket=bkt)
        index_etag_during = next(
            (o.get("ETag", "").strip('"') for o in list_resp.get("Contents", [])
             if o["Key"] == key), None)
        log.info("ListObjectsV2 ETag during stall: %s", index_etag_during)
        ta.join(90)
        env.asok_set("ms_inject_delay_probability", 0)
        env.asok_set("ms_inject_delay_max", 0)
        log.info("PUT-A=%s", pa.get("c"))
        head_etag = a.head_object(Bucket=bkt, Key=key)["ETag"].strip('"')
        list_etag_after = next(
            (o.get("ETag", "").strip('"')
             for o in b.list_objects_v2(Bucket=bkt).get("Contents", [])
             if o["Key"] == key), None)
        log.info("HeadObject ETag after PUT: %s", head_etag)
        log.info("ListObjectsV2 ETag after PUT: %s", list_etag_after)
        if pa.get("c") != 200:
            pytest.skip(f"PUT-A did not return 200 (got {pa.get('c')}) — race not set up")
        if head_etag == old_etag:
            pytest.skip("HeadObject still shows old ETag — stall delay may not have held long enough")
        if list_etag_after == old_etag:
            pytest.fail(
                f"IBMCEPH-19416 BUG CONFIRMED: stalled write lost from bucket index"
                f" — HeadObject ETag={head_etag} (new) but ListObjectsV2 still"
                f" shows old ETag={list_etag_after}"
            )
    finally:
        for k, v in reversed(armed):
            try: env.asok_set(k, v)
            except Exception: pass
        env.ceph("config", "rm", "osd", "rgw_pending_bucket_index_op_expiration")
        env.reset_gc()
        try: b.delete_object(Bucket=bkt, Key=key); b.delete_bucket(Bucket=bkt)
        except Exception: pass


# ===========================================================================
# MULTIPART BLOCKLIST RACE TEST  (marker: ibmceph_mpu)
# ===========================================================================

@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19407bl_meta_delete_fail_blocklist_retry(rgw_env):
    """
    IBMCEPH-19407 (blocklist variant): .meta deletion failure forces data loss
    on retry from a second RGW.

    Instead of SIGKILL (too coarse), this test uses OSD blocklisting to
    deterministically force meta_obj->delete_object() to fail with -EACCES:

      1. Upload 8-part MPU on RGW-A.
      2. Set a short lock TTL (bl_lock_ttl, default 30 s).
      3. Arm ms_inject_delay (prob=1, max=10 s) to widen the race window.
      4. Fire CompleteMultipartUpload on RGW-A in a background thread.
      5. Poll until HEAD 200 visible on RGW-B AND .meta still present in pool.
      6. Blocklist RGW-A RADOS addr(s) for bl_secs (default 40 s).
         => meta_obj->delete_object() fails with -EACCES
         => RGW-A's CMU thread stalls / returns error; lock expires after TTL
      7. Disarm delay; wait for blocklist auto-expiry; restore RGW-A health.
      8. Assert: .meta still present, lock expired (0 lockers).
      9. Immediate retry on RGW-B — returns 200, enqueues GC tasks.
     10. Run GC. Oracle: HEAD=200 GET=404 bytes=0 → data loss confirmed.

    Confirmed reproduced on grim017 (ceph-20.2.2-338.el10cp):
      oracle: HEAD=200 GET=404 bytes=0/41943040 dataloss=True
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19407bl-{uuid.uuid4().hex[:8]}"; key = "mpu-obj"
    armed = []; blocklisted = []

    try:
        env.set_rgw("rgw_mp_lock_max_time", str(env.bl_lock_ttl))
        env.set_rgw("rgw_gc_obj_min_wait", "5")
        env.set_rgw("rgw_gc_processor_period", "1")

        a.create_bucket(Bucket=bkt)
        uid = a.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts = env.parts_upload(a, bkt, key, uid)
        log.info("bkt=%s uid=%s", bkt, uid)

        # Resolve RGW-A RADOS addrs BEFORE arming delay (servicemap may stall)
        rgw_a_addrs = env.get_rgw_a_addrs()
        if not rgw_a_addrs:
            pytest.skip("RGW-A RADOS addr not found in servicemap — skip")

        log.info("RGW-A RADOS addr(s): %s", rgw_a_addrs)

        env.asok_set("ms_inject_delay_max", 10)
        armed.append(("ms_inject_delay_max", 0))
        env.asok_set("ms_inject_delay_probability", 1)
        armed.append(("ms_inject_delay_probability", 0))

        ra = {}; ev = threading.Event()

        def do_a():
            ev.set()
            ra["s"] = env.do_complete(a, bkt, key, uid, parts)

        t = threading.Thread(target=do_a, daemon=True)
        t.start(); ev.wait()

        # Poll: HEAD 200 on RGW-B + .meta still present in pool
        log.info("polling for HEAD 200 + .meta present…")
        meta_oid = None
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                b.head_object(Bucket=bkt, Key=key)
                oid = env.find_meta(uid)
                if oid:
                    meta_oid = oid
                    break
            except Exception:
                pass
            time.sleep(0.1)

        if not meta_oid:
            t.join(timeout=120)
            pytest.skip("HEAD-ok + .meta window not caught within 180 s")

        log.info("struck: HEAD=200 + .meta present (%s)", meta_oid)

        # Blocklist all RGW-A RADOS addrs for bl_secs
        t_bl = time.monotonic()
        for addr in rgw_a_addrs:
            ok = env.blocklist_add(addr, env.bl_secs)
            if ok:
                blocklisted.append(addr)

        # Disarm delay — blocklist now holds the barrier
        env.asok_set("ms_inject_delay_probability", 0)
        env.asok_set("ms_inject_delay_max", 0)
        armed.clear()

        # CMU thread will fail / timeout due to blocklist
        t.join(timeout=20)
        log.info("CMU(A) returned: %s", ra.get("s", "still-running"))

        # Wait for blocklist to auto-expire
        elapsed = time.monotonic() - t_bl
        remain = env.bl_secs - elapsed + 2
        if remain > 0:
            log.info("waiting %.0fs for blocklist to expire…", remain)
            time.sleep(remain)

        # Clear any remaining blocklist entries
        for addr in list(blocklisted):
            env.blocklist_rm(addr)
            blocklisted.remove(addr)

        # Wait for RGW-A to recover (it may have restarted)
        log.info("waiting for RGW-A to recover…")
        recovered = env.wait_rgw_healthy(env.rgw_a_url, timeout=60)
        log.info("RGW-A healthy: %s", recovered)

        # Verify state
        h0, g0, _ = env.check(b, bkt, key)
        gc0 = env.gc_count(uid)
        oid2 = env.find_meta(uid)
        lock_raw = env.rados("-p", env.meta_pool, "lock", "info",
                             oid2, "RGWCompleteMultipart") if oid2 else ""
        try:
            lockers = json.loads(lock_raw).get("lockers", [])
        except Exception:
            lockers = []
        log.info("post-bl: HEAD=%s GET=%s gc_tails=%s .meta=%s lockers=%s",
                 h0, g0, gc0, bool(oid2), len(lockers))

        if not oid2:
            pytest.skip(".meta deleted despite blocklist — delete completed before blocklist took effect")
        if g0 != 200:
            pytest.skip(f"pre-retry GET={g0} (expected 200)")

        # If lock still held, wait for TTL to expire
        if lockers:
            log.info("lock still held — waiting %ss for TTL…", env.bl_lock_ttl)
            time.sleep(env.bl_lock_ttl + 5)
            lock_raw2 = env.rados("-p", env.meta_pool, "lock", "info",
                                  oid2, "RGWCompleteMultipart")
            try:
                lockers = json.loads(lock_raw2).get("lockers", [])
            except Exception:
                lockers = []
            if lockers:
                pytest.skip("lock still held after TTL wait — cannot retry")

        # Immediate retry on RGW-B (lock expired, .meta present)
        log.info("immediate retry CompleteMultipartUpload on RGW-B…")
        sb = env.do_complete(b, bkt, key, uid, parts)
        gc1 = env.gc_count(uid)
        log.info("retry=%s  gc_tails=%s (was %s)", sb, gc1, gc0)

        env.run_gc()
        h, g, dl = env.check(b, bkt, key)
        exp = env.num_parts * env.part_size
        log.info("oracle: HEAD=%s GET=%s bytes=%s/%s", h, g, dl, exp)

        if h == 200 and (g != 200 or dl != exp):
            pytest.fail(
                f"IBMCEPH-19407bl BUG CONFIRMED: .meta deletion failure via OSD"
                f" blocklist + retry from second RGW caused data loss"
                f" — HEAD={h} GET={g} bytes={dl}/{exp}"
            )

    finally:
        for k, v in reversed(armed):
            try:
                env.asok_set(k, v)
            except Exception:
                pass
        for addr in list(blocklisted):
            try:
                env.blocklist_rm(addr)
            except Exception:
                pass
        env.reset_mp()
        env.reset_gc()
        try:
            b.delete_object(Bucket=bkt, Key=key)
            b.delete_bucket(Bucket=bkt)
        except Exception:
            pass


# ===========================================================================
# ETAG PREFIX MATCH BUG TEST  (marker: ibmceph_cond)
# ===========================================================================

@pytest.mark.ibmceph_cond
@pytest.mark.ibmceph_all
def test_19423_if_match_accepts_etag_prefix(rgw_env):
    """
    IBMCEPH-19423: RGW If-Match and If-None-Match match any value that
    starts with the object's ETag (prefix comparison instead of equality).

    Per RFC 7232, If-Match must compare entity tags using full equality
    (or weak comparison for If-None-Match). A value of "<etag>suffix"
    must NOT match — it should return 412 PreconditionFailed.

    Bug: RGW uses a prefix check so "<etag>EXTRA" passes If-Match and
    fails If-None-Match — both wrong.

    Tests:
      A) GET with full ETag           → 200  (correct)
      B) GET with ETag + suffix       → must be 412 (was 200 on buggy build)
      C) PUT with full ETag If-Match  → 200  (correct)
      D) PUT with ETag + suffix       → must be 412 (was 200 on buggy build)
      E) GET with If-None-Match full  → must be 304 (correct)
      F) GET with If-None-Match + sfx → must be 200 (was 304 on buggy build)
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19423-{uuid.uuid4().hex[:8]}"; key = "etag-prefix-obj"

    try:
        a.create_bucket(Bucket=bkt)
        r0 = a.put_object(Bucket=bkt, Key=key, Body=b"hello-etag-prefix")
        etag = r0.get("ETag", "").strip('"')
        log.info("object ETag: %s", etag)

        suffix_etag = etag + "EXTRA"
        bugs = []

        # A) GET with exact ETag — must be 200
        try:
            r = a.get_object(Bucket=bkt, Key=key, IfMatch=etag)
            code_a = r["ResponseMetadata"]["HTTPStatusCode"]
        except ClientError as e:
            code_a = e.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info("A) GET If-Match=exact → %s (expect 200)", code_a)
        if code_a != 200:
            bugs.append(f"A) GET exact etag returned {code_a} (want 200)")

        # B) GET with ETag+suffix — must be 412
        try:
            r = a.get_object(Bucket=bkt, Key=key, IfMatch=suffix_etag)
            code_b = r["ResponseMetadata"]["HTTPStatusCode"]
            r["Body"].read()
        except ClientError as e:
            code_b = e.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info("B) GET If-Match=etag+suffix → %s (expect 412)", code_b)
        if code_b != 412:
            bugs.append(f"B) GET etag+suffix returned {code_b} (want 412) — prefix match bug")

        # C) PUT with exact ETag If-Match — must be 200
        try:
            r = a.put_object(Bucket=bkt, Key=key, Body=b"put-exact",
                             **{"IfMatch": etag})
            code_c = r["ResponseMetadata"]["HTTPStatusCode"]
            # restore original content
            a.put_object(Bucket=bkt, Key=key, Body=b"hello-etag-prefix")
            etag = a.head_object(Bucket=bkt, Key=key)["ETag"].strip('"')
        except ClientError as e:
            code_c = e.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info("C) PUT If-Match=exact → %s (expect 200)", code_c)
        if code_c != 200:
            pytest.skip(f"If-Match on PUT not supported (got {code_c}) — skip")

        # D) PUT with ETag+suffix — must be 412
        try:
            r = a.put_object(Bucket=bkt, Key=key, Body=b"put-suffix",
                             **{"IfMatch": suffix_etag})
            code_d = r["ResponseMetadata"]["HTTPStatusCode"]
        except ClientError as e:
            code_d = e.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info("D) PUT If-Match=etag+suffix → %s (expect 412)", code_d)
        if code_d != 412:
            bugs.append(f"D) PUT etag+suffix returned {code_d} (want 412) — prefix match bug")

        # E) GET with If-None-Match exact ETag — must be 304
        try:
            r = a.get_object(Bucket=bkt, Key=key, IfNoneMatch=etag)
            code_e = r["ResponseMetadata"]["HTTPStatusCode"]
            r["Body"].read()
        except ClientError as e:
            code_e = e.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info("E) GET If-None-Match=exact → %s (expect 304)", code_e)
        if code_e != 304:
            bugs.append(f"E) GET If-None-Match exact returned {code_e} (want 304)")

        # F) GET with If-None-Match ETag+suffix — must be 200 (no match → return body)
        try:
            r = a.get_object(Bucket=bkt, Key=key, IfNoneMatch=suffix_etag)
            code_f = r["ResponseMetadata"]["HTTPStatusCode"]
            r["Body"].read()
        except ClientError as e:
            code_f = e.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info("F) GET If-None-Match=etag+suffix → %s (expect 200)", code_f)
        if code_f != 200:
            bugs.append(f"F) GET If-None-Match etag+suffix returned {code_f} (want 200) — prefix match bug")

        log.info("results: A=%s B=%s C=%s D=%s E=%s F=%s", code_a, code_b, code_c, code_d, code_e, code_f)

        if bugs:
            pytest.fail(
                f"IBMCEPH-19423 BUG CONFIRMED: If-Match/If-None-Match prefix comparison — "
                + "; ".join(bugs)
            )

    finally:
        try:
            a.delete_object(Bucket=bkt, Key=key)
            a.delete_bucket(Bucket=bkt)
        except Exception:
            pass


# ===========================================================================
# CONDITIONAL WRITE ATOMICITY TEST  (marker: ibmceph_cond)
# ===========================================================================

@pytest.mark.ibmceph_cond
@pytest.mark.ibmceph_all
def test_19424_concurrent_conditional_puts_not_atomic(rgw_env):
    """
    IBMCEPH-19424: Concurrent conditional PUTs in a versioning-enabled bucket
    are not atomic.

    In a versioning-enabled bucket, a PutObject with If-None-Match: * checks
    the condition, writes a new version, and only then makes it current —
    with no atomic guard. Two concurrent PUTs with If-None-Match: * on an
    empty key, or If-Match on the same ETag, can both win.

    S3 semantics: only ONE should succeed (HTTP 200); all others → 412.

    This test fires 8 concurrent PUT requests (4 on RGW-A, 4 on RGW-B)
    each with If-Match set to the same initial ETag on a versioned bucket.

    Confirmed reproduced on grim017 (ceph-20.2.2-338.el10cp):
      200 OK: 8   412: 0   (all 8 won; only 1 should have)
      Total versions: 9 (v0 + 8 concurrent winners)

    Also tests If-None-Match: * on a new key (only 1 of N concurrent
    creates should succeed).
    """
    env = rgw_env
    a = env.a(); b = env.b()
    bkt = f"ibm19424-{uuid.uuid4().hex[:8]}"; key = "if-match-obj"
    CONCURRENT = 8

    try:
        # Versioning-ENABLED bucket (bug is specific to versioned path)
        a.create_bucket(Bucket=bkt)
        a.put_bucket_versioning(
            Bucket=bkt,
            VersioningConfiguration={"Status": "Enabled"},
        )
        log.info("bucket versioning enabled")

        # --- Part 1: If-Match on existing ETag ---
        r0 = a.put_object(Bucket=bkt, Key=key, Body=b"INITIAL")
        etag = r0.get("ETag", "").strip('"')
        log.info("initial ETag: %s", etag)

        # Pre-check: verify If-Match on PUT is supported (skip if not)
        code_precheck = env.http(lambda: a.put_object(
            Bucket=bkt, Key=key,
            Body=b"PRE-CHECK",
            **{"IfMatch": "nonexistent-etag-000"},
        ))
        if code_precheck not in (412, 200):
            pytest.skip(f"If-Match not supported on this build (got {code_precheck}) — skip")

        codes = [None] * CONCURRENT
        ready = threading.Barrier(CONCURRENT)

        def do_put(idx):
            ready.wait()
            client = a if idx % 2 == 0 else b
            try:
                r2 = client.put_object(
                    Bucket=bkt, Key=key,
                    Body=f"concurrent-body-{idx}".encode() * 1024,
                    **{"IfMatch": etag},
                )
                codes[idx] = r2["ResponseMetadata"]["HTTPStatusCode"]
            except ClientError as e:
                codes[idx] = e.response["ResponseMetadata"]["HTTPStatusCode"]
            except Exception:
                codes[idx] = -1

        threads = [threading.Thread(target=do_put, args=(i,), daemon=True)
                   for i in range(CONCURRENT)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        successes = [c for c in codes if c == 200]
        failures  = [c for c in codes if c == 412]
        others    = [c for c in codes if c not in (200, 412)]
        log.info("If-Match results: %s", codes)
        log.info("200s=%d  412s=%d  other=%s", len(successes), len(failures), others)

        versions = a.list_object_versions(Bucket=bkt, Prefix=key)
        version_count = len(versions.get("Versions", []))
        log.info("total versions after If-Match test: %d", version_count)

        if len(successes) > 1:
            pytest.fail(
                f"IBMCEPH-19424 BUG CONFIRMED (If-Match, versioned bucket): "
                f"{len(successes)}/{CONCURRENT} concurrent If-Match writes succeeded"
                f" (at most 1 should); versions created={version_count}"
            )

        # --- Part 2: If-None-Match: * on new key (create-once semantics) ---
        key2 = "if-none-match-new-obj"
        codes2 = [None] * CONCURRENT
        ready2 = threading.Barrier(CONCURRENT)

        def do_put2(idx):
            ready2.wait()
            client = a if idx % 2 == 0 else b
            try:
                r3 = client.put_object(
                    Bucket=bkt, Key=key2,
                    Body=f"create-once-{idx}".encode() * 1024,
                    **{"IfNoneMatch": "*"},
                )
                codes2[idx] = r3["ResponseMetadata"]["HTTPStatusCode"]
            except ClientError as e:
                codes2[idx] = e.response["ResponseMetadata"]["HTTPStatusCode"]
            except Exception:
                codes2[idx] = -1

        threads2 = [threading.Thread(target=do_put2, args=(i,), daemon=True)
                    for i in range(CONCURRENT)]
        for t in threads2:
            t.start()
        for t in threads2:
            t.join(timeout=60)

        successes2 = [c for c in codes2 if c == 200]
        log.info("If-None-Match:* results: %s", codes2)
        log.info("200s=%d  412s=%d", len(successes2), len([c for c in codes2 if c == 412]))

        versions2 = a.list_object_versions(Bucket=bkt, Prefix=key2)
        version_count2 = len(versions2.get("Versions", []))
        log.info("total versions after If-None-Match test: %d", version_count2)

        if len(successes2) > 1:
            pytest.fail(
                f"IBMCEPH-19424 BUG CONFIRMED (If-None-Match:*, versioned bucket): "
                f"{len(successes2)}/{CONCURRENT} concurrent If-None-Match:* writes succeeded"
                f" (at most 1 should); versions created={version_count2}"
            )

        log.info(
            "PASS: If-Match=%d/%d winners, If-None-Match:*=%d/%d winners (correct)",
            len(successes), CONCURRENT, len(successes2), CONCURRENT,
        )

    finally:
        try:
            versions = a.list_object_versions(Bucket=bkt)
            for v in versions.get("Versions", []):
                a.delete_object(Bucket=bkt, Key=v["Key"], VersionId=v["VersionId"])
            for dm in versions.get("DeleteMarkers", []):
                a.delete_object(Bucket=bkt, Key=dm["Key"], VersionId=dm["VersionId"])
            a.delete_bucket(Bucket=bkt)
        except Exception:
            pass
