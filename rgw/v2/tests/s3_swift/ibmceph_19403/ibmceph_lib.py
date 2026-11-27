# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
ibmceph_lib.py - shared helpers for the IBMCEPH-19403 RGW race/data-loss suite.

The helpers are lifted from the per-Jira reproducers (apple-ms/IBMCEPH-<id>/
repro_<id>.py) so that every test drives the cluster the same way:

  * ceph / radosgw-admin / rados run through `cephadm shell` on the admin node
    (ceph_cli: cephadm) or directly (ceph_cli: local).
  * RGW-A is the daemon the races are forced on.  Host-level work on it (gdb,
    podman, journalctl) runs over ssh, or locally when rgw_a_host is empty.
    RGW-B is the second daemon, used for the competing request.
  * gdb stands in for the injection points of the upstream Jiras
    (write_meta_before_head_write, delete_obj_before_head_delete, ...).  It
    stops RGW-A at a function, waits for a flag file, then detaches.

Test semantics (pytest):
  PASSED  - the fixed behaviour was observed (and the control behaved).
  FAILED  - the bug was reproduced, or a control behaved unexpectedly.
  SKIPPED - the race window was not reached (inconclusive, run again).
"""

import contextlib
import json
import logging
import os
import shlex
import subprocess
import threading
import time
import uuid

import boto3
import pytest
import yaml
from botocore.config import Config

log = logging.getLogger(__name__)

GDB_BIN = "/root/ibmceph_radosgw.bin"


class Cfg:
    """YAML config with upper-case environment variable fallbacks."""

    def __init__(self, path):
        self._d = {}
        if path and os.path.exists(path):
            with open(path) as f:
                self._d = yaml.safe_load(f) or {}

    def get(self, key, default=None):
        return self._d.get(key, os.environ.get(key.upper(), default))


def code_of(exc):
    """HTTP status carried by a botocore exception, else a short repr."""
    resp = getattr(exc, "response", None)
    if resp:
        return resp.get("ResponseMetadata", {}).get("HTTPStatusCode", repr(exc)[:80])
    return repr(exc)[:80]


def status_of(fn):
    """Run fn() and return its HTTP status (200 if there is no metadata)."""
    try:
        r = fn()
        if isinstance(r, dict):
            return r.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
        return 200
    except Exception as e:
        return code_of(e)


def inconclusive(msg):
    """The race window was not reached: report SKIPPED, not PASSED or FAILED."""
    log.warning("INCONCLUSIVE: %s", msg)
    pytest.skip(msg)


def hold_script(go_file, breakpoint, msg, ignore=0, temporary=False):
    """gdb script: stop at `breakpoint`, wait for `go_file`, then detach."""
    bp = "tbreak" if temporary else "break"
    lines = [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending off",
        f"{bp} {breakpoint}",
    ]
    if ignore:
        lines.append(f"ignore 1 {ignore}")
    lines += [
        "commands",
        "silent",
        f'printf "HOLD: {msg}; waiting for release flag\\n"',
        f"shell n=0; while [ ! -f {go_file} ] && [ $n -lt 180 ]; "
        "do sleep 1; n=$((n+1)); done",
        'printf "RELEASE: continuing\\n"',
        "detach",
        "quit",
        "end",
        "continue",
    ]
    return "\n".join(lines) + "\n"


def inject_script(breakpoint, retval, msg):
    """gdb script: make the first call of `breakpoint` return `retval`."""
    lines = [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending off",
        f"tbreak {breakpoint}",
        "commands",
        "silent",
        f'printf "INJECT: {msg}\\n"',
        f"return (int){retval}",
        "detach",
        "quit",
        "end",
        "continue",
    ]
    return "\n".join(lines) + "\n"


class Held:
    """A client request that RGW-A is holding inside gdb."""

    def __init__(self, tag):
        self.tag = tag
        self.res = {}
        self.thread = None

    @property
    def status(self):
        return self.res.get("status")


class Env:
    """Connection details plus every low-level helper the tests use."""

    def __init__(self, cfg):
        g = cfg.get
        self.cfg = cfg
        self.a_url = g("rgw_a_url", "http://127.0.0.1:80")
        self.b_url = g("rgw_b_url", "http://127.0.0.1:81")
        self.access_key = g("access_key", "")
        self.secret_key = g("secret_key", "")
        self.data_pool = g("data_pool", "default.rgw.buckets.data")
        self.meta_pool = g("meta_pool", "default.rgw.buckets.non-ec")
        self.index_pool = g("index_pool", "default.rgw.buckets.index")
        self.cli = g("ceph_cli", "cephadm")
        self.cephadm_args = shlex.split(g("cephadm_args", ""))
        self.a_host = g("rgw_a_host", "")
        self.b_host = g("rgw_b_host", "")
        self.ssh_user = g("ssh_user", "root")
        self.ssh_key = g("ssh_key", "")
        self.ssh_sudo = str(g("ssh_sudo", "")).lower() in ("1", "true", "yes")
        self.a_daemon = g("rgw_a_daemon", "")
        self.b_daemon = g("rgw_b_daemon", "")
        self.a_container = g("rgw_a_container", "")
        self.a_unit = g("rgw_a_unit", "")
        self.b_unit = g("rgw_b_unit", "")
        self.part_size = int(g("part_size", 5 * 1024 * 1024))
        self.num_parts = int(g("num_parts", 8))
        self.obj_size = int(g("obj_size", 8 * 1024 * 1024))
        self.lock_max_time = int(g("lock_max_time", 120))
        self.gc_min_wait = int(g("gc_min_wait", 30))
        self.outdir = g("outdir", "/tmp/ibmceph_19403")
        self._bin_ready = False
        self._tags = set()
        self._socks = {}
        os.makedirs(self.outdir, exist_ok=True)

    # ── command runners ─────────────────────────────────────────────────────

    def sh(self, cmd, timeout=150):
        """Run a ceph / rados / radosgw-admin command line; return stdout."""
        if self.cli == "cephadm":
            argv = ["cephadm", "shell", *self.cephadm_args, "--", "bash", "-c", cmd]
        else:
            argv = ["bash", "-c", cmd]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.stdout

    def host(self, side, cmd, timeout=120):
        """Run a shell command on the host of RGW-A ('a') or RGW-B ('b')."""
        target = self.a_host if side == "a" else self.b_host
        if target:
            argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
            if self.ssh_key:
                argv += ["-i", self.ssh_key]
            if self.ssh_sudo:
                cmd = f"sudo -n bash -c {shlex.quote(cmd)}"
            argv += [f"{self.ssh_user}@{target}", cmd]
        else:
            argv = ["bash", "-c", cmd]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()

    def cfg_set(self, who, key, value):
        self.sh(f"ceph config set {who} {key} {value}")

    def cfg_rm(self, who, key):
        self.sh(f"ceph config rm {who} {key}")

    def orch_name(self, side):
        daemon = self.a_daemon if side == "a" else self.b_daemon
        return daemon[len("client.") :]

    def url(self, side):
        return self.a_url if side == "a" else self.b_url

    # ── S3 ──────────────────────────────────────────────────────────────────

    def s3(self, url, read_timeout=300):
        return boto3.client(
            "s3",
            endpoint_url=url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name="us-east-1",
            config=Config(
                retries={"max_attempts": 1},
                read_timeout=read_timeout,
                connect_timeout=5,
                s3={"addressing_style": "path"},
            ),
        )

    def a(self):
        return self.s3(self.a_url)

    def b(self):
        return self.s3(self.b_url)

    def wait_rgw(self, side, timeout=420):
        c = self.s3(self.url(side), read_timeout=10)
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                c.list_buckets()
                return True
            except Exception:
                time.sleep(5)
        return False

    def restart(self, side, timeout=420):
        """Restart an RGW through the orchestrator and wait until it answers."""
        self.sh(f"ceph orch daemon restart {self.orch_name(side)} --force")
        time.sleep(30)
        if not self.wait_rgw(side, timeout):
            inconclusive(f"RGW {side} did not come back within {timeout}s")

    @contextlib.contextmanager
    def configs(self, items, restart=(), timeout=420):
        """Set (who, key, value) configs; always remove them (and restart)."""
        try:
            for who, key, value in items:
                self.cfg_set(who, key, value)
            for side in restart:
                self.restart(side, timeout)
            yield
        finally:
            self.gdb_stop()
            for who, key, _ in items:
                self.cfg_rm(who, key)
            for side in restart:
                self.sh(f"ceph orch daemon restart {self.orch_name(side)} --force")
            if restart:
                # the old daemon still answers until the orchestrator stops it;
                # without this pause the next test arms gdb on a dying daemon
                time.sleep(30)
            for side in restart:
                self.wait_rgw(side, timeout)

    def gc_config(self):
        return [("global", "rgw_gc_obj_min_wait", self.gc_min_wait)]

    def lock_config(self):
        return [
            (self.a_daemon, "rgw_mp_lock_max_time", self.lock_max_time),
            (self.b_daemon, "rgw_mp_lock_max_time", self.lock_max_time),
        ]

    # ── RADOS / bucket state ────────────────────────────────────────────────

    def marker_of(self, bucket):
        out = self.sh(f"radosgw-admin bucket stats --bucket {bucket}")
        return json.loads(out)["marker"]

    def bucket_objs(self, marker):
        out = self.sh(f"rados -p {self.data_pool} ls")
        return sorted(ln for ln in out.splitlines() if ln.startswith(marker + "_"))

    @staticmethod
    def short(objs, marker):
        return [o[len(marker) :] for o in objs]

    def gc_count(self):
        out = self.sh("radosgw-admin gc list --include-all | grep -c '\"oid\"'")
        return int(out.strip() or 0)

    def gc_and_list(self, marker):
        """Wait out rgw_gc_obj_min_wait, run GC, return the bucket's RADOS objects."""
        time.sleep(self.gc_min_wait + 5)
        self.sh("radosgw-admin gc process --include-all")
        time.sleep(5)
        return self.bucket_objs(marker)

    def meta_oid(self, upload_id):
        """'<namespace>\\t<oid>' of the upload's .meta object, or None."""
        for ln in self.sh(f"rados -p {self.meta_pool} --all ls").splitlines():
            if upload_id in ln and ln.endswith(".meta"):
                return ln
        return None

    def _lock_base(self, oid):
        ns, _, name = oid.rpartition("\t")
        return f"rados -p {self.meta_pool} -N '{ns}'", name

    def lockers(self, oid):
        base, name = self._lock_base(oid)
        out = []
        locks = json.loads(self.sh(f"{base} lock list '{name}'") or "{}")
        for ln in [x["name"] for x in locks.get("locks", [])]:
            info = json.loads(self.sh(f"{base} lock info '{name}' '{ln}'") or "{}")
            out += info.get("lockers", [])
        return out

    def drop_meta_lock(self, upload_id):
        """Break the cls lock on the .meta object; True only if lockers are gone."""
        oid = self.meta_oid(upload_id)
        if not oid:
            return False
        base, name = self._lock_base(oid)
        locks = json.loads(self.sh(f"{base} lock list '{name}'") or "{}")
        for ln in [x["name"] for x in locks.get("locks", [])]:
            info = json.loads(self.sh(f"{base} lock info '{name}' '{ln}'") or "{}")
            for lk in info.get("lockers", []):
                out = self.sh(
                    f"{base} lock break '{name}' '{ln}' '{lk['name']}' "
                    f"--lock-cookie '{lk['cookie']}' 2>&1"
                )
                log.info("lock break %s %s -> %s", ln, lk["name"], out.strip() or "ok")
            left = json.loads(self.sh(f"{base} lock info '{name}' '{ln}'") or "{}")
            return not left.get("lockers", [])
        return False

    def purge(self, objs):
        for o in objs:
            self.sh(f"rados -p {self.data_pool} rm '{o}'")

    @contextlib.contextmanager
    def bucket(self, client, prefix):
        """Create a bucket; on exit delete its keys, the bucket and leaked objects."""
        name = f"{prefix}-{uuid.uuid4().hex[:8]}"
        client.create_bucket(Bucket=name)
        marker = self.marker_of(name)
        log.info("bucket %s marker %s", name, marker)
        try:
            yield name, marker
        finally:
            try:
                for u in client.list_multipart_uploads(Bucket=name).get("Uploads", []):
                    client.abort_multipart_upload(
                        Bucket=name, Key=u["Key"], UploadId=u["UploadId"]
                    )
                for o in client.list_objects_v2(Bucket=name).get("Contents", []):
                    client.delete_object(Bucket=name, Key=o["Key"])
                client.delete_bucket(Bucket=name)
            except Exception as e:
                log.warning("bucket cleanup %s: %r", name, e)
            left = self.bucket_objs(marker)
            if left:
                log.info("purging %d leaked RADOS objects of %s", len(left), name)
                self.purge(left)

    def upload_parts(self, client, bucket, key, n=None, size=None):
        n, size = n or self.num_parts, size or self.part_size
        up = client.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
        parts = []
        for i in range(1, n + 1):
            r = client.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=up,
                PartNumber=i,
                Body=bytes([i]) * size,
            )
            parts.append({"PartNumber": i, "ETag": r["ETag"]})
        return up, parts

    @staticmethod
    def complete(client, bucket, key, up, parts):
        return status_of(
            lambda: client.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=up,
                MultipartUpload={"Parts": parts},
            )
        )

    @staticmethod
    def head_get(client, bucket, key):
        """(head status, head size, get status, bytes read)."""
        try:
            hsize = client.head_object(Bucket=bucket, Key=key)["ContentLength"]
            hs = 200
        except Exception as e:
            hs, hsize = code_of(e), None
        try:
            got = len(client.get_object(Bucket=bucket, Key=key)["Body"].read())
            gs = 200
        except Exception as e:
            gs, got = code_of(e), None
        return hs, hsize, gs, got

    def capture_env(self):
        """Write versions, status, zone and config to the evidence directory."""
        for name, cmd in (
            ("ceph_versions.txt", "ceph versions"),
            ("ceph_status.txt", "ceph -s; ceph orch ps --daemon-type rgw"),
            ("zone.txt", "radosgw-admin zone get"),
            ("config_dump.txt", "ceph config dump"),
        ):
            with open(os.path.join(self.outdir, name), "w") as f:
                f.write(self.sh(cmd))

    def wait_head(self, client, bucket, key, timeout=240, interval=0.2):
        """True once HEAD of the key succeeds."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                client.head_object(Bucket=bucket, Key=key)
                return True
            except Exception:
                time.sleep(interval)
        return False

    def injected_error_fired(self, upload_id):
        """True if RGW-A logged the injected lock-renewal error for this upload."""
        out = self.host(
            "a",
            f"journalctl -u {self.a_unit} --since '15 min ago' --no-pager | "
            f"grep 'failed with injected error' | grep -c '{upload_id}'",
            timeout=60,
        )
        return out.strip() not in ("", "0")

    def kill_rgw_a(self):
        """SIGKILL the RGW-A container."""
        return self.host("a", f"podman kill --signal KILL {self.a_container}")

    # ── admin socket (customer-gap test) ────────────────────────────────────

    def sock(self, side):
        """(container, socket) of the live admin socket of an RGW.

        The host keeps stale sockets of earlier daemon runs; probe from the
        newest down until one answers.
        """
        if side in self._socks:
            return self._socks[side]
        c = self.host(side, "podman ps --format '{{.Names}}' | grep -m1 -- '-rgw-rgw-'")
        names = self.host(side, f"podman exec {c} ls /var/run/ceph | grep client.rgw")
        for s in reversed(sorted(names.split())):
            out = self.host(
                side,
                f"timeout 5 podman exec {c} ceph --admin-daemon /var/run/ceph/{s} "
                "config get rgw_mp_lock_max_time",
            )
            if "rgw_mp_lock_max_time" in out:
                self._socks[side] = (c, s)
                return self._socks[side]
        inconclusive(f"no live admin socket on RGW {side}")

    def asok(self, side, key, val=None):
        c, s = self.sock(side)
        verb = f"config set {key} {val}" if val is not None else f"config get {key}"
        return self.host(
            side,
            f"timeout 20 podman exec {c} ceph --admin-daemon /var/run/ceph/{s} {verb}",
        )

    def asok_both(self, key, val):
        for side in ("a", "b"):
            self.asok(side, key, val)

    def journal(self, side, since, pattern):
        unit = self.a_unit if side == "a" else self.b_unit
        return self.host(
            side,
            f"journalctl -u {unit} --since '{since}' --no-pager | "
            f"grep -E '{pattern}' | cut -c1-420",
            timeout=90,
        )

    # ── gdb on RGW-A ────────────────────────────────────────────────────────

    def go_file(self, tag):
        return f"/root/ibmceph_{tag}.go"

    def gdb_log(self, tag):
        return f"/root/ibmceph_{tag}_gdb.log"

    def prepare_gdb(self):
        """Copy radosgw out of the container (host gdb cannot read it in place)."""
        if self._bin_ready:
            return
        if "GNU gdb" not in self.host("a", "gdb --version | head -1"):
            inconclusive("gdb is not installed on the RGW-A host")
        self.host("a", f"podman cp {self.a_container}:/usr/bin/radosgw {GDB_BIN}")
        if "radosgw" not in self.host("a", f"ls {GDB_BIN}"):
            inconclusive(f"could not copy radosgw out of {self.a_container}")
        self._bin_ready = True

    def arm_gdb(self, tag, script):
        """Attach gdb to RGW-A with `script`; True once the breakpoint is set."""
        self.prepare_gdb()
        self._tags.add(tag)
        gdb_file = f"/root/ibmceph_{tag}.gdb"
        self.host(
            "a",
            f"rm -f {self.gdb_log(tag)} {self.go_file(tag)}; pkill -x gdb; "
            f"cat > {gdb_file} <<'EOF'\n{script}EOF",
        )
        self.host(
            "a",
            f"nohup sh -c 'gdb -p $(pgrep -x radosgw | head -1) {GDB_BIN} "
            f"-batch -x {gdb_file}' > {self.gdb_log(tag)} 2>&1 < /dev/null &",
        )
        for _ in range(60):
            if "reakpoint 1 at" in self.host("a", f"cat {self.gdb_log(tag)}"):
                return True
            time.sleep(1)
        return False

    def gdb_seen(self, tag, word, timeout=60):
        """Wait until gdb printed `word` (HOLD: / INJECT:) to its log."""
        for _ in range(timeout):
            if word in self.host("a", f"cat {self.gdb_log(tag)}"):
                return True
            time.sleep(1)
        return False

    def release(self, tag):
        self.host("a", f"touch {self.go_file(tag)}")

    def gdb_lines(self, tag):
        out = self.host("a", f"grep -E 'HOLD|RELEASE|INJECT' {self.gdb_log(tag)}")
        return out.replace("\n", " | ")

    def gdb_stop(self):
        """Release every hold, kill gdb, remove the flag files."""
        if not self._tags:
            return
        files = " ".join(self.go_file(t) for t in self._tags)
        self.host("a", f"touch {files}; sleep 1; pkill -x gdb; rm -f {files}; true")
        self._tags.clear()

    def hold_request(self, tag, script, fn):
        """Arm gdb, run fn() in a thread and wait until RGW-A is stopped in it.

        Returns a Held; the caller does the competing request, calls
        self.release(tag) and then self.finish(held).  Skips if gdb did not
        arm or the request never reached the breakpoint.
        """
        if not self.arm_gdb(tag, script):
            inconclusive("gdb did not arm on RGW-A")
        held = Held(tag)

        def run():
            held.res["status"] = fn()

        held.thread = threading.Thread(target=run)
        held.thread.start()
        if not self.gdb_seen(tag, "HOLD:"):
            self.release(tag)
            held.thread.join()
            inconclusive("RGW-A never stopped at the breakpoint (window not reached)")
        return held

    def finish(self, held, timeout=120):
        """Release the hold and wait for the held request to return."""
        self.release(held.tag)
        held.thread.join(timeout=timeout)
        log.info("gdb log: %s", self.gdb_lines(held.tag))
        return held.status
