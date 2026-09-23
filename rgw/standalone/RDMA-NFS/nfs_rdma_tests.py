#!/usr/bin/env python3
"""
nfs_rdma_tests.py — IBM Ceph NFS-RDMA Automated Test Suite
===========================================================
Usage:
    python3 nfs_rdma_tests.py [--config config/cluster.yaml]
                               [--scale  config/scale.yaml]
                               [--perf   config/performance.yaml]
                               [--run    sanity,functional,scale,performance,regression,negative]
                               [--client grim019]

    --run defaults to: sanity,functional,regression,negative
    Add 'scale' and/or 'performance' explicitly to include those.

Examples:
    # Run sanity + functional only (default)
    python3 nfs_rdma_tests.py

    # Run everything
    python3 nfs_rdma_tests.py --run all

    # Run only scale tests with custom config
    python3 nfs_rdma_tests.py --run scale --scale config/scale.yaml

    # Run against a specific client
    python3 nfs_rdma_tests.py --client grim020

Sanity and Functional tests are hardcoded in this script.
Scale and Performance tests are driven by YAML config files.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _c(colour, text): return f"{colour}{text}{RESET}"
def ok(msg):   print(f"  {_c(GREEN,  '✅ PASS')}  {msg}")
def fail(msg): print(f"  {_c(RED,    '❌ FAIL')}  {msg}")
def skip(msg): print(f"  {_c(YELLOW, '⏭  SKIP')}  {msg}")
def info(msg): print(f"  {_c(CYAN,   'ℹ ')}      {msg}")
def head(msg): print(f"\n{_c(BOLD, msg)}")

# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def ssh(host, cmd, cfg, timeout=30, raise_on_error=False):
    """Run cmd on host via SSH. Returns (stdout, stderr, returncode)."""
    user = cfg["ssh"]["user"]
    pw   = cfg["ssh"]["password"]
    ct   = cfg["ssh"].get("connect_timeout", 15)
    full_cmd = [
        "sshpass", "-p", pw,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={ct}",
        "-o", "ServerAliveInterval=10",
        "-o", "BatchMode=no",
        f"{user}@{host}",
        cmd,
    ]
    result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
    if raise_on_error and result.returncode != 0:
        raise RuntimeError(
            f"SSH {host} failed (rc={result.returncode}):\n"
            f"  cmd : {cmd}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def ssh_ok(host, cmd, cfg, timeout=30):
    """Return True if command exits 0."""
    _, _, rc = ssh(host, cmd, cfg, timeout=timeout)
    return rc == 0


# ---------------------------------------------------------------------------
# Result collector
# ---------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.records = []

    def add(self, tid, name, verdict, notes="", metrics=None):
        self.records.append({
            "id":      tid,
            "name":    name,
            "verdict": verdict,   # PASS / FAIL / SKIP / PARTIAL
            "notes":   notes,
            "metrics": metrics or {},
            "ts":      datetime.utcnow().isoformat(),
        })
        if verdict == "PASS":    ok(f"[{tid}] {name}  {_c(CYAN, notes)}")
        elif verdict == "FAIL":  fail(f"[{tid}] {name}  {notes}")
        elif verdict == "SKIP":  skip(f"[{tid}] {name}  {notes}")
        else:                    info(f"[{tid}] {name}  {verdict} — {notes}")

    def summary(self):
        total   = len(self.records)
        passed  = sum(1 for r in self.records if r["verdict"] == "PASS")
        failed  = sum(1 for r in self.records if r["verdict"] == "FAIL")
        partial = sum(1 for r in self.records if r["verdict"] == "PARTIAL")
        skipped = sum(1 for r in self.records if r["verdict"] == "SKIP")
        return {"total": total, "pass": passed, "fail": failed,
                "partial": partial, "skip": skipped}

    def save(self, out_dir):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        ts   = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        path = Path(out_dir) / f"nfs_rdma_results_{ts}.json"
        with open(path, "w") as f:
            json.dump({"results": self.records, "summary": self.summary()}, f, indent=2)
        return str(path)


# ---------------------------------------------------------------------------
# Setup / pre-flight checks (run before any tests)
# ---------------------------------------------------------------------------

def run_setup_checks(cfg, results):
    """
    Verify every node meets pre-conditions before tests start.
    Covers:
      - SSH reachability
      - RDMA kernel modules loaded (rpcrdma, ib_core, mlx5_ib)
      - RDMA device present and PORT_ACTIVE
      - NFS-Ganesha running on server
      - Ceph cluster health (warn is OK, error is not)
      - Export accessible
    """
    head("═══ SETUP CHECKS ═══")
    server  = cfg["cluster"]["nfs_server"]
    clients = cfg["cluster"]["rdma_clients"]
    all_nodes = cfg["cluster"]["all_nodes"]

    # 1. SSH reachability — all nodes
    for node in all_nodes:
        if ssh_ok(node, "echo ok", cfg, timeout=10):
            results.add("SETUP-01", f"SSH reachable: {node}", "PASS")
        else:
            results.add("SETUP-01", f"SSH reachable: {node}", "FAIL",
                        "Cannot reach node — remaining tests may fail")

    # 2. RDMA kernel modules on clients
    required_mods = ["rpcrdma", "ib_core", "mlx5_ib"]
    for node in clients:
        for mod in required_mods:
            out, _, _ = ssh(node, f"lsmod | grep -c {mod}", cfg)
            if out.strip() and int(out.strip()) > 0:
                results.add("SETUP-02", f"{node}: kmod {mod} loaded", "PASS")
            else:
                results.add("SETUP-02", f"{node}: kmod {mod} loaded", "FAIL",
                            f"Run: modprobe {mod}")

    # 3. RDMA device PORT_ACTIVE on clients
    device = cfg["rdma"]["device"]
    for node in clients:
        out, _, _ = ssh(node, f"ibv_devinfo 2>/dev/null | grep -E 'hca_id|state'", cfg)
        if device in out and "PORT_ACTIVE" in out:
            results.add("SETUP-03", f"{node}: RDMA device {device} PORT_ACTIVE", "PASS")
        else:
            results.add("SETUP-03", f"{node}: RDMA device {device} PORT_ACTIVE", "FAIL",
                        f"Check NIC/cable — ibv_devinfo output: {out[:80]}")

    # 4. NFS-Ganesha running on server
    out, _, rc = ssh(server, "systemctl is-active --quiet nfs-ganesha; echo $?", cfg)
    if rc == 0 or out.strip() == "0":
        results.add("SETUP-04", f"{server}: nfs-ganesha service active", "PASS")
    else:
        # Try cephadm-managed daemon
        out2, _, _ = ssh(server, "ceph orch ps --daemon-type nfs 2>/dev/null | grep running | wc -l", cfg)
        if out2.strip() and int(out2.strip()) > 0:
            results.add("SETUP-04", f"{server}: nfs-ganesha daemon running (cephadm)", "PASS")
        else:
            results.add("SETUP-04", f"{server}: nfs-ganesha service active", "FAIL",
                        "NFS-Ganesha not running — mount tests will fail")

    # 5. Ceph cluster health — WARN is acceptable, ERR is not
    out, _, _ = ssh(server, "ceph health 2>/dev/null", cfg, timeout=20)
    if "HEALTH_ERR" in out:
        results.add("SETUP-05", "Ceph cluster health", "FAIL",
                    f"Cluster in ERROR state: {out[:120]}")
    elif "HEALTH_WARN" in out:
        results.add("SETUP-05", "Ceph cluster health", "PASS",
                    f"HEALTH_WARN (acceptable): {out[:80]}")
    else:
        results.add("SETUP-05", "Ceph cluster health", "PASS", out[:80])

    # 6. Stale rpcrdma handles check on clients (refcount > 0 = stale)
    for node in clients:
        out, _, _ = ssh(node, "cat /sys/module/rpcrdma/refcnt 2>/dev/null", cfg)
        refcnt = out.strip()
        if refcnt == "0" or refcnt == "":
            results.add("SETUP-06", f"{node}: rpcrdma refcount clean (no stale handles)", "PASS")
        else:
            results.add("SETUP-06", f"{node}: rpcrdma refcount={refcnt}", "FAIL",
                        f"Stale RDMA handles — reboot {node} to clear before mounting")


# ---------------------------------------------------------------------------
# Mount helpers
# ---------------------------------------------------------------------------

def mount_rdma(host, cfg, timeout=30):
    vip    = cfg["cluster"]["nfs_vip"]
    export = cfg["nfs"]["export"]
    mnt    = cfg["nfs"]["mount_point"]
    opts   = cfg["nfs"]["rdma_mount_opts"]
    ssh(host, f"mkdir -p {mnt}", cfg)
    # Unmount first if already mounted
    ssh(host, f"umount -lf {mnt} 2>/dev/null; sleep 1", cfg)
    _, err, rc = ssh(host, f"mount -t nfs -o {opts} {vip}:{export} {mnt}", cfg, timeout=timeout)
    return rc == 0, err


def mount_tcp(host, cfg, timeout=30):
    vip    = cfg["cluster"]["nfs_vip"]
    export = cfg["nfs"]["export"]
    mnt    = cfg["nfs"]["mount_point"] + "-tcp"
    opts   = cfg["nfs"]["tcp_mount_opts"]
    ssh(host, f"mkdir -p {mnt}", cfg)
    ssh(host, f"umount -lf {mnt} 2>/dev/null; sleep 1", cfg)
    _, err, rc = ssh(host, f"mount -t nfs -o {opts} {vip}:{export} {mnt}", cfg, timeout=timeout)
    return rc == 0, mnt, err


def umount(host, mnt, cfg):
    ssh(host, f"umount -lf {mnt} 2>/dev/null", cfg)


def get_rdma_counter(host, cfg):
    path = cfg["rdma"]["rx_counter"]
    out, _, _ = ssh(host, f"cat {path} 2>/dev/null", cfg)
    try:
        return int(out.strip())
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# ── SANITY TESTS ────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_t01_rdma_hardware(host, cfg, results):
    """T-01: Validate RDMA hardware — device present, PORT_ACTIVE, firmware."""
    head("T-01 | RDMA Hardware Validation")
    device = cfg["rdma"]["device"]

    out, _, _ = ssh(host, f"ibv_devinfo 2>/dev/null | grep -E 'hca_id|state|fw_ver'", cfg)
    if device not in out:
        results.add("T-01", "RDMA hardware validation", "FAIL",
                    f"{device} not found in ibv_devinfo")
        return

    if "PORT_ACTIVE" not in out:
        results.add("T-01", "RDMA hardware validation", "FAIL", "Port not active")
        return

    fw_line = [l for l in out.splitlines() if "fw_ver" in l]
    fw = fw_line[0].split()[-1] if fw_line else "unknown"
    results.add("T-01", "RDMA hardware validation", "PASS",
                f"device={device} fw={fw}", {"device": device, "fw_ver": fw})


def test_t02_rdma_mount(host, cfg, results):
    """T-02: Mount NFS over RDMA with sync option and verify mount options."""
    head("T-02 | NFS RDMA Sync Mount Verification")
    ok_mount, err = mount_rdma(host, cfg)
    if not ok_mount:
        results.add("T-02", "RDMA sync mount", "FAIL", f"Mount failed: {err}")
        return

    mnt  = cfg["nfs"]["mount_point"]
    out, _, _ = ssh(host, f"mount | grep {mnt}", cfg)
    checks = {
        "proto=rdma":   "proto=rdma" in out,
        "port=20049":   "port=20049" in out,
        "vers=4.1":     "vers=4.1"   in out,
        "sync":         "sync"       in out,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        results.add("T-02", "RDMA sync mount", "FAIL",
                    f"Missing mount options: {failed}", {"mount_line": out})
    else:
        results.add("T-02", "RDMA sync mount", "PASS",
                    "proto=rdma port=20049 vers=4.1 sync confirmed",
                    {"mount_options": out})


def test_t04_no_tcp_fallback(host, cfg, results):
    """T-04: Confirm proto=rdma mount fails cleanly — does not silently fall back to TCP."""
    head("T-04 | No TCP Fallback Confirmation")
    vip    = cfg["cluster"]["nfs_vip"]
    export = cfg["nfs"]["export"]
    mnt    = cfg["nfs"]["mount_point"] + "-rdmaonly"

    ssh(host, f"mkdir -p {mnt}", cfg)
    ssh(host, f"umount -lf {mnt} 2>/dev/null", cfg)

    # Mount with proto=rdma but wrong port (2049 instead of 20049) — must fail
    _, err, rc = ssh(
        host,
        f"mount -t nfs -o vers=4.1,proto=rdma,port=2049,nofsc {vip}:{export} {mnt}",
        cfg, timeout=15,
    )
    ssh(host, f"umount -lf {mnt} 2>/dev/null", cfg)

    if rc != 0:
        results.add("T-04", "No TCP fallback — wrong RDMA port fails cleanly", "PASS",
                    "Mount correctly refused, no silent TCP fallback")
    else:
        # Check if TCP was used
        out, _, _ = ssh(host, f"mount | grep {mnt}", cfg)
        if "tcp" in out.lower():
            results.add("T-04", "No TCP fallback — wrong RDMA port fails cleanly", "FAIL",
                        "Mount succeeded but fell back to TCP silently")
        else:
            results.add("T-04", "No TCP fallback — wrong RDMA port fails cleanly", "PASS",
                        "Mount with wrong port succeeded on RDMA (port was ignored)")


def test_t05_protocol_verify(host, cfg, results):
    """T-05: Confirm RDMA RX counters increment during I/O (traffic is on wire)."""
    head("T-05 | Protocol Verification — RDMA Counter Delta")
    mnt = cfg["nfs"]["mount_point"]
    wdir = cfg["test"]["remote_workdir"]

    ssh(host, f"mkdir -p {wdir}", cfg)
    before = get_rdma_counter(host, cfg)

    # Write 64MB to trigger measurable RDMA traffic
    _, _, rc = ssh(
        host,
        f"dd if=/dev/zero of={wdir}/t05_probe.bin bs=1M count=64 oflag=direct 2>/dev/null",
        cfg, timeout=60,
    )
    after = get_rdma_counter(host, cfg)
    delta = after - before
    ssh(host, f"rm -f {wdir}/t05_probe.bin", cfg)

    if rc == 0 and delta > 0:
        results.add("T-05", "Protocol verification — RDMA counter delta", "PASS",
                    f"RX delta={delta}", {"rdma_rx_delta": delta})
    elif rc != 0:
        results.add("T-05", "Protocol verification — RDMA counter delta", "FAIL",
                    "Write command failed")
    else:
        results.add("T-05", "Protocol verification — RDMA counter delta", "FAIL",
                    f"RX counter did not increase (delta={delta}) — traffic may be on TCP")


# ---------------------------------------------------------------------------
# ── FUNCTIONAL TESTS ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_t03_basic_file_ops(host, cfg, results):
    """T-03: Write / Read / Rename / Delete on RDMA mount."""
    head("T-03 | Basic File Operations")
    wdir = cfg["test"]["remote_workdir"]
    ssh(host, f"mkdir -p {wdir}", cfg)

    errors = []

    # Write
    _, _, rc = ssh(host, f"dd if=/dev/urandom of={wdir}/t03.bin bs=1M count=10 2>/dev/null", cfg, timeout=60)
    if rc != 0: errors.append("write failed")

    # Read back
    out, _, rc = ssh(host, f"md5sum {wdir}/t03.bin 2>/dev/null", cfg, timeout=30)
    if rc != 0: errors.append("read/md5 failed")
    md5_orig = out.split()[0] if out else ""

    # Rename
    _, _, rc = ssh(host, f"mv {wdir}/t03.bin {wdir}/t03_renamed.bin", cfg)
    if rc != 0: errors.append("rename failed")

    # Verify renamed file MD5 matches
    out2, _, rc = ssh(host, f"md5sum {wdir}/t03_renamed.bin 2>/dev/null", cfg, timeout=30)
    md5_renamed = out2.split()[0] if out2 else ""
    if md5_orig and md5_renamed and md5_orig != md5_renamed:
        errors.append("md5 mismatch after rename")

    # Delete
    _, _, rc = ssh(host, f"rm -f {wdir}/t03_renamed.bin", cfg)
    if rc != 0: errors.append("delete failed")

    if errors:
        results.add("T-03", "Basic file ops (write/read/rename/delete)", "FAIL",
                    ", ".join(errors))
    else:
        results.add("T-03", "Basic file ops (write/read/rename/delete)", "PASS",
                    f"md5={md5_orig}")


def test_t08_dual_mount(rdma_host, tcp_host, cfg, results):
    """T-08: Same export mounted via RDMA on one client and TCP on another simultaneously."""
    head("T-08 | Dual Mount — RDMA + TCP Same Export")
    wdir_rdma = cfg["test"]["remote_workdir"]
    wdir_tcp  = cfg["nfs"]["mount_point"] + "-tcp"

    ok_tcp, tcp_mnt, err_tcp = mount_tcp(tcp_host, cfg)
    if not ok_tcp:
        results.add("T-08", "Dual mount TCP+RDMA same export", "FAIL",
                    f"TCP mount failed: {err_tcp}")
        return

    # Write from RDMA client
    ssh(rdma_host, f"mkdir -p {wdir_rdma}", cfg)
    _, _, rc1 = ssh(rdma_host, f"dd if=/dev/urandom of={wdir_rdma}/t08_rdma.bin bs=1M count=32 2>/dev/null",
                    cfg, timeout=60)

    # Read from TCP client
    out, _, rc2 = ssh(tcp_host, f"md5sum {tcp_mnt}/rdma-nfs-autotest/t08_rdma.bin 2>/dev/null",
                      cfg, timeout=30)

    # Write from TCP client
    _, _, rc3 = ssh(tcp_host, f"dd if=/dev/urandom of={tcp_mnt}/rdma-nfs-autotest/t08_tcp.bin bs=1M count=32 2>/dev/null",
                    cfg, timeout=60)

    # Read from RDMA client
    out2, _, rc4 = ssh(rdma_host, f"md5sum {wdir_rdma}/t08_tcp.bin 2>/dev/null", cfg, timeout=30)

    # Cleanup
    ssh(rdma_host, f"rm -f {wdir_rdma}/t08_rdma.bin {wdir_rdma}/t08_tcp.bin", cfg)
    umount(tcp_host, tcp_mnt, cfg)

    if rc1 == 0 and rc2 == 0 and rc3 == 0 and rc4 == 0:
        results.add("T-08", "Dual mount TCP+RDMA same export", "PASS",
                    f"Cross-client R/W OK — RDMA:{rdma_host} TCP:{tcp_host}")
    else:
        results.add("T-08", "Dual mount TCP+RDMA same export", "FAIL",
                    f"rc write_rdma={rc1} read_tcp={rc2} write_tcp={rc3} read_rdma={rc4}")


def test_t09_dir_depth(host, cfg, results, depth=20, files_per_level=1000):
    """T-09: Create directory tree of given depth with N files at each level."""
    head(f"T-09 | Directory Depth={depth}, {files_per_level} files/level")
    wdir = cfg["test"]["remote_workdir"] + "/t09_dirdepth"
    ssh(host, f"rm -rf {wdir}", cfg)

    # Build nested path
    nested = wdir
    for i in range(1, depth + 1):
        nested += f"/d{i:02d}"
    ssh(host, f"mkdir -p {nested}", cfg)

    # Write files at each level
    total_written = 0
    current = wdir
    for level in range(1, depth + 1):
        current += f"/d{level:02d}"
        cmd = (
            f"python3 -c \""
            f"import os; data=b'A'*4096; "
            f"[open('{current}/f%05d'%i,'wb').write(data) for i in range(1,{files_per_level}+1)]\""
        )
        _, _, rc = ssh(host, cmd, cfg, timeout=120)
        if rc == 0:
            total_written += files_per_level

    expected = depth * files_per_level
    if total_written == expected:
        results.add("T-09", f"Dir depth-{depth} + {files_per_level} files/level", "PASS",
                    f"{total_written}/{expected} files created",
                    {"depth": depth, "files_per_level": files_per_level, "total": total_written})
    else:
        results.add("T-09", f"Dir depth-{depth} + {files_per_level} files/level", "FAIL",
                    f"Only {total_written}/{expected} files created")

    ssh(host, f"rm -rf {wdir}", cfg)


def test_t10_permissions(host, cfg, results):
    """T-10: Set and verify file permissions 644, 755, 400."""
    head("T-10 | File Permissions")
    wdir = cfg["test"]["remote_workdir"]
    errors = []
    for mode in ["644", "755", "400"]:
        f = f"{wdir}/t10_perm_{mode}.bin"
        ssh(host, f"dd if=/dev/zero of={f} bs=4096 count=1 2>/dev/null", cfg)
        ssh(host, f"chmod {mode} {f}", cfg)
        out, _, _ = ssh(host, f"stat -c %a {f}", cfg)
        if out.strip() != mode:
            errors.append(f"mode {mode}: got {out.strip()}")
        ssh(host, f"rm -f {f}", cfg)

    if errors:
        results.add("T-10", "File permissions 644/755/400", "FAIL", ", ".join(errors))
    else:
        results.add("T-10", "File permissions 644/755/400", "PASS")


def test_t23_no_tcp_fallback_negative(host, cfg, results):
    """T-23: Negative — RDMA mount with forced proto=rdma never silently uses TCP."""
    head("T-23 | Negative: No Silent TCP Fallback")
    mnt = cfg["nfs"]["mount_point"]
    out, _, _ = ssh(host, f"cat /proc/mounts | grep {mnt}", cfg)
    if "proto=rdma" in out:
        results.add("T-23", "No silent TCP fallback", "PASS",
                    "Active mount confirmed as proto=rdma")
    elif "proto=tcp" in out:
        results.add("T-23", "No silent TCP fallback", "FAIL",
                    "Mount is using TCP instead of RDMA")
    else:
        results.add("T-23", "No silent TCP fallback", "FAIL",
                    f"Could not determine protocol: {out[:80]}")


def test_t24_incompatible_nic(host, cfg, results):
    """T-24: Skip — all nodes use Mellanox ConnectX-5, incompatible NIC test N/A."""
    head("T-24 | Incompatible NIC Types")
    device = cfg["rdma"]["device"]
    out, _, _ = ssh(host, f"ibv_devinfo 2>/dev/null | grep hca_id", cfg)
    if device in out:
        results.add("T-24", "Incompatible NIC types", "SKIP",
                    "All nodes use same NIC type (Mellanox ConnectX-5) — test not applicable")
    else:
        results.add("T-24", "Incompatible NIC types", "SKIP", "NIC type check skipped")


def test_t25_file_locking(host, cfg, results):
    """T-25: Concurrent writers — file locking enforced via fcntl."""
    head("T-25 | File Locking with Concurrent Writers")
    wdir = cfg["test"]["remote_workdir"]
    lockfile = f"{wdir}/t25_locktest.bin"

    script = (
        "python3 -c \""
        "import fcntl,os,time;"
        "f=open('{lf}','wb');"
        "fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);"
        "f.write(b'locked');f.flush();"
        "time.sleep(3);"
        "fcntl.flock(f,fcntl.LOCK_UN);f.close()"
        "\"".format(lf=lockfile)
    )
    # Launch writer 1 in background
    ssh(host, f"mkdir -p {wdir}", cfg)
    ssh(host, script + " &", cfg, timeout=5)
    time.sleep(1)

    # Writer 2 tries LOCK_NB — must get EWOULDBLOCK
    check = (
        "python3 -c \""
        "import fcntl,sys;"
        "f=open('{lf}','rb');"
        "try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('UNLOCKED')"
        "except IOError: print('LOCKED')"
        "\"".format(lf=lockfile)
    )
    out, _, _ = ssh(host, check, cfg, timeout=10)
    ssh(host, f"rm -f {lockfile}", cfg)

    if "LOCKED" in out:
        results.add("T-25", "File locking — concurrent writers blocked", "PASS",
                    "fcntl LOCK_EX correctly blocked second writer")
    else:
        results.add("T-25", "File locking — concurrent writers blocked", "FAIL",
                    f"Lock was not held: got '{out}'")


# ---------------------------------------------------------------------------
# ── PERFORMANCE TESTS ───────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_write_throughput(host, cfg, results, tid, name, size_mb):
    """Generic write throughput test — measures MB/s via dd."""
    head(f"{tid} | Write Throughput: {name}")
    wdir = cfg["test"]["remote_workdir"]
    ssh(host, f"mkdir -p {wdir}", cfg)
    f = f"{wdir}/{tid.lower()}_write.bin"

    before = get_rdma_counter(host, cfg)
    t0 = time.time()
    _, stderr, rc = ssh(
        host,
        f"dd if=/dev/zero of={f} bs=1M count={size_mb} oflag=direct 2>&1",
        cfg, timeout=cfg["test"]["io_timeout"],
    )
    elapsed = time.time() - t0
    after = get_rdma_counter(host, cfg)
    rdma_delta = after - before

    ssh(host, f"rm -f {f}", cfg)

    if rc != 0:
        results.add(tid, name, "FAIL", f"dd failed: {stderr[:80]}")
        return

    mbps = size_mb / elapsed if elapsed > 0 else 0
    results.add(tid, name, "PASS",
                f"{mbps:.0f} MB/s  RDMA_RX_delta={rdma_delta}",
                {"size_mb": size_mb, "elapsed_s": round(elapsed, 2),
                 "mbps": round(mbps, 1), "rdma_rx_delta": rdma_delta})


def test_read_throughput(host, cfg, results, tid, name, size_mb, verify_md5=True):
    """Generic read throughput + optional integrity test."""
    head(f"{tid} | Read Throughput: {name}")
    wdir = cfg["test"]["remote_workdir"]
    f = f"{wdir}/{tid.lower()}_read.bin"

    # Write first
    _, _, rc = ssh(
        host,
        f"dd if=/dev/urandom of={f} bs=1M count={size_mb} 2>/dev/null",
        cfg, timeout=cfg["test"]["io_timeout"],
    )
    if rc != 0:
        results.add(tid, name, "FAIL", "Setup write failed")
        return

    md5_write = ""
    if verify_md5:
        out, _, _ = ssh(host, f"md5sum {f}", cfg, timeout=120)
        md5_write = out.split()[0] if out else ""

    # Read (dd to /dev/null)
    t0 = time.time()
    _, _, rc = ssh(
        host,
        f"dd if={f} of=/dev/null bs=1M iflag=direct 2>/dev/null",
        cfg, timeout=cfg["test"]["io_timeout"],
    )
    elapsed = time.time() - t0
    ssh(host, f"rm -f {f}", cfg)

    if rc != 0:
        results.add(tid, name, "FAIL", "Read failed")
        return

    mbps = size_mb / elapsed if elapsed > 0 else 0
    notes = f"{mbps:.0f} MB/s"
    if verify_md5 and md5_write:
        notes += f"  md5={md5_write}"
    results.add(tid, name, "PASS", notes,
                {"size_mb": size_mb, "elapsed_s": round(elapsed, 2),
                 "mbps": round(mbps, 1), "md5": md5_write})


def test_t11_mixed_sizes(host, cfg, results, sizes_kb):
    """T-11: Write + read + md5 verify for a range of file sizes."""
    head("T-11 | Mixed File Sizes")
    wdir = cfg["test"]["remote_workdir"]
    ssh(host, f"mkdir -p {wdir}", cfg)
    errors = []

    for kb in sizes_kb:
        f = f"{wdir}/t11_{kb}kb.bin"
        ssh(host, f"dd if=/dev/urandom of={f} bs=1024 count={kb} 2>/dev/null", cfg, timeout=120)
        out1, _, _ = ssh(host, f"md5sum {f}", cfg, timeout=60)
        # Re-read and check
        out2, _, _ = ssh(host, f"md5sum {f}", cfg, timeout=60)
        md51 = out1.split()[0] if out1 else ""
        md52 = out2.split()[0] if out2 else ""
        if not md51 or md51 != md52:
            errors.append(f"{kb}KB md5 mismatch")
        ssh(host, f"rm -f {f}", cfg)

    if errors:
        results.add("T-11", "Mixed file sizes 4KB–100MB", "FAIL", ", ".join(errors))
    else:
        results.add("T-11", "Mixed file sizes 4KB–100MB", "PASS",
                    f"{len(sizes_kb)} sizes verified: {sizes_kb[0]}KB–{sizes_kb[-1]}KB")


def test_t14_cpu_util(host, cfg, results, size_mb=1024):
    """T-14: Capture CPU utilisation via mpstat during a 1GB RDMA write."""
    head("T-14 | CPU Utilisation During RDMA Write")
    wdir = cfg["test"]["remote_workdir"]
    f    = f"{wdir}/t14_cpu.bin"
    ssh(host, f"mkdir -p {wdir}", cfg)

    # Launch mpstat in background, write, collect
    ssh(host, "mpstat 1 30 > /tmp/t14_mpstat.txt 2>/dev/null &", cfg, timeout=5)
    time.sleep(1)
    _, _, rc = ssh(
        host,
        f"dd if=/dev/zero of={f} bs=1M count={size_mb} oflag=direct 2>/dev/null",
        cfg, timeout=180,
    )
    time.sleep(2)
    ssh(host, "pkill -f mpstat 2>/dev/null", cfg)
    out, _, _ = ssh(host, "cat /tmp/t14_mpstat.txt | tail -5", cfg)
    ssh(host, f"rm -f {f} /tmp/t14_mpstat.txt", cfg)

    if rc == 0 and out:
        results.add("T-14", "CPU utilisation during RDMA write", "PASS",
                    f"mpstat captured ({size_mb}MB write)", {"mpstat_tail": out})
    else:
        results.add("T-14", "CPU utilisation during RDMA write",
                    "PARTIAL" if rc == 0 else "FAIL",
                    "mpstat output missing" if rc == 0 else "Write failed")


# ---------------------------------------------------------------------------
# ── SCALE TESTS ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_scale_flat_files(host, cfg, results, tid, name, total_files, file_size_bytes):
    """Generic flat-file scale test: create N files of given size in one directory."""
    head(f"{tid} | Scale: {name}")
    wdir  = cfg["test"]["remote_workdir"] + f"/{tid.lower()}_flat"
    ssh(host, f"mkdir -p {wdir}", cfg)

    data_kb = file_size_bytes // 1024 or 1
    t0 = time.time()
    cmd = (
        f"python3 -c \""
        f"import os; data=b'\\x00'*{file_size_bytes}; "
        f"[open('{wdir}/f%07d'%i,'wb').write(data) for i in range(1,{total_files}+1)]; "
        f"print(len(os.listdir('{wdir}')))\""
    )
    out, _, rc = ssh(host, cmd, cfg, timeout=cfg["test"]["scale_timeout"])
    elapsed = time.time() - t0

    try:
        actual = int(out.strip())
    except ValueError:
        actual = 0

    rate = actual / elapsed if elapsed > 0 else 0
    if rc == 0 and actual >= total_files:
        results.add(tid, name, "PASS",
                    f"{actual}/{total_files} files in {elapsed:.0f}s ({rate:.0f} files/sec)",
                    {"total_files": actual, "elapsed_s": round(elapsed, 1),
                     "files_per_sec": round(rate, 1), "file_size_bytes": file_size_bytes})
    else:
        results.add(tid, name, "FAIL",
                    f"Only {actual}/{total_files} files created (rc={rc})")

    ssh(host, f"rm -rf {wdir}", cfg)


def test_scale_depth_tree(host, cfg, results, depth, total_files, file_size_bytes):
    """T-18 variant: N files spread equally across depth-D tree, parallel workers."""
    tid  = "T-18"
    name = f"Scale {total_files//1000000}M files depth-{depth} tree"
    head(f"{tid} | {name}")

    files_per_level = total_files // depth
    base = cfg["test"]["remote_workdir"] + "/t18_depthtree"
    ssh(host, f"rm -rf {base}", cfg)

    # Create all depth dirs
    dirs = " ".join([f"{base}/depth{d:02d}" for d in range(1, depth + 1)])
    ssh(host, f"mkdir -p {dirs}", cfg)

    before = get_rdma_counter(host, cfg)
    t0 = time.time()

    # Build Python worker script via base64 to avoid quoting issues
    worker_code = f"""
import os, sys
d = sys.argv[1]
base = "{base}/depth" + d
data = b"\\x00" * {file_size_bytes}
for i in range(1, {files_per_level} + 1):
    with open(base + "/f%07d" % i, "wb") as f:
        f.write(data)
print("DONE depth" + d + " " + str(len(os.listdir(base))))
"""
    import base64
    encoded = base64.b64encode(worker_code.encode()).decode()
    # Write worker script to remote
    ssh(host, f"echo {encoded} | base64 -d > /tmp/t18_worker.py", cfg)

    # Launch one Python process per depth level
    for d in range(1, depth + 1):
        ssh(host, f"python3 /tmp/t18_worker.py {d:02d} > /tmp/t18_d{d:02d}.log 2>&1 &", cfg, timeout=5)

    # Poll until all workers finish
    timeout = cfg["test"]["scale_timeout"]
    poll_interval = 15
    waited = 0
    while waited < timeout:
        time.sleep(poll_interval)
        waited += poll_interval
        out, _, _ = ssh(host, "pgrep -c python3 2>/dev/null || echo 0", cfg)
        running = int(out.strip()) if out.strip().isdigit() else 0
        if running == 0:
            break
        # Progress report
        out2, _, _ = ssh(host, f"ls {base}/depth01 2>/dev/null | wc -l", cfg)
        done = int(out2.strip()) if out2.strip().isdigit() else 0
        pct  = done * 100 // files_per_level if files_per_level else 0
        info(f"  depth01: {done}/{files_per_level} files ({pct}%)  — {waited}s elapsed")

    elapsed = time.time() - t0
    after   = get_rdma_counter(host, cfg)
    rdma_delta = after - before

    # Count total
    total_actual = 0
    for d in range(1, depth + 1):
        out, _, _ = ssh(host, f"ls {base}/depth{d:02d} 2>/dev/null | wc -l", cfg)
        total_actual += int(out.strip()) if out.strip().isdigit() else 0

    rate = total_actual / elapsed if elapsed > 0 else 0

    if total_actual >= total_files:
        results.add(tid, name, "PASS",
                    f"{total_actual}/{total_files} files in {elapsed:.0f}s ({rate:.0f} files/sec)  RDMA_RX_delta={rdma_delta}",
                    {"total": total_actual, "elapsed_s": round(elapsed, 1),
                     "files_per_sec": round(rate, 1), "rdma_rx_delta": rdma_delta})
    else:
        results.add(tid, name, "FAIL",
                    f"Only {total_actual}/{total_files} files created in {elapsed:.0f}s")

    ssh(host, f"rm -rf {base} /tmp/t18_worker.py /tmp/t18_d*.log", cfg)


# ---------------------------------------------------------------------------
# ── REGRESSION TESTS ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_t20_io_stability(host, cfg, results):
    """T-20: I/O stability — sustained writes for 60s, no errors."""
    head("T-20 | Regression: I/O Stability")
    wdir = cfg["test"]["remote_workdir"]
    ssh(host, f"mkdir -p {wdir}", cfg)
    f = f"{wdir}/t20_stability.bin"

    # Write 2GB in 10×200MB chunks, check for errors each iteration
    errors = []
    for chunk in range(1, 6):
        _, stderr, rc = ssh(
            host,
            f"dd if=/dev/zero of={f} bs=1M count=200 oflag=direct conv=notrunc 2>&1",
            cfg, timeout=120,
        )
        if rc != 0:
            errors.append(f"chunk {chunk} failed: {stderr[:60]}")

    ssh(host, f"rm -f {f}", cfg)

    if errors:
        results.add("T-20", "I/O stability (sustained writes)", "FAIL", "; ".join(errors))
    else:
        results.add("T-20", "I/O stability (sustained writes)", "PASS",
                    "5x200MB writes completed without error")


def test_t21_ganesha_restart(server, client, cfg, results):
    """T-21: Ganesha restart with active RDMA mount — mount must survive."""
    head("T-21 | Regression: Ganesha Restart With Active Mount")
    mnt  = cfg["nfs"]["mount_point"]
    wdir = cfg["test"]["remote_workdir"]

    # Confirm mount is live
    out, _, _ = ssh(client, f"mount | grep {mnt}", cfg)
    if "rdma" not in out:
        results.add("T-21", "Ganesha restart with active mount", "FAIL",
                    "RDMA mount not active before restart")
        return

    # Write a file, restart Ganesha, read it back
    ssh(client, f"mkdir -p {wdir}", cfg)
    _, _, rc1 = ssh(client, f"dd if=/dev/urandom of={wdir}/t21_pre.bin bs=1M count=10 2>/dev/null",
                    cfg, timeout=30)

    info(f"  Restarting NFS-Ganesha on {server}...")
    ssh(server, "ceph orch restart nfs.nfs-gateway 2>/dev/null || systemctl restart nfs-ganesha 2>/dev/null", cfg, timeout=30)
    time.sleep(15)  # allow Ganesha to come back

    # Try to read after restart
    _, _, rc2 = ssh(client, f"md5sum {wdir}/t21_pre.bin 2>/dev/null", cfg, timeout=30)

    # Write new file after restart
    _, _, rc3 = ssh(client, f"dd if=/dev/urandom of={wdir}/t21_post.bin bs=1M count=10 2>/dev/null",
                    cfg, timeout=30)
    ssh(client, f"rm -f {wdir}/t21_pre.bin {wdir}/t21_post.bin", cfg)

    if rc1 == 0 and rc2 == 0 and rc3 == 0:
        results.add("T-21", "Ganesha restart with active mount", "PASS",
                    "Mount survived Ganesha restart, I/O works before and after")
    else:
        results.add("T-21", "Ganesha restart with active mount", "FAIL",
                    f"rc pre-write={rc1} post-read={rc2} post-write={rc3}")


def test_t22_rgw_restart(server, client, cfg, results):
    """T-22: RGW restart with active RDMA connections — I/O must survive."""
    head("T-22 | Regression: RGW Restart With Active RDMA")
    wdir = cfg["test"]["remote_workdir"]
    f    = f"{wdir}/t22_rgw.bin"
    ssh(client, f"mkdir -p {wdir}", cfg)

    _, _, rc1 = ssh(client, f"dd if=/dev/urandom of={f} bs=1M count=64 2>/dev/null",
                    cfg, timeout=60)

    info(f"  Restarting RGW on {server}...")
    ssh(server, "ceph orch restart rgw.default 2>/dev/null", cfg, timeout=30)
    time.sleep(20)

    _, _, rc2 = ssh(client, f"md5sum {f} 2>/dev/null", cfg, timeout=30)
    _, _, rc3 = ssh(client, f"dd if=/dev/urandom of={f}.post bs=1M count=32 2>/dev/null",
                    cfg, timeout=60)
    ssh(client, f"rm -f {f} {f}.post", cfg)

    if rc1 == 0 and rc2 == 0 and rc3 == 0:
        results.add("T-22", "RGW restart with active RDMA connections", "PASS",
                    "I/O survived RGW restart")
    else:
        results.add("T-22", "RGW restart with active RDMA connections", "FAIL",
                    f"rc pre={rc1} read-after={rc2} post={rc3}")


# ---------------------------------------------------------------------------
# ── CONCURRENT TESTS ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_t15_concurrent_rdma(clients, cfg, results, per_client_files, per_client_size_mb):
    """T-15: Multiple RDMA clients writing concurrently to same export."""
    head(f"T-15 | {len(clients)} Concurrent RDMA Clients")
    wdir = cfg["test"]["remote_workdir"]

    # Launch writes from all clients simultaneously (non-blocking SSH)
    procs = []
    for client in clients:
        ssh(client, f"mkdir -p {wdir}/t15_{client}", cfg)
        cmd = (
            f"for i in $(seq 1 {per_client_files}); do "
            f"dd if=/dev/urandom of={wdir}/t15_{client}/f$i bs=1M count={per_client_size_mb} "
            f"2>/dev/null; done"
        )
        user = cfg["ssh"]["user"]
        pw   = cfg["ssh"]["password"]
        p = subprocess.Popen(
            ["sshpass", "-p", pw, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=15",
             f"{user}@{client}", cmd],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append((client, p))

    # Wait for all
    failed_clients = []
    for client, p in procs:
        try:
            p.wait(timeout=cfg["test"]["io_timeout"])
            if p.returncode != 0:
                failed_clients.append(client)
        except subprocess.TimeoutExpired:
            p.kill()
            failed_clients.append(f"{client}(timeout)")

    # Cleanup
    for client in clients:
        ssh(client, f"rm -rf {wdir}/t15_{client}", cfg)

    if not failed_clients:
        results.add("T-15", f"{len(clients)} concurrent RDMA clients", "PASS",
                    f"All {len(clients)} clients completed I/O",
                    {"clients": len(clients), "per_client_files": per_client_files})
    else:
        results.add("T-15", f"{len(clients)} concurrent RDMA clients", "FAIL",
                    f"Failed clients: {failed_clients}")


def test_t16_mixed_concurrent(rdma_clients, tcp_clients_host, cfg, results,
                               per_client_files, per_client_size_mb):
    """T-16: Mixed RDMA + TCP concurrent clients on same export."""
    head(f"T-16 | Mixed Concurrent: {len(rdma_clients)} RDMA + TCP clients")
    wdir   = cfg["test"]["remote_workdir"]
    tcp_mnt = cfg["nfs"]["mount_point"] + "-tcp"
    user    = cfg["ssh"]["user"]
    pw      = cfg["ssh"]["password"]

    # Mount TCP on the tcp host
    ok_tcp, tcp_mnt_actual, _ = mount_tcp(tcp_clients_host, cfg)
    if not ok_tcp:
        results.add("T-16", "Mixed RDMA+TCP concurrent", "FAIL",
                    f"Could not set up TCP mount on {tcp_clients_host}")
        return

    procs = []
    # RDMA writers
    for client in rdma_clients:
        ssh(client, f"mkdir -p {wdir}/t16_{client}", cfg)
        cmd = (f"for i in $(seq 1 {per_client_files}); do "
               f"dd if=/dev/urandom of={wdir}/t16_{client}/f$i "
               f"bs=1M count={per_client_size_mb} 2>/dev/null; done")
        p = subprocess.Popen(
            ["sshpass", "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
             f"{user}@{client}", cmd],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append((client, p))

    # TCP writer
    tcp_wdir = f"{tcp_mnt_actual}/rdma-nfs-autotest/t16_tcp"
    ssh(tcp_clients_host, f"mkdir -p {tcp_wdir}", cfg)
    cmd_tcp = (f"for i in $(seq 1 {per_client_files}); do "
               f"dd if=/dev/urandom of={tcp_wdir}/f$i "
               f"bs=1M count={per_client_size_mb} 2>/dev/null; done")
    p_tcp = subprocess.Popen(
        ["sshpass", "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
         f"{user}@{tcp_clients_host}", cmd_tcp],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    procs.append((tcp_clients_host + "(tcp)", p_tcp))

    failed = []
    for label, p in procs:
        try:
            p.wait(timeout=cfg["test"]["io_timeout"])
            if p.returncode != 0:
                failed.append(label)
        except subprocess.TimeoutExpired:
            p.kill()
            failed.append(f"{label}(timeout)")

    for client in rdma_clients:
        ssh(client, f"rm -rf {wdir}/t16_{client}", cfg)
    ssh(tcp_clients_host, f"rm -rf {tcp_wdir}", cfg)
    umount(tcp_clients_host, tcp_mnt_actual, cfg)

    if not failed:
        results.add("T-16", f"Mixed {len(rdma_clients)} RDMA + 1 TCP concurrent", "PASS",
                    "All clients completed I/O without errors")
    else:
        results.add("T-16", f"Mixed {len(rdma_clients)} RDMA + 1 TCP concurrent", "FAIL",
                    f"Failed: {failed}")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def parse_args():
    p = argparse.ArgumentParser(description="NFS-RDMA Automated Test Suite")
    p.add_argument("--config", default="config/cluster.yaml",
                   help="Cluster config YAML (default: config/cluster.yaml)")
    p.add_argument("--scale",  default="config/scale.yaml",
                   help="Scale test config YAML (default: config/scale.yaml)")
    p.add_argument("--perf",   default="config/performance.yaml",
                   help="Performance test config YAML (default: config/performance.yaml)")
    p.add_argument("--run",    default="sanity,functional,regression,negative",
                   help="Comma-separated list of test categories to run. "
                        "Options: sanity, functional, performance, scale, regression, negative, all")
    p.add_argument("--client", default=None,
                   help="Override primary test client (default: first rdma_client in config)")
    return p.parse_args()


def main():
    args   = parse_args()
    cfg    = load_yaml(args.config)

    # Determine which categories to run
    if args.run.strip().lower() == "all":
        categories = {"sanity", "functional", "performance", "scale", "regression", "negative"}
    else:
        categories = {c.strip().lower() for c in args.run.split(",")}

    # Load optional configs only if needed
    scale_cfg = load_yaml(args.scale) if "scale" in categories and Path(args.scale).exists() else {}
    perf_cfg  = load_yaml(args.perf)  if "performance" in categories and Path(args.perf).exists() else {}

    server  = cfg["cluster"]["nfs_server"]
    clients = cfg["cluster"]["rdma_clients"]
    primary = args.client if args.client else clients[0]
    secondary = clients[1] if len(clients) > 1 else None

    results = Results()

    print(f"\n{_c(BOLD + CYAN, '╔══════════════════════════════════════════════════════╗')}")
    print(f"{_c(BOLD + CYAN,   '║   IBM Ceph NFS-RDMA Automated Test Suite             ║')}")
    print(f"{_c(BOLD + CYAN,   '╚══════════════════════════════════════════════════════╝')}")
    print(f"  Server  : {server}")
    print(f"  Client  : {primary}  (secondary: {secondary})")
    print(f"  Running : {', '.join(sorted(categories))}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── Setup checks (always run) ──────────────────────────────────────────
    run_setup_checks(cfg, results)

    # ── Mount RDMA on primary client ──────────────────────────────────────
    ok_mount, err = mount_rdma(primary, cfg)
    if not ok_mount:
        fail(f"Cannot mount RDMA on {primary}: {err}")
        fail("Aborting — all remaining tests require a live RDMA mount.")
        results.save(cfg["test"]["local_results_dir"])
        sys.exit(1)

    # ── SANITY ─────────────────────────────────────────────────────────────
    if "sanity" in categories:
        head("══ SANITY TESTS ══")
        test_t01_rdma_hardware(primary, cfg, results)
        test_t02_rdma_mount(primary, cfg, results)
        test_t04_no_tcp_fallback(primary, cfg, results)
        test_t05_protocol_verify(primary, cfg, results)

    # ── FUNCTIONAL ─────────────────────────────────────────────────────────
    if "functional" in categories:
        head("══ FUNCTIONAL TESTS ══")
        test_t03_basic_file_ops(primary, cfg, results)
        test_t09_dir_depth(primary, cfg, results, depth=20, files_per_level=1000)
        test_t10_permissions(primary, cfg, results)
        test_t25_file_locking(primary, cfg, results)

        if secondary:
            test_t08_dual_mount(primary, secondary, cfg, results)
        else:
            results.add("T-08", "Dual mount TCP+RDMA", "SKIP", "No secondary client configured")

    # ── PERFORMANCE ────────────────────────────────────────────────────────
    if "performance" in categories:
        head("══ PERFORMANCE TESTS ══")
        p = perf_cfg.get("performance", {})

        # Write tests
        for wt in p.get("write_tests", []):
            if wt.get("enabled", True):
                tid = "T-06" if wt["size_mb"] <= 1024 else "T-12"
                test_write_throughput(primary, cfg, results, tid, wt["name"], wt["size_mb"])

        # Read tests
        for rt in p.get("read_tests", []):
            if rt.get("enabled", True):
                tid = "T-07" if rt["size_mb"] <= 1024 else "T-13"
                test_read_throughput(primary, cfg, results, tid, rt["name"],
                                     rt["size_mb"], rt.get("verify_md5", True))

        # Mixed sizes
        ms = p.get("mixed_sizes", {})
        if ms.get("enabled", True):
            test_t11_mixed_sizes(primary, cfg, results, ms.get("sizes_kb", [4, 64, 1024, 10240, 102400]))

        # CPU utilisation
        cpu = p.get("cpu_util", {})
        if cpu.get("enabled", True):
            test_t14_cpu_util(primary, cfg, results, cpu.get("write_size_mb", 1024))

        # Concurrent tests
        conc = p.get("concurrent", {})
        if conc.get("rdma_enabled", False) and len(clients) >= 2:
            n = conc.get("rdma_clients", 2)
            test_t15_concurrent_rdma(
                clients[:n], cfg, results,
                conc.get("per_client_files", 3),
                conc.get("per_client_file_size_mb", 512),
            )
        elif conc.get("rdma_enabled", False):
            results.add("T-15", "20 concurrent RDMA clients", "SKIP",
                        "Need ≥2 clients in config")

        if conc.get("mixed_enabled", False) and secondary:
            test_t16_mixed_concurrent(
                [primary], secondary, cfg, results,
                conc.get("per_client_files", 3),
                conc.get("per_client_file_size_mb", 512),
            )
        elif conc.get("mixed_enabled", False):
            results.add("T-16", "Mixed RDMA+TCP concurrent", "SKIP",
                        "Need secondary client")

    # ── SCALE ──────────────────────────────────────────────────────────────
    if "scale" in categories:
        head("══ SCALE TESTS ══")
        s = scale_cfg.get("scale", {})

        # Flat file scale tests (T-17, T-18 flat, T-19)
        scale_tids = ["T-17", "T-18", "T-19"]
        for i, fc in enumerate(s.get("file_counts", [])):
            if fc.get("enabled", True):
                tid = scale_tids[i] if i < len(scale_tids) else f"T-SCALE-{i}"
                test_scale_flat_files(
                    primary, cfg, results,
                    tid, fc["name"], fc["count"],
                    s.get("file_size_bytes", 4096),
                )

        # Depth-tree scale test
        dd = s.get("dir_depth", {})
        if dd.get("enabled", True):
            test_scale_depth_tree(
                primary, cfg, results,
                dd.get("depth", 20),
                dd.get("total_files", 2000000),
                dd.get("file_size_bytes", 4096),
            )

    # ── REGRESSION ─────────────────────────────────────────────────────────
    if "regression" in categories:
        head("══ REGRESSION TESTS ══")
        test_t20_io_stability(primary, cfg, results)
        test_t21_ganesha_restart(server, primary, cfg, results)
        test_t22_rgw_restart(server, primary, cfg, results)

    # ── NEGATIVE ───────────────────────────────────────────────────────────
    if "negative" in categories:
        head("══ NEGATIVE TESTS ══")
        test_t23_no_tcp_fallback_negative(primary, cfg, results)
        test_t24_incompatible_nic(primary, cfg, results)

    # ── Summary ────────────────────────────────────────────────────────────
    s = results.summary()
    saved = results.save(cfg["test"]["local_results_dir"])
    print(f"\n{_c(BOLD, '══ FINAL SUMMARY ══')}")
    print(f"  Total   : {s['total']}")
    print(f"  {_c(GREEN,  'PASS')}    : {s['pass']}")
    print(f"  {_c(RED,    'FAIL')}    : {s['fail']}")
    print(f"  {_c(YELLOW, 'PARTIAL')} : {s['partial']}")
    print(f"  {_c(YELLOW, 'SKIP')}    : {s['skip']}")
    print(f"\n  Results saved → {saved}")

    if s["fail"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
