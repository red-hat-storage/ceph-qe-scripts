# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
ibmceph_discover.py - fill in the cluster details the suite needs.

cephci runs the suite with a committed config that holds placeholders only
(`run_ibmceph_19403.py -c <config> --rgw-node <ip>`).  Everything the config
leaves unset is discovered here from the cephadm orchestrator, and an S3 user
is created (and removed again) when no keys are given.  Values that the config
sets explicitly are never overwritten.
"""

import glob
import json
import logging
import os
import re
import sys

log = logging.getLogger()

UID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TEST_USER = "ibmceph-test"


def unset(value):
    """True for an empty value or a placeholder such as RGW_A_IP or <fsid>."""
    return not value or "<" in str(value) or "RGW_" in str(value)


def add_system_rados():
    """Make the distro `rados` module importable from a plain venv."""
    try:
        import rados  # noqa: F401

        return True
    except ImportError:
        pass
    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    for base in (f"/usr/lib64/{ver}", f"/usr/lib/{ver}"):
        site = os.path.join(base, "site-packages")
        if glob.glob(os.path.join(site, "rados*.so")):
            sys.path.append(site)  # appended: venv packages keep priority
            return True
    return False


def _json(text):
    start = min((i for i in (text.find("["), text.find("{")) if i >= 0), default=-1)
    return json.loads(text[start:]) if start >= 0 else None


def cephadm_args(env):
    """Extra `cephadm shell` arguments for a node that is not a cephadm admin."""
    if UID_RE.search(env.sh("ceph fsid", timeout=60)):
        return []
    fsid = ""
    try:
        with open("/etc/ceph/ceph.conf") as f:
            m = UID_RE.search(f.read())
            fsid = m.group(0) if m else ""
    except OSError:
        return []
    for keyring in ("/etc/ceph/ceph.keyring", "/etc/ceph/ceph.client.admin.keyring"):
        if fsid and os.path.exists(keyring):
            return ["--fsid", fsid, "-c", "/etc/ceph/ceph.conf", "-k", keyring]
    return []


def discover_topology(env, rgw_node=""):
    """RGW-A / RGW-B urls, hosts, daemon, container and unit names."""
    fsid = UID_RE.search(env.sh("ceph fsid", timeout=60)).group(0)
    daemons = _json(env.sh("ceph orch ps --daemon-type rgw --format json"))
    hosts = _json(env.sh("ceph orch host ls --format json"))
    addr = {h["hostname"]: h.get("addr") or h["hostname"] for h in hosts}
    running = [d for d in daemons if d.get("status_desc") == "running"]
    if len(running) < 2:
        raise RuntimeError(f"need two running RGW daemons, found {len(running)}")
    # RGW-B is the daemon on the node cephci selected, RGW-A is another one
    b = next(
        (
            d
            for d in running
            if rgw_node in (addr[d["hostname"]], d["hostname"]) and rgw_node
        ),
        running[-1],
    )
    a = next(d for d in running if d is not b)
    for side, d in (("a", a), ("b", b)):
        name = d["daemon_name"]
        host = addr[d["hostname"]]
        port = (d.get("ports") or [80])[0]
        setattr(env, f"{side}_url", f"http://{host}:{port}")
        setattr(env, f"{side}_host", host)
        setattr(env, f"{side}_daemon", f"client.{name}")
        setattr(env, f"{side}_unit", f"ceph-{fsid}@{name}")
        if side == "a":
            env.a_container = f"ceph-{fsid}-{name.replace('.', '-')}"
    log.info(
        "discovered RGW-A %s (%s) and RGW-B %s (%s)",
        env.a_daemon,
        env.a_host,
        env.b_daemon,
        env.b_host,
    )


def ensure_user(env):
    """Set S3 keys; creates the test user when none are given. True if created."""
    if env.access_key and env.secret_key:
        return False
    out = env.sh(f"radosgw-admin user info --uid {TEST_USER}")
    created = False
    info = None
    try:
        info = _json(out)
    except ValueError:
        pass
    if not info:
        out = env.sh(
            f"radosgw-admin user create --uid {TEST_USER} --display-name {TEST_USER}"
        )
        info = _json(out)
        created = True
    key = info["keys"][0]
    env.access_key, env.secret_key = key["access_key"], key["secret_key"]
    log.info("S3 user %s %s", TEST_USER, "created" if created else "reused")
    return created


def remove_user(env):
    env.sh(f"radosgw-admin user rm --uid {TEST_USER} --purge-data")


def autofill(env, rgw_node=""):
    """Fill whatever the config left unset; returns True if the user was created."""
    if env.cli == "cephadm" and not env.cephadm_args:
        try:
            env.cephadm_args = cephadm_args(env)
        except Exception as e:
            log.warning("cephadm shell arguments not detected: %s", e)
    if unset(env.a_daemon) or unset(env.b_daemon):
        try:
            discover_topology(env, rgw_node)
        except Exception as e:
            log.warning("RGW topology not discovered (lab tests will skip): %r", e)
    if rgw_node and unset(env.b_url):
        env.b_url = f"http://{rgw_node}:80"
    try:
        return ensure_user(env)
    except Exception as e:
        log.warning("S3 user not set up: %r", e)
        return False
