"""
Helpers for RGW Standalone (Zipper) pytest automation.

Adapted from QE scripts embedded in zipper_QE_test_results reports
(rgw_zipper_test_report_on_92_rc_build, user_crud, quota, object-lock, etc.).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from urllib.parse import urlparse

import boto3
from botocore.client import Config as BotoConfig
from botocore.exceptions import ClientError

log = logging.getLogger()

DEFAULT_USERS = {
    "normal": {
        "uid": "testuser",
        "display_name": "Test User",
        "ak": "TESTUSERAK",
        "sk": "TESTUSERSECRETKEY1234567890",
    },
    "tenant": {
        "uid": "tenantuser",
        "tenant": "tenant1",
        "display_name": "Tenant User",
        "ak": "TENANTUSERAK",
        "sk": "TENANTUSERSECRETKEY123456789",
        "s3_uid": "tenant1$tenantuser",
    },
    "subuser": {
        "parent_uid": "testuser",
        "subuser": "sub1",
        "ak": "SUBUSERAK",
        "sk": "SUBUSERSECRETKEY123456789012",
        "s3_uid": "testuser:sub1",
        "access": "full",
    },
    "account_root": {
        "uid": "AcctRoot",
        "display_name": "Account Root",
        "ak": "ACCTROOTAK",
        "sk": "ACCTROOTSECRETKEY1234567890",
        "account_id": "RGW12345678901234567",
        "account_name": "ZipperAcct",
        "account_root": True,
    },
    "account_user": {
        "uid": "AcctUser1",
        "display_name": "Account User1",
        "ak": "ACCTUSER1AK",
        "sk": "ACCTUSER1SECRETKEY123456789",
        "account_id": "RGW12345678901234567",
        "attach_policy": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    },
}

OBJECT_SIZES = {
    "small": 64,
    "medium": 256 * 1024,
    "large": 8 * 1024 * 1024,
}


class ZipperAdmin:
    """Wrap podman exec <cid> rgw-standalone-admin ..."""

    def __init__(
        self,
        container: str,
        admin_bin: str = "rgw-standalone-admin",
        conf: Optional[str] = None,
    ):
        self.container = container
        self.admin_bin = admin_bin
        self.conf = conf

    def run(self, *args: str, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
        cmd = ["podman", "exec", self.container, self.admin_bin]
        if self.conf:
            cmd.extend(["-c", self.conf])
        cmd.extend(args)
        log.info("admin: %s", " ".join(cmd[3:]))
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise RuntimeError(
                f"admin {' '.join(args)} rc={p.returncode}: "
                f"{(p.stderr or p.stdout)[-800:]}"
            )
        return p

    def text(self, *args: str, **kwargs) -> str:
        return self.run(*args, **kwargs).stdout

    def json(self, *args: str, **kwargs) -> Any:
        out = self.text(*args, **kwargs)
        combined = out
        for i, ch in enumerate(combined):
            if ch in "{[":
                try:
                    return json.loads(combined[i:])
                except json.JSONDecodeError:
                    continue
        for opener in ("{", "["):
            idx = combined.rfind(opener)
            if idx >= 0:
                try:
                    return json.loads(combined[idx:])
                except json.JSONDecodeError:
                    pass
        raise RuntimeError(f"no json from admin {' '.join(args)}: {combined[-400:]}")


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def make_s3_client(
    endpoint: str,
    ak: str,
    sk: str,
    region: str = "default",
    max_pool_connections: int = 50,
):
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        region_name=region,
        config=BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3},
            max_pool_connections=max_pool_connections,
        ),
    )


def make_iam_client(endpoint: str, ak: str, sk: str, region: str = "default"):
    return boto3.client(
        "iam",
        endpoint_url=endpoint,
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        region_name=region,
        config=BotoConfig(signature_version="s3v4", retries={"max_attempts": 2}),
    )


def unique_name(prefix: str, label: str = "") -> str:
    suffix = f"{label}-" if label else ""
    return f"{prefix}-{suffix}{int(time.time() * 1000) % 10000000}".lower().replace(
        "_", "-"
    )[:60]


def ensure_bucket(client, bucket: str, creator=None):
    """Create bucket; optionally fall back to creator client (account root)."""
    try:
        client.create_bucket(Bucket=bucket)
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            return
        if creator is None:
            raise
        if code not in {"AccessDenied", "403"}:
            raise
    creator.create_bucket(Bucket=bucket)


def wipe_bucket(client, bucket: str):
    """Best-effort empty + delete bucket (including versions/delete markers)."""
    try:
        # non-versioned
        token = None
        while True:
            kw = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            resp = client.list_objects_v2(**kw)
            objs = [{"Key": o["Key"]} for o in (resp.get("Contents") or [])]
            if objs:
                client.delete_objects(
                    Bucket=bucket, Delete={"Objects": objs, "Quiet": True}
                )
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        # versioned
        try:
            key_marker = None
            ver_marker = None
            while True:
                kw = {"Bucket": bucket}
                if key_marker:
                    kw["KeyMarker"] = key_marker
                if ver_marker:
                    kw["VersionIdMarker"] = ver_marker
                resp = client.list_object_versions(**kw)
                to_del = []
                for v in resp.get("Versions") or []:
                    to_del.append({"Key": v["Key"], "VersionId": v["VersionId"]})
                for m in resp.get("DeleteMarkers") or []:
                    to_del.append({"Key": m["Key"], "VersionId": m["VersionId"]})
                if to_del:
                    client.delete_objects(
                        Bucket=bucket, Delete={"Objects": to_del, "Quiet": True}
                    )
                if not resp.get("IsTruncated"):
                    break
                key_marker = resp.get("NextKeyMarker")
                ver_marker = resp.get("NextVersionIdMarker")
        except ClientError:
            pass
        client.delete_bucket(Bucket=bucket)
    except ClientError as e:
        log.warning("wipe_bucket %s: %s", bucket, e)


def zipper_health(container: str, endpoint: str, expect_nginx: bool = False) -> str:
    """Validate zipper container process + endpoint responsiveness."""
    top = subprocess.run(
        ["podman", "top", container], capture_output=True, text=True
    )
    inspect = subprocess.run(
        [
            "podman",
            "inspect",
            container,
            "--format",
            "{{.State.Status}} {{.State.OOMKilled}} {{.RestartCount}}",
        ],
        capture_output=True,
        text=True,
    )
    logs = subprocess.run(
        ["podman", "logs", "--tail", "40", container],
        capture_output=True,
        text=True,
    )
    status = (inspect.stdout or "").strip()
    if "running" not in status.lower() and not status.startswith("running"):
        # format is "running false 0"
        parts = status.split()
        if not parts or parts[0] != "running":
            raise RuntimeError(f"container not running: {status}")
    if "true" in status.split():  # OOMKilled
        # only fail if OOMKilled token is true (2nd field)
        fields = status.split()
        if len(fields) >= 2 and fields[1].lower() == "true":
            raise RuntimeError(f"container OOMKilled: {status}")

    top_out = top.stdout or ""
    if "rgw" not in top_out.lower() and "radosgw" not in top_out.lower():
        # developer-experience has rgw-standalone process name
        if "standalone" not in top_out.lower():
            raise RuntimeError(f"rgw process missing: {top_out[:400]}")
    if expect_nginx and "nginx" not in top_out.lower():
        log.warning("nginx not in process list (ok for plain rgw-standalone image)")

    bad = any(
        x in (logs.stdout or "").lower()
        for x in ("segfault", "fatal signal", "assertion")
    )
    if bad:
        raise RuntimeError(f"bad logs: {(logs.stdout or '')[-500:]}")

    parsed = urlparse(endpoint)
    probe = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}/"
    r = subprocess.run(
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--connect-timeout",
            "5",
            probe,
        ],
        capture_output=True,
        text=True,
    )
    if (r.stdout or "").strip() not in {"200", "403", "400", "405"}:
        raise RuntimeError(
            f"endpoint unhealthy http={r.stdout} err={r.stderr}"
        )
    return f"ok status={status}"


def restart_container(container: str, wait_s: int = 15):
    subprocess.run(["podman", "restart", container], check=True)
    time.sleep(wait_s)


def setup_default_users(admin: ZipperAdmin, users: dict = None) -> dict:
    """Create plain/tenant/subuser/account users used by the suite."""
    users = users or DEFAULT_USERS

    # Account first
    acct = users["account_root"]
    admin.run(
        "account",
        "create",
        f"--account-id={acct['account_id']}",
        f"--account-name={acct['account_name']}",
        "--max-users=1000",
        "--max-buckets=10000",
        check=False,
    )

    # Plain user
    u = users["normal"]
    admin.run(
        "user",
        "create",
        f"--uid={u['uid']}",
        f"--display-name={u['display_name']}",
        f"--access-key={u['ak']}",
        f"--secret-key={u['sk']}",
        "--max-buckets=10000",
        check=False,
    )

    # Tenant user
    t = users["tenant"]
    admin.run(
        "user",
        "create",
        f"--uid={t['uid']}",
        f"--tenant={t['tenant']}",
        f"--display-name={t['display_name']}",
        f"--access-key={t['ak']}",
        f"--secret-key={t['sk']}",
        "--max-buckets=1000",
        check=False,
    )

    # Subuser
    s = users["subuser"]
    admin.run(
        "subuser",
        "create",
        f"--uid={s['parent_uid']}",
        f"--subuser={s['subuser']}",
        f"--access={s['access']}",
        f"--key-type=s3",
        f"--access-key={s['ak']}",
        f"--secret-key={s['sk']}",
        check=False,
    )

    # Account root
    admin.run(
        "user",
        "create",
        f"--uid={acct['uid']}",
        f"--display-name={acct['display_name']}",
        f"--access-key={acct['ak']}",
        f"--secret-key={acct['sk']}",
        f"--account-id={acct['account_id']}",
        "--account-root",
        "--max-buckets=10000",
        check=False,
    )

    # Account non-root — attach managed policy BEFORE any S3 use
    # (workaround for IBMCEPH-18508 sticky AccessDenied)
    au = users["account_user"]
    admin.run(
        "user",
        "create",
        f"--uid={au['uid']}",
        f"--display-name={au['display_name']}",
        f"--access-key={au['ak']}",
        f"--secret-key={au['sk']}",
        f"--account-id={au['account_id']}",
        "--max-buckets=1000",
        check=False,
    )
    if au.get("attach_policy"):
        admin.run(
            "user",
            "policy",
            "attach",
            f"--uid={au['uid']}",
            f"--policy-arn={au['attach_policy']}",
            check=False,
        )

    return users


def user_creds(users: dict, label: str) -> tuple[str, str]:
    u = users[label]
    return u["ak"], u["sk"]


def multipart_upload(
    client,
    bucket: str,
    key: str,
    data: bytes,
    part_size: int = 5 * 1024 * 1024,
) -> dict:
    """Upload data via MPU; returns {UploadId, Parts, ETag}."""
    uid = client.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    parts = []
    part_num = 1
    for i in range(0, len(data), part_size):
        chunk = data[i : i + part_size]
        resp = client.upload_part(
            Bucket=bucket,
            Key=key,
            PartNumber=part_num,
            UploadId=uid,
            Body=chunk,
        )
        parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
        part_num += 1
    complete = client.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=uid,
        MultipartUpload={"Parts": parts},
    )
    return {"UploadId": uid, "Parts": parts, "ETag": complete.get("ETag")}


ELBENCHO_BIN = "/usr/local/bin/elbencho"
ELBENCHO_TARBALL_URL = (
    "https://github.com/breuner/elbencho/releases/download/v3.0-25/"
    "elbencho-static-x86_64.tar.gz"
)


def find_elbencho() -> Optional[str]:
    """Return path to elbencho binary if present."""
    which = subprocess.run(
        ["bash", "-lc", f"command -v elbencho || command -v {ELBENCHO_BIN}"],
        capture_output=True,
        text=True,
    )
    path = (which.stdout or "").strip()
    return path or None


def ensure_elbencho() -> str:
    """Install elbencho if missing (same artifact as s3_swift/rgw_s3_elbencho)."""
    existing = find_elbencho()
    if existing:
        ver = subprocess.run(
            [existing, "--version"], capture_output=True, text=True
        )
        log.info("elbencho present: %s", (ver.stdout or ver.stderr or existing).strip())
        return existing

    log.info("elbencho not found; installing from %s", ELBENCHO_TARBALL_URL)
    cmds = [
        f"wget -q {ELBENCHO_TARBALL_URL} -O /tmp/elbencho-static-x86_64.tar.gz "
        f"|| curl -fsSL -o /tmp/elbencho-static-x86_64.tar.gz {ELBENCHO_TARBALL_URL}",
        "tar -xf /tmp/elbencho-static-x86_64.tar.gz -C /tmp",
        f"sudo mv /tmp/elbencho {ELBENCHO_BIN} 2>/dev/null || mv /tmp/elbencho {ELBENCHO_BIN}",
        f"sudo chmod +x {ELBENCHO_BIN} 2>/dev/null || chmod +x {ELBENCHO_BIN}",
        f"{ELBENCHO_BIN} --version",
        "rm -f /tmp/elbencho-static-x86_64.tar.gz",
    ]
    for cmd in cmds:
        p = subprocess.run(
            ["bash", "-lc", cmd], capture_output=True, text=True
        )
        if p.returncode != 0:
            raise RuntimeError(
                f"elbencho install failed ({cmd}): "
                f"{(p.stderr or p.stdout or '')[-500:]}"
            )
        if p.stdout:
            log.info("%s", p.stdout.strip())

    path = find_elbencho()
    if not path:
        raise RuntimeError("elbencho install completed but binary not found")
    return path


def scale_put_objects(
    endpoint: str,
    ak: str,
    sk: str,
    bucket: str,
    count: int,
    size: int = 64,
    threads: int = 32,
    prefer_elbencho: bool = True,
) -> str:
    """Put `count` objects via elbencho (install if needed) or boto3 fallback.

    Elbencho CLI matches s3_swift/rgw_s3_elbencho QE:
      elbencho --s3endpoints URL --s3key AK --s3secret SK \\
        -w -t THREADS -n0 -N COUNT -s SIZE BUCKET
    """
    if prefer_elbencho:
        elbencho = ensure_elbencho()
        # Cap threads for small counts; still use enough concurrency for scale.
        t = max(1, min(threads, count))
        size_arg = str(size) if size >= 1024 else f"{size}"
        cmd = [
            elbencho,
            f"--s3endpoints={endpoint}",
            f"--s3key={ak}",
            f"--s3secret={sk}",
            "-w",
            "-t",
            str(t),
            "-n0",
            "-N",
            str(count),
            "-s",
            size_arg,
            bucket,
        ]
        log.info(
            "elbencho scale put: bin=%s endpoint=%s bucket=%s -w -t %s -n0 -N %s -s %s",
            elbencho,
            endpoint,
            bucket,
            t,
            count,
            size_arg,
        )
        p = subprocess.run(cmd, capture_output=True, text=True)
        out = (p.stdout or "") + (p.stderr or "")
        if p.returncode != 0:
            raise RuntimeError(f"elbencho failed rc={p.returncode}: {out[-800:]}")
        log.info("elbencho finished ok (%s bytes log)", len(out))
        return "elbencho"

    # boto3 fallback (prefer_elbencho=false); enlarge pool to avoid urllib3 warnings
    client = make_s3_client(
        endpoint, ak, sk, max_pool_connections=max(50, threads * 2)
    )
    body = b"x" * size
    errors = 0

    def one(i: int):
        client.put_object(Bucket=bucket, Key=f"o/{i:06d}", Body=body)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(one, i) for i in range(count)]
        done = 0
        for f in as_completed(futs):
            done += 1
            try:
                f.result()
            except Exception:
                errors += 1
            if done % 5000 == 0:
                log.info("scale put %s/%s errors=%s", done, count, errors)
    if errors:
        raise RuntimeError(f"put errors={errors}/{count}")
    return "boto3"


def set_max_buckets(admin: ZipperAdmin, uid: str, max_buckets: int, restart_if_needed: bool = True):
    """Raise user max_buckets; restart container if value does not take effect."""
    admin.run("user", "modify", f"--uid={uid}", f"--max-buckets={max_buckets}")
    info = admin.json("user", "info", f"--uid={uid}")
    mb = int(info.get("max_buckets") or 0)
    if mb >= max_buckets:
        return mb
    if not restart_if_needed:
        raise RuntimeError(f"max_buckets still {mb} after modify")
    log.warning("max_buckets=%s after modify; restarting container", mb)
    restart_container(admin.container)
    info = admin.json("user", "info", f"--uid={uid}")
    mb = int(info.get("max_buckets") or 0)
    if mb < max_buckets:
        raise RuntimeError(f"max_buckets still {mb} after restart")
    return mb


def epoch_timestamp(dt) -> bool:
    """True if datetime looks like unix epoch / 1970-01-01."""
    if dt is None:
        return True
    try:
        return int(dt.timestamp()) == 0
    except Exception:
        return "1970-01-01" in str(dt)
