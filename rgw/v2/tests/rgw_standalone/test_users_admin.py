"""User management + admin CLI + per-user-type CRUD smoke."""

import time

import pytest
from botocore.exceptions import ClientError

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.admin]


def test_admin_user_bucket_account_mgmt(admin, s3_client_factory, users):
    uid = f"mgmtuser-{int(time.time()) % 100000}"
    ak = f"MGMT{uid[-6:].upper()}AK"
    sk = f"MGMT{uid[-6:].upper()}SECRETKEY1234567890"

    admin.run(
        "user",
        "create",
        f"--uid={uid}",
        "--display-name=MgmtUser",
        f"--access-key={ak}",
        f"--secret-key={sk}",
        "--max-buckets=100",
    )
    info = admin.json("user", "info", f"--uid={uid}")
    assert info.get("user_id") == uid

    admin.run("user", "modify", f"--uid={uid}", "--display-name=MgmtUser2")
    info2 = admin.json("user", "info", f"--uid={uid}")
    assert info2.get("display_name") == "MgmtUser2"

    admin.run("user", "suspend", f"--uid={uid}")
    admin.run("user", "enable", f"--uid={uid}")

    endpoint = s3_client_factory("normal").meta.endpoint_url
    client = zs.make_s3_client(endpoint, ak, sk)
    bkt = zs.unique_name("admin-bkt")
    client.create_bucket(Bucket=bkt)
    client.put_object(Bucket=bkt, Key="a", Body=b"x")
    stats = admin.json("bucket", "stats", "--bucket", bkt)
    assert stats
    blist = admin.json("bucket", "list")
    assert blist is not None
    admin.run("bucket", "rm", "--bucket", bkt, "--purge-objects")

    admin.run("user", "rm", f"--uid={uid}", "--purge-data")
    ulist = admin.json("user", "list")
    assert uid not in ulist

    # account get (created in session fixture)
    acct = users["account_root"]["account_id"]
    ainfo = admin.json("account", "get", f"--account-id={acct}")
    assert ainfo.get("id") == acct


@pytest.mark.user_type
@pytest.mark.sanity
def test_user_type_bucket_object_crud(
    user_label, s3_client_factory, account_root_client
):
    """CRUD smoke for each identity type (plain/tenant/subuser/account)."""
    client = s3_client_factory(user_label)
    creator = account_root_client if user_label == "account_user" else None
    bkt = zs.unique_name("ucrud", user_label)
    zs.ensure_bucket(client, bkt, creator=creator)
    try:
        client.put_object(Bucket=bkt, Key="o1", Body=b"hello")
        assert client.get_object(Bucket=bkt, Key="o1")["Body"].read() == b"hello"
        client.head_object(Bucket=bkt, Key="o1")
        keys = {
            o["Key"]
            for o in (client.list_objects_v2(Bucket=bkt).get("Contents") or [])
        }
        assert "o1" in keys
        client.delete_object(Bucket=bkt, Key="o1")
    finally:
        wipe = account_root_client if user_label == "account_user" else client
        zs.wipe_bucket(wipe, bkt)


@pytest.mark.bug
def test_admin_metadata_needs_restart(admin, s3_client_factory, container, endpoint):
    """IBMCEPH-18508: admin user attr changes reflected without restart (expected).

    Fails if S3 still sees stale credentials/attrs until container restart.
    """
    uid = f"meta-{int(time.time()) % 100000}"
    ak = f"META{uid[-5:].upper()}AK12"
    sk = f"META{uid[-5:].upper()}SECRETKEY123456789012"
    admin.run(
        "user",
        "create",
        f"--uid={uid}",
        "--display-name=MetaUser",
        f"--access-key={ak}",
        f"--secret-key={sk}",
        "--max-buckets=50",
    )
    client = zs.make_s3_client(endpoint, ak, sk)
    bkt = zs.unique_name("meta")
    try:
        client.create_bucket(Bucket=bkt)
        # modify display name + max buckets via admin
        admin.run(
            "user",
            "modify",
            f"--uid={uid}",
            "--display-name=MetaUserUpdated",
            "--max-buckets=200",
        )
        info = admin.json("user", "info", f"--uid={uid}")
        assert info.get("display_name") == "MetaUserUpdated"
        assert int(info.get("max_buckets") or 0) >= 200

        # S3 should still work immediately (metadata live)
        client.put_object(Bucket=bkt, Key="alive", Body=b"1")
        # Create buckets up to new limit smoke (a few)
        for i in range(3):
            client.create_bucket(Bucket=f"{bkt}-extra-{i}")
            client.delete_bucket(Bucket=f"{bkt}-extra-{i}")
    except ClientError as e:
        pytest.fail(
            f"IBMCEPH-18508: admin metadata not live without restart: {e}"
        )
    finally:
        try:
            zs.wipe_bucket(client, bkt)
        except Exception:
            pass
        admin.run("user", "rm", f"--uid={uid}", "--purge-data", check=False)


@pytest.mark.bug
def test_lc_process_command_available(admin):
    """IBMCEPH-18377: rgw-standalone-admin lc process should be available."""
    p = admin.run("lc", "process", "--help", check=False)
    text = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0 and (
        "unrecognized" in text.lower()
        or "invalid command" in text.lower()
        or "no such command" in text.lower()
        or "usage" not in text.lower()
    ):
        # try without --help
        p2 = admin.run("lc", "process", check=False)
        text2 = (p2.stdout or "") + (p2.stderr or "")
        if p2.returncode != 0 and "process" not in text2.lower():
            pytest.fail(
                f"IBMCEPH-18377: 'lc process' unavailable: {text[-300:] or text2[-300:]}"
            )


@pytest.mark.bug
def test_sts_config_knob_rfe(admin, container):
    """IBMCEPH-18380 (RFE): easy way to set rgw_s3_auth_use_sts-like configs.

    Validates whether admin/config or env/conf supports the knob.
    """
    # Probe common knobs; pass if any supported path exists
    probes = [
        ("config", "get", "client.rgw", "rgw_s3_auth_use_sts"),
        ("period", "get"),
    ]
    supported = False
    details = []
    for args in probes:
        p = admin.run(*args, check=False)
        out = (p.stdout or "") + (p.stderr or "")
        details.append(f"{' '.join(args)} rc={p.returncode}")
        if p.returncode == 0 and out.strip():
            supported = True
            break
    # Also check if ceph.conf inside container has a documented place
    conf = subprocess_cat_conf(container)
    if "rgw_s3_auth_use_sts" in conf or "rgw s3 auth use sts" in conf:
        supported = True
    if not supported:
        pytest.fail(
            "IBMCEPH-18380 RFE: no easy path found to set rgw_s3_auth_use_sts; "
            + "; ".join(details)
        )


def subprocess_cat_conf(container: str) -> str:
    import subprocess

    for path in (
        "/var/lib/ceph/radosgw/ceph.conf",
        "/etc/ceph/ceph.conf",
        "/etc/ceph/rgw.conf",
    ):
        p = subprocess.run(
            ["podman", "exec", container, "cat", path],
            capture_output=True,
            text=True,
        )
        if p.returncode == 0:
            return p.stdout or ""
    return ""


@pytest.mark.bug
def test_s3browser_version_not_dev(container, rgw_config):
    """IBMCEPH-17892: S3 browser About/version should not be a bare 'dev' string."""
    import subprocess

    # Only meaningful on developer-experience image
    image = rgw_config.get("image") or ""
    inspect = subprocess.run(
        ["podman", "inspect", container, "--format", "{{.Config.Image}}"],
        capture_output=True,
        text=True,
    )
    image = image or (inspect.stdout or "").strip()
    if "developer-experience" not in image and "object-browser" not in image:
        pytest.skip("not a developer-experience / browser image")

    # Grep logs and common about endpoints
    logs = subprocess.run(
        ["podman", "logs", "--tail", "200", container],
        capture_output=True,
        text=True,
    ).stdout or ""
    about_hits = []
    for port in (
        rgw_config.get("browser_port"),
        8081,
        8091,
    ):
        if not port:
            continue
        for path in ("/about", "/api/about", "/"):
            p = subprocess.run(
                [
                    "curl",
                    "-sS",
                    f"http://127.0.0.1:{port}{path}",
                ],
                capture_output=True,
                text=True,
            )
            about_hits.append(p.stdout or "")

    blob = logs + "\n".join(about_hits)
    if "dev" in blob.lower() and "version" in blob.lower():
        # fail if we only see 'dev' without a real version token nearby
        if "v9." not in blob and "20.2" not in blob and "tentacle" not in blob.lower():
            pytest.fail(
                "IBMCEPH-17892: browser version looks like 'dev' without release version"
            )
