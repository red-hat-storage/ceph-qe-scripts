"""IBMCEPH-19128: quota discrepancies on rgw-standalone."""

import pytest
from botocore.exceptions import ClientError

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.bug, pytest.mark.feature]

QUOTA_CODES = frozenset(
    {"QuotaExceeded", "UserQuotaExceeded", "BucketQuotaExceeded"}
)


def _enable_user_quota(admin, uid, max_objects=None, max_size=None):
    args = ["quota", "set", f"--uid={uid}", "--quota-scope=user"]
    if max_objects is not None:
        args.append(f"--max-objects={max_objects}")
    if max_size is not None:
        args.append(f"--max-size={max_size}")
    admin.run(*args)
    admin.run("quota", "enable", f"--uid={uid}", "--quota-scope=user")


def _disable_user_quota(admin, uid):
    admin.run("quota", "disable", f"--uid={uid}", "--quota-scope=user", check=False)


def test_user_max_objects_quota_enforced(admin, s3_client_factory):
    uid = "testuser"
    client = s3_client_factory("normal")
    bkt = zs.unique_name("qobj")
    zs.ensure_bucket(client, bkt)
    try:
        _enable_user_quota(admin, uid, max_objects=3)
        for i in range(3):
            client.put_object(Bucket=bkt, Key=f"o{i}", Body=b"x")
        with pytest.raises(ClientError) as exc:
            client.put_object(Bucket=bkt, Key="o3", Body=b"x")
        code = exc.value.response.get("Error", {}).get("Code", "")
        assert code in QUOTA_CODES, f"unexpected code {code}"
    finally:
        _disable_user_quota(admin, uid)
        zs.wipe_bucket(client, bkt)


def test_user_max_size_quota_enforced(admin, s3_client_factory):
    uid = "testuser"
    client = s3_client_factory("normal")
    bkt = zs.unique_name("qsize")
    zs.ensure_bucket(client, bkt)
    try:
        # 2 KiB max
        _enable_user_quota(admin, uid, max_size=2048)
        client.put_object(Bucket=bkt, Key="small", Body=b"x" * 1024)
        with pytest.raises(ClientError) as exc:
            client.put_object(Bucket=bkt, Key="big", Body=b"x" * 4096)
        code = exc.value.response.get("Error", {}).get("Code", "")
        assert code in QUOTA_CODES, f"unexpected code {code}"
    finally:
        _disable_user_quota(admin, uid)
        zs.wipe_bucket(client, bkt)


def test_bucket_quota_enforced(admin, s3_client_factory):
    uid = "testuser"
    client = s3_client_factory("normal")
    bkt = zs.unique_name("qbkt")
    zs.ensure_bucket(client, bkt)
    try:
        admin.run(
            "quota",
            "set",
            f"--uid={uid}",
            f"--bucket={bkt}",
            "--quota-scope=bucket",
            "--max-objects=2",
        )
        admin.run(
            "quota",
            "enable",
            f"--uid={uid}",
            f"--bucket={bkt}",
            "--quota-scope=bucket",
        )
        client.put_object(Bucket=bkt, Key="a", Body=b"1")
        client.put_object(Bucket=bkt, Key="b", Body=b"2")
        with pytest.raises(ClientError) as exc:
            client.put_object(Bucket=bkt, Key="c", Body=b"3")
        code = exc.value.response.get("Error", {}).get("Code", "")
        assert code in QUOTA_CODES, f"unexpected code {code}"
    finally:
        admin.run(
            "quota",
            "disable",
            f"--uid={uid}",
            f"--bucket={bkt}",
            "--quota-scope=bucket",
            check=False,
        )
        zs.wipe_bucket(client, bkt)
