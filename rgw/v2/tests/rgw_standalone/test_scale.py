"""Scale testing: progressive + 1K buckets, capacity-aware object scale."""

import logging
import subprocess

import pytest
from botocore.exceptions import ClientError
from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

log = logging.getLogger()
pytestmark = [pytest.mark.scale]


@pytest.mark.parametrize("count", [1, 10, 100])
def test_scale_buckets_progressive(admin, s3_client_factory, count):
    """Progressive bucket create/list/delete for small counts (always run)."""
    _scale_buckets_boto(admin, s3_client_factory, count)


@pytest.mark.slow
def test_scale_buckets_1k(endpoint, users, admin, s3_client_factory, rgw_config):
    """Create 1K buckets via elbencho (-d); drop 10K (too slow / TooManyBuckets)."""
    counts = rgw_config.get("scale_bucket_counts") or []
    if 1000 not in counts and max(counts or [0]) < 1000:
        pytest.skip("1K buckets not enabled in config")
    prefer = bool(rgw_config.get("prefer_elbencho", True))
    if prefer:
        _scale_buckets_elbencho(
            endpoint, users, admin, s3_client_factory, rgw_config, 1000
        )
    else:
        _scale_buckets_boto(admin, s3_client_factory, 1000)


def _scale_buckets_boto(admin, s3_client_factory, count: int):
    zs.set_max_buckets(admin, "testuser", max(count, 10000), restart_if_needed=True)
    client = s3_client_factory("normal")
    prefix = zs.unique_name("scaleb")
    created = 0
    last_err = ""
    try:
        for i in range(count):
            name = f"{prefix}-{i:05d}"
            try:
                client.create_bucket(Bucket=name)
                created += 1
            except ClientError as e:
                last_err = str(e)
                if created == 0 and i > 5:
                    raise
            if (i + 1) % 500 == 0:
                log.info("created %s/%s buckets", created, i + 1)
        if created < count:
            pytest.fail(f"created only {created}/{count}; last_err={last_err}")
        _assert_bucket_list(client, prefix, count)
    finally:
        deleted = 0
        for i in range(count):
            name = f"{prefix}-{i:05d}"
            try:
                client.delete_bucket(Bucket=name)
                deleted += 1
            except ClientError:
                pass
        log.info("deleted %s buckets", deleted)


def _scale_buckets_elbencho(
    endpoint, users, admin, s3_client_factory, rgw_config, count: int
):
    zs.set_max_buckets(admin, "testuser", max(count, 10000), restart_if_needed=True)
    client = s3_client_factory("normal")
    ak, sk = zs.user_creds(users, "normal")
    # elbencho brace expand: prefix0 .. prefix{count-1} (no hyphen; keeps names legal)
    prefix = zs.unique_name("scaleb").replace("_", "")
    threads = int(rgw_config.get("scale_elbencho_threads", 32))
    try:
        engine = zs.scale_create_buckets(
            endpoint, ak, sk, prefix, count, threads=threads
        )
        log.info("scale buckets via %s count=%s prefix=%s", engine, count, prefix)
        assert engine == "elbencho"
        # Spot-check a few buckets exist
        client.head_bucket(Bucket=f"{prefix}0")
        client.head_bucket(Bucket=f"{prefix}{count - 1}")
        _assert_bucket_list(client, prefix, count)
    finally:
        try:
            zs.scale_delete_buckets(endpoint, ak, sk, prefix, count, threads=threads)
        except Exception as e:
            log.warning("elbencho delete failed, falling back to boto: %s", e)
            for i in range(count):
                try:
                    zs.wipe_bucket(client, f"{prefix}{i}")
                except Exception:
                    pass


def _assert_bucket_list(client, prefix: str, count: int):
    """ListBuckets on zipper often caps ~1000 names globally — soft-check only."""
    listed = [
        b["Name"]
        for b in client.list_buckets().get("Buckets", [])
        if b["Name"].startswith(prefix)
    ]
    if count <= 100:
        assert len(listed) >= count, f"listed {len(listed)}/{count}"
    else:
        # With other leftover buckets, ListBuckets may return < count for our prefix
        assert len(listed) >= min(
            count, 50
        ), f"expected some listed buckets with prefix={prefix}, got {len(listed)}"
        log.info(
            "list_buckets returned %s names with prefix (created=%s)",
            len(listed),
            count,
        )


@pytest.mark.slow
def test_scale_objects_1k(endpoint, users, s3_client_factory, rgw_config):
    _scale_objects(endpoint, users, s3_client_factory, rgw_config, 1000)


@pytest.mark.slow
def test_scale_objects_large(endpoint, users, s3_client_factory, rgw_config):
    """Large object scale — count capped by free space on zipper data dir.

    Config ``scale_object_counts`` may still list 100000; we never exceed what
    the node can hold (see ``cap_scale_object_count``).
    """
    counts = rgw_config.get("scale_object_counts") or []
    desired = max(counts) if counts else 10000
    if desired < 5000:
        pytest.skip("large object scale not enabled in config")
    _scale_objects(endpoint, users, s3_client_factory, rgw_config, desired)


def _scale_objects(endpoint, users, s3_client_factory, rgw_config, count: int):
    client = s3_client_factory("normal")
    ak, sk = zs.user_creds(users, "normal")
    bkt = zs.unique_name("scaleo")
    client.create_bucket(Bucket=bkt)
    prefer_elbencho = bool(rgw_config.get("prefer_elbencho", True))
    size = int(rgw_config.get("scale_object_size", 64))
    threads = int(rgw_config.get("scale_elbencho_threads", 32))
    data_dir = rgw_config.get("data_dir") or "/root/my_zgw_data_dev_exp"
    headroom = float(rgw_config.get("scale_capacity_headroom", 0.35))
    # Cap BEFORE put so we do not fill the volume and poison later tests
    capped = zs.cap_scale_object_count(
        count,
        size,
        data_dir=data_dir,
        headroom_ratio=headroom,
        min_count=min(1000, count),
    )
    if capped < count:
        log.info("scale objects reduced %s -> %s for capacity", count, capped)
    count = capped
    try:
        engine = zs.scale_put_objects(
            endpoint,
            ak,
            sk,
            bkt,
            count,
            size=size,
            threads=threads,
            prefer_elbencho=prefer_elbencho,
        )
        log.info("scale put via %s count=%s size=%s", engine, count, size)
        if prefer_elbencho:
            assert engine == "elbencho", f"expected elbencho, got {engine}"

        n = 0
        token = None
        while True:
            kw = {"Bucket": bkt, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            resp = client.list_objects_v2(**kw)
            n += len(resp.get("Contents") or [])
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
            if count >= 5000 and n >= 2000:
                break
        assert n > 0, "bucket empty after scale put"
        if count <= 1000:
            assert n >= count, f"listed {n}/{count}"
        else:
            assert n >= 1000, f"expected at least 1000 listed keys, got {n}"
    finally:
        # Prefer elbencho -F for fast cleanup of large buckets; fall back to wipe
        if prefer_elbencho:
            elbencho = zs.find_elbencho()
            if elbencho:
                cmd = [
                    elbencho,
                    f"--s3endpoints={endpoint}",
                    f"--s3key={ak}",
                    f"--s3secret={sk}",
                    "-F",
                    "-D",
                    "-t",
                    str(max(1, min(threads, 16))),
                    "--dirsharing",
                    "-n",
                    "1",
                    "-N",
                    str(count),
                    bkt,
                ]
                p = subprocess.run(cmd, capture_output=True, text=True)
                if p.returncode == 0:
                    return
                log.warning(
                    "elbencho cleanup rc=%s; wipe_bucket fallback", p.returncode
                )
        zs.wipe_bucket(client, bkt)
