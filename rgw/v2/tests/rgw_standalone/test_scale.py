"""Scale testing: 1..10K buckets (max_buckets) and up to 100K objects."""

import logging

import pytest
from botocore.exceptions import ClientError

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

log = logging.getLogger()
pytestmark = [pytest.mark.scale]


@pytest.mark.parametrize("count", [1, 10, 100])
def test_scale_buckets_progressive(admin, s3_client_factory, count):
    """Progressive bucket create/list/delete for small counts (always run)."""
    _scale_buckets(admin, s3_client_factory, count)


@pytest.mark.slow
def test_scale_buckets_1k(admin, s3_client_factory, rgw_config):
    counts = rgw_config.get("scale_bucket_counts") or []
    if 1000 not in counts and max(counts or [0]) < 1000:
        pytest.skip("1K buckets not enabled in config")
    _scale_buckets(admin, s3_client_factory, 1000)


@pytest.mark.slow
def test_scale_buckets_10k(admin, s3_client_factory, rgw_config):
    counts = rgw_config.get("scale_bucket_counts") or []
    target = 10000
    if target not in counts and max(counts or [0]) < target:
        pytest.skip("10K buckets not enabled in config")
    _scale_buckets(admin, s3_client_factory, target)


def _scale_buckets(admin, s3_client_factory, count: int):
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

        listed = [
            b["Name"]
            for b in client.list_buckets().get("Buckets", [])
            if b["Name"].startswith(prefix)
        ]
        # Zipper/list_buckets may cap ~1000 names without continuation
        if count <= 1000:
            assert len(listed) >= count, f"listed {len(listed)}/{count}"
        else:
            assert len(listed) >= 1000, (
                f"expected ListBuckets to return ~1000 names, got {len(listed)}"
            )
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


@pytest.mark.slow
def test_scale_objects_1k(endpoint, users, s3_client_factory, rgw_config):
    _scale_objects(endpoint, users, s3_client_factory, rgw_config, 1000)


@pytest.mark.slow
def test_scale_objects_100k(endpoint, users, s3_client_factory, rgw_config):
    counts = rgw_config.get("scale_object_counts") or []
    if 100000 not in counts and max(counts or [0]) < 100000:
        pytest.skip("100K objects not enabled in config")
    _scale_objects(endpoint, users, s3_client_factory, rgw_config, 100000)


def _scale_objects(endpoint, users, s3_client_factory, rgw_config, count: int):
    client = s3_client_factory("normal")
    ak, sk = zs.user_creds(users, "normal")
    bkt = zs.unique_name("scaleo")
    client.create_bucket(Bucket=bkt)
    prefer_elbencho = bool(rgw_config.get("prefer_elbencho", True))
    try:
        engine = zs.scale_put_objects(
            endpoint,
            ak,
            sk,
            bkt,
            count,
            size=int(rgw_config.get("scale_object_size", 64)),
            threads=int(rgw_config.get("scale_elbencho_threads", 32)),
            prefer_elbencho=prefer_elbencho,
        )
        log.info("scale put via %s count=%s", engine, count)
        if prefer_elbencho:
            assert engine == "elbencho", f"expected elbencho, got {engine}"

        # Spot-check listing: elbencho uses its own key layout under the bucket
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
            # Avoid scanning all 100k keys in CI smoke; sample first pages
            if count >= 10000 and n >= 2000:
                break
        assert n > 0, "bucket empty after scale put"
        if count <= 1000:
            assert n >= count, f"listed {n}/{count}"
        else:
            assert n >= 1000, f"expected at least 1000 listed keys, got {n}"
    finally:
        zs.wipe_bucket(client, bkt)
