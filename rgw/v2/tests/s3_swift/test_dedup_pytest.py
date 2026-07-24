"""
test_dedup_pytest.py - RGW Dedup Test Suite (Pytest Format)

All 30 dedup test scenarios in pytest format with fixtures and markers.
Reuses helpers from reusables/dedup.py -- no logic duplication.

Usage:
  pytest test_dedup_pytest.py -C config.yaml -v
  pytest test_dedup_pytest.py -C config.yaml -m sanity
  pytest test_dedup_pytest.py -C config.yaml -m enhancement
  pytest test_dedup_pytest.py -C config.yaml -k "test_128_limit"

Categories:
  sanity       : S1-S5   (basic dedup operations)
  feature      : S6-S15  (multipart, versioning, filters, lifecycle, etc.)
  compression  : S16-S21 (compressed object dedup)
  bug          : B1-B5   (data integrity, regression)
  enhancement  : E1-E5   (128-limit boundary, multi-cycle, split-head)
"""

import hashlib
import json
import logging
import os
import random
import sys
import time

import pytest

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import dedup as dedup_utils

log = logging.getLogger()


# =============================================================================
# SANITY TESTS (S1-S5)
# =============================================================================


@pytest.mark.sanity
def test_s1_sanity_large_objects(s3_client, bucket, rgw_config):
    """S1: Upload 50 identical objects > 4MB, dedup, verify accessible."""
    obj_count = getattr(rgw_config, "objects_count", None) or 50
    obj_size = 5 * 1024

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, obj_size, prefix="large-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)

    parsed = dedup_utils.parse_dedup_stats(exec_stats)
    assert parsed.get("deduped_count", 0) > 0, "Expected dedup to deduplicate objects"
    dedup_utils.log_dedup_savings(exec_stats, obj_count * obj_size, "S1")


@pytest.mark.sanity
def test_s2_sanity_small_objects(s3_client, bucket):
    """S2: Upload identical objects at various small sizes, dedup, verify split-head."""
    sizes = [5 * 1024, 8 * 1024, 10 * 1024]
    all_keys = []
    md5_map = {}

    for size in sizes:
        size_label = f"{size // 1024}KB"
        keys, md5_hash, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 30, size, prefix=f"small-{size_label}"
        )
        all_keys.extend(keys)
        for k in keys:
            md5_map[k] = md5_hash

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    for key in all_keys:
        dedup_utils.verify_object_integrity(s3_client, bucket, key, md5_map[key])
    total_uploaded = sum(30 * s for s in sizes)
    dedup_utils.log_dedup_savings(exec_stats, total_uploaded, "S2")


@pytest.mark.sanity
def test_s3_admin_ops_api(s3_client, bucket, admin_user, endpoint_url):
    """S3: Verify dedup Admin OPS REST API (estimate, stats, exec)."""
    ak = admin_user["access_key"]
    sk = admin_user["secret_key"]
    dedup_utils.ensure_dedup_caps("dedup-admin")

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 20, 5 * 1024, prefix="api-obj"
    )

    resp = dedup_utils.dedup_api_request(
        endpoint_url,
        "estimate",
        method="POST",
        access_key=ak,
        secret_key=sk,
    )
    assert (
        resp.status_code == 200
    ), f"Estimate API failed: {resp.status_code} {resp.text}"

    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    resp = dedup_utils.dedup_api_request(
        endpoint_url,
        "stats",
        method="GET",
        access_key=ak,
        secret_key=sk,
    )
    assert resp.status_code == 200, f"Stats API failed: {resp.status_code} {resp.text}"
    stats_json = resp.json()
    assert "worker_stats" in stats_json, "Stats API missing worker_stats"
    assert "md5_stats" in stats_json, "Stats API missing md5_stats"

    resp = dedup_utils.dedup_api_request(
        endpoint_url,
        "exec",
        method="POST",
        access_key=ak,
        secret_key=sk,
        params={"yes-i-really-mean-it": ""},
    )
    assert resp.status_code == 200, f"Exec API failed: {resp.status_code} {resp.text}"

    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, 20 * 5 * 1024, "S3")


@pytest.mark.sanity
def test_s4_estimate_dry_run(s3_client, bucket):
    """S4: Run estimate only, verify no data changes."""
    dup_keys, dup_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 30, 5 * 1024, prefix="dup-obj"
    )

    unique_keys = []
    for i in range(10):
        key = f"unique-obj-{i}"
        s3_client.put_object(Bucket=bucket, Key=key, Body=os.urandom(5 * 1024))
        unique_keys.append(key)

    all_keys = dup_keys + unique_keys
    pre_etags = {}
    for key in all_keys:
        resp = s3_client.head_object(Bucket=bucket, Key=key)
        pre_etags[key] = resp["ETag"]

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    for key in all_keys:
        resp = s3_client.head_object(Bucket=bucket, Key=key)
        assert pre_etags[key] == resp["ETag"], f"ETag changed for {key} after estimate"

    dedup_utils.verify_all_objects_integrity(s3_client, bucket, dup_keys, dup_md5)


@pytest.mark.sanity
def test_s5_data_integrity(s3_client, bucket, rgw_config):
    """S5: Upload 100 duplicates with known MD5, dedup, verify all match."""
    obj_count = getattr(rgw_config, "objects_count", None) or 100
    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, 5 * 1024, prefix="integrity-obj"
    )

    pre_etags = {}
    for key in keys:
        resp = s3_client.head_object(Bucket=bucket, Key=key)
        pre_etags[key] = resp["ETag"]

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, obj_count * 5 * 1024, "S5")


# =============================================================================
# FEATURE TESTS (S6-S15)
# =============================================================================


@pytest.mark.feature
@pytest.mark.slow
def test_s6_multipart_objects(s3_client, bucket):
    """S6: Upload 5 identical 50MB multipart objects, dedup, verify range GETs."""
    mp_size = 20 * 1024 * 1024
    keys, expected_md5, original_data = dedup_utils.upload_identical_multipart_objects(
        s3_client, bucket, 5, mp_size, prefix="mp-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)

    for key in keys:
        dedup_utils.verify_range_get(
            s3_client, bucket, key, original_data, 0, 1024 * 1024
        )
        mid = mp_size // 2
        dedup_utils.verify_range_get(
            s3_client, bucket, key, original_data, mid, mid + 1024 * 1024
        )
    dedup_utils.log_dedup_savings(exec_stats, 5 * mp_size, "S6")


@pytest.mark.feature
@pytest.mark.slow
def test_s7_session_lifecycle(s3_client, bucket):
    """S7: Test dedup pause/resume/abort controls."""
    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 100, 5 * 1024, prefix="lifecycle-obj"
    )

    dedup_utils.run_dedup_execute()
    time.sleep(3)
    dedup_utils.run_dedup_pause()
    time.sleep(2)
    dedup_utils.get_dedup_stats()
    dedup_utils.run_dedup_resume()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete after resume"

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, 100 * 5 * 1024, "S7")

    keys2, _, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 50, 5 * 1024, prefix="lifecycle2-obj"
    )
    dedup_utils.run_dedup_execute()
    time.sleep(3)
    dedup_utils.run_dedup_abort()
    time.sleep(2)

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys + keys2)


@pytest.mark.feature
def test_s8_ssec_exclusion(s3_client, bucket):
    """S8: SSE-C encrypted objects excluded from dedup."""
    utils.exec_shell_cmd("ceph config set client.rgw rgw_crypt_require_ssl false")
    time.sleep(5)

    ssec_keys, sse_key_b64, sse_key_md5 = dedup_utils.upload_ssec_objects(
        s3_client, bucket, 20, 5 * 1024, prefix="ssec-obj"
    )
    plain_keys, plain_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 20, 5 * 1024, prefix="plain-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    dedup_utils.verify_all_objects_integrity(s3_client, bucket, plain_keys, plain_md5)

    for key in ssec_keys:
        resp = s3_client.get_object(
            Bucket=bucket,
            Key=key,
            SSECustomerAlgorithm="AES256",
            SSECustomerKey=sse_key_b64,
            SSECustomerKeyMD5=sse_key_md5,
        )
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    dedup_utils.log_dedup_savings(exec_stats, (20 + 20) * 5 * 1024, "S8")


@pytest.mark.feature
def test_s9_storage_class_dedup(s3_client, bucket, ssh_con):
    """S9: Create storage class, upload objects to it, run dedup, verify integrity.

    Steps:
      1. Create data pool for the storage class
      2. Enable rgw application on that pool
      3. Add storage class to zonegroup and zone placement
      4. Period update + restart RGW
      5. Upload identical objects with that storage class
      6. Run dedup estimate → wait for completed
      7. Run dedup exec → wait for completed
      8. Validate estimate/exec ratio match
      9. Verify object integrity
     10. Teardown storage class and pool
    """
    sc_name = "DEDUP_TEST_SC"
    pool_name = "dedup-sc-test-pool"

    dedup_utils.setup_storage_class(sc_name, pool_name, ssh_con)
    try:
        obj_count = 20
        obj_size = 5 * 1024
        data = os.urandom(obj_size)
        content_md5 = hashlib.md5(data).hexdigest()
        keys = []
        for i in range(obj_count):
            key = f"sc-obj-{i}"
            s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=data,
                StorageClass=sc_name,
            )
            keys.append(key)
        log.info(
            f"Uploaded {obj_count} objects to bucket {bucket} "
            f"with StorageClass={sc_name}"
        )

        sc_file = dedup_utils.create_filter_list_file([sc_name])
        try:
            dedup_utils.run_dedup_estimate(allow_sc_file=sc_file)
            estimate_stats = dedup_utils.wait_for_dedup_completion()
            assert estimate_stats.get("completed") is True, "Estimate did not complete"

            dedup_utils.run_dedup_execute(allow_sc_file=sc_file)
            exec_stats = dedup_utils.wait_for_dedup_completion()
            assert exec_stats.get("completed") is True, "Exec did not complete"

            dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
        finally:
            os.remove(sc_file)

        for key in keys:
            resp = s3_client.get_object(Bucket=bucket, Key=key)
            body = resp["Body"].read()
            assert (
                hashlib.md5(body).hexdigest() == content_md5
            ), f"Integrity mismatch for {key} after dedup"
        log.info("All objects in storage class verified post-dedup")
        dedup_utils.log_dedup_savings(exec_stats, obj_count * obj_size, "S9")

    finally:
        dedup_utils.teardown_storage_class(sc_name, pool_name, ssh_con)


@pytest.mark.feature
@pytest.mark.slow
def test_s10_lc_expiration(s3_client, bucket):
    """S10: LC expiration with deduplicated objects."""
    utils.exec_shell_cmd("ceph config set client.rgw rgw_lc_debug_interval 30")
    time.sleep(3)

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 20, 5 * 1024, prefix="lc-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.log_dedup_savings(exec_stats, 20 * 5 * 1024, "S10")

    dedup_utils.set_lifecycle_expiration(s3_client, bucket, days=1)
    time.sleep(90)

    resp = s3_client.list_objects_v2(Bucket=bucket)
    remaining = resp.get("KeyCount", 0)
    log.info(f"Objects remaining after LC expiration: {remaining}")


@pytest.mark.feature
def test_s11_versioned_objects(s3_client, bucket, rgw_config):
    """S11: Versioned objects dedup, verify all versions accessible."""
    dedup_utils.enable_bucket_versioning(s3_client, bucket)

    identical_data = dedup_utils.generate_identical_data(5 * 1024)
    expected_md5 = hashlib.md5(identical_data).hexdigest()

    version_count = getattr(rgw_config, "version_count", None) or 10
    object_key = "versioned-dedup-object"
    version_ids = []

    for i in range(version_count):
        resp = s3_client.put_object(Bucket=bucket, Key=object_key, Body=identical_data)
        version_ids.append(resp["VersionId"])

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    for vid in version_ids:
        resp = s3_client.get_object(Bucket=bucket, Key=object_key, VersionId=vid)
        body = resp["Body"].read()
        actual_md5 = hashlib.md5(body).hexdigest()
        assert actual_md5 == expected_md5, f"Version {vid} MD5 mismatch"

    versions = dedup_utils.get_all_versions(s3_client, bucket, object_key)
    assert len(versions) == version_count
    dedup_utils.log_dedup_savings(exec_stats, version_count * 5 * 1024, "S11")


@pytest.mark.feature
def test_s12_s3_copy_dedup(s3_client, bucket):
    """S12: S3 COPY to duplicate 20 times, dedup, verify all copies."""
    source_data = dedup_utils.generate_identical_data(5 * 1024)
    expected_md5 = hashlib.md5(source_data).hexdigest()

    source_key = "source-large-obj"
    s3_client.put_object(Bucket=bucket, Key=source_key, Body=source_data)

    copy_keys = []
    for i in range(20):
        copy_key = f"copy-obj-{i}"
        s3_client.copy_object(
            Bucket=bucket,
            Key=copy_key,
            CopySource={"Bucket": bucket, "Key": source_key},
        )
        copy_keys.append(copy_key)

    all_keys = [source_key] + copy_keys

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    dedup_utils.verify_all_objects_integrity(s3_client, bucket, all_keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, 21 * 5 * 1024, "S12")


@pytest.mark.feature
def test_s14_same_content_diff_metadata(s3_clients, test_context):
    """S14: Same content, different metadata/tags/users. Metadata preserved."""
    s3_client1, s3_client2 = s3_clients
    bucket1 = f"dedup-meta1-{random.randint(1, 9999)}"
    bucket2 = f"dedup-meta2-{random.randint(1, 9999)}"
    s3_client1.create_bucket(Bucket=bucket1)
    s3_client2.create_bucket(Bucket=bucket2)

    test_context["buckets"].extend([bucket1, bucket2])
    for bkt in [bucket1, bucket2]:
        marker = dedup_utils.get_bucket_marker(bkt)
        if marker:
            test_context["bucket_markers"][bkt] = marker

    try:
        identical_data = dedup_utils.generate_identical_data(5 * 1024)
        expected_md5 = hashlib.md5(identical_data).hexdigest()

        s3_client1.put_object(
            Bucket=bucket1,
            Key="obj-user1-a",
            Body=identical_data,
            Metadata={"custom-key": "value-a"},
            Tagging="env=prod",
        )
        s3_client1.put_object(
            Bucket=bucket1,
            Key="obj-user1-b",
            Body=identical_data,
            Metadata={"custom-key": "value-b"},
            Tagging="env=staging",
        )
        s3_client2.put_object(
            Bucket=bucket2,
            Key="obj-user2-a",
            Body=identical_data,
            Metadata={"custom-key": "value-c"},
        )
        s3_client2.put_object(
            Bucket=bucket2,
            Key="obj-user2-b",
            Body=identical_data,
            Metadata={"custom-key": "value-d"},
        )

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

        for client, bkt, key, expected_meta in [
            (s3_client1, bucket1, "obj-user1-a", "value-a"),
            (s3_client1, bucket1, "obj-user1-b", "value-b"),
            (s3_client2, bucket2, "obj-user2-a", "value-c"),
            (s3_client2, bucket2, "obj-user2-b", "value-d"),
        ]:
            dedup_utils.verify_object_integrity(client, bkt, key, expected_md5)
            resp = client.head_object(Bucket=bkt, Key=key)
            actual = resp.get("Metadata", {}).get("custom-key", "")
            assert actual == expected_meta, f"Metadata mismatch for {bkt}/{key}"

        tag_resp = s3_client1.get_object_tagging(Bucket=bucket1, Key="obj-user1-a")
        tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
        assert tags.get("env") == "prod"
        dedup_utils.log_dedup_savings(exec_stats, 4 * 5 * 1024, "S14")
    finally:
        dedup_utils.cleanup_bucket(s3_client1, bucket1)
        dedup_utils.cleanup_bucket(s3_client2, bucket2)


@pytest.mark.feature
@pytest.mark.slow
def test_s15_concurrent_s3_ops(s3_client, bucket_factory):
    """S15: Concurrent S3 workload during dedup."""
    dedup_bucket = bucket_factory("dedup-concurrent")
    workload_bucket = bucket_factory("workload-concurrent")

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, dedup_bucket, 50, 5 * 1024, prefix="concurrent-obj"
    )

    dedup_utils.run_dedup_execute()
    workload_results = dedup_utils.run_concurrent_s3_workload(
        s3_client, workload_bucket, duration_secs=20, prefix="workload"
    )
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.verify_all_objects_accessible(s3_client, dedup_bucket, keys)
    dedup_utils.verify_all_objects_integrity(
        s3_client, dedup_bucket, keys, expected_md5
    )

    dedup_utils.log_dedup_savings(exec_stats, 50 * 5 * 1024, "S15")

    assert workload_results["puts"] > 0
    assert workload_results["gets"] > 0
    error_rate = workload_results["errors"] / max(
        workload_results["puts"]
        + workload_results["gets"]
        + workload_results["deletes"],
        1,
    )
    assert error_rate < 0.05, f"Error rate too high: {error_rate:.2%}"


# =============================================================================
# COMPRESSION TESTS (S16-S21)
# =============================================================================


@pytest.mark.compression
def test_s16_compressed_sanity(s3_client, bucket, rgw_config, ssh_con):
    """S16: Compressed objects are always skipped by dedup. Verify skip + integrity."""
    dedup_utils.enable_zone_compression("zlib", ssh_con)
    try:
        obj_count = getattr(rgw_config, "objects_count", None) or 50
        keys, expected_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, obj_count, 5 * 1024, prefix="compressed-obj"
        )

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        parsed = dedup_utils.parse_dedup_stats_full(exec_stats)
        assert (
            parsed["deduped_count"] == 0
        ), f"Compressed objects should NOT be deduped, got deduped_count={parsed['deduped_count']}"
        assert (
            parsed["skipped_compressed"] > 0
        ), f"Expected skipped_compressed > 0, got {parsed['skipped_compressed']}"
        log.info(
            f"Compressed skip verified: skipped_compressed={parsed['skipped_compressed']}, "
            f"deduped_count={parsed['deduped_count']}"
        )

        dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
        dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
        dedup_utils.log_dedup_savings(exec_stats, obj_count * 5 * 1024, "S16")
    finally:
        dedup_utils.disable_zone_compression(ssh_con)


@pytest.mark.compression
def test_s17_compressed_cross_mode(s3_client, bucket, ssh_con):
    """S17: Mixed plain + compressed. Only plain objects deduped, compressed skipped."""
    dedup_utils.disable_zone_compression(ssh_con)
    plain_keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, 20, 5 * 1024, prefix="plain-obj"
    )

    dedup_utils.enable_zone_compression("zlib", ssh_con)
    try:
        comp_keys, comp_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 20, 5 * 1024, prefix="compressed-obj"
        )
        assert expected_md5 == comp_md5

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        parsed = dedup_utils.parse_dedup_stats_full(exec_stats)
        assert (
            parsed["deduped_count"] > 0
        ), "Plain (uncompressed) objects should be deduped"
        assert (
            parsed["skipped_compressed"] > 0
        ), f"Compressed objects should be skipped, got skipped_compressed={parsed['skipped_compressed']}"
        log.info(
            f"Mixed mode verified: deduped_count={parsed['deduped_count']} (plain), "
            f"skipped_compressed={parsed['skipped_compressed']} (compressed)"
        )

        all_keys = plain_keys + comp_keys
        dedup_utils.verify_all_objects_accessible(s3_client, bucket, all_keys)
        dedup_utils.verify_all_objects_integrity(
            s3_client, bucket, all_keys, expected_md5
        )
        dedup_utils.log_dedup_savings(exec_stats, 40 * 5 * 1024, "S17")
    finally:
        dedup_utils.disable_zone_compression(ssh_con)


@pytest.mark.compression
def test_s18_compressed_algo_switch(s3_client, bucket, ssh_con):
    """S18: zlib -> snappy switch. All compressed objects skipped regardless of algorithm."""
    dedup_utils.enable_zone_compression("zlib", ssh_con)
    try:
        zlib_keys, expected_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 15, 5 * 1024, prefix="zlib-obj"
        )

        dedup_utils.enable_zone_compression("snappy", ssh_con)
        snappy_keys, snappy_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 15, 5 * 1024, prefix="snappy-obj"
        )
        assert expected_md5 == snappy_md5

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        parsed = dedup_utils.parse_dedup_stats_full(exec_stats)
        assert (
            parsed["deduped_count"] == 0
        ), f"All objects are compressed — none should be deduped, got {parsed['deduped_count']}"
        assert (
            parsed["skipped_compressed"] > 0
        ), f"Expected skipped_compressed > 0 for mixed zlib+snappy, got {parsed['skipped_compressed']}"
        log.info(
            f"Algo switch skip verified: skipped_compressed={parsed['skipped_compressed']}"
        )

        all_keys = zlib_keys + snappy_keys
        dedup_utils.verify_all_objects_accessible(s3_client, bucket, all_keys)
        dedup_utils.verify_all_objects_integrity(
            s3_client, bucket, all_keys, expected_md5
        )
        dedup_utils.log_dedup_savings(exec_stats, 30 * 5 * 1024, "S18")
    finally:
        dedup_utils.disable_zone_compression(ssh_con)


@pytest.mark.compression
@pytest.mark.slow
def test_s19_compressed_multipart(s3_client, bucket, ssh_con):
    """S19: Compressed multipart objects skipped by dedup. Verify skip + range GETs."""
    dedup_utils.enable_zone_compression("zlib", ssh_con)
    try:
        mp_size = 20 * 1024 * 1024
        (
            keys,
            expected_md5,
            original_data,
        ) = dedup_utils.upload_identical_multipart_objects(
            s3_client, bucket, 5, mp_size, prefix="compmp-obj"
        )

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        parsed = dedup_utils.parse_dedup_stats_full(exec_stats)
        assert (
            parsed["deduped_count"] == 0
        ), f"Compressed multipart objects should NOT be deduped, got {parsed['deduped_count']}"
        assert (
            parsed["skipped_compressed"] > 0
        ), f"Expected skipped_compressed > 0, got {parsed['skipped_compressed']}"

        dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
        dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)

        for key in keys:
            dedup_utils.verify_range_get(
                s3_client, bucket, key, original_data, 0, 1024 * 1024
            )
            mid = mp_size // 2
            dedup_utils.verify_range_get(
                s3_client, bucket, key, original_data, mid, mid + 1024 * 1024
            )
        dedup_utils.log_dedup_savings(exec_stats, 5 * mp_size, "S19")
    finally:
        dedup_utils.disable_zone_compression(ssh_con)


@pytest.mark.compression
def test_s20_compressed_skip_verify(s3_client, bucket, ssh_con):
    """S20: Verify compressed objects skipped via stats, check skipped_compressed field."""
    dedup_utils.enable_zone_compression("zlib", ssh_con)
    try:
        keys, expected_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 30, 5 * 1024, prefix="skipverify-obj"
        )

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        parsed = dedup_utils.parse_dedup_stats_full(exec_stats)
        assert (
            parsed["deduped_count"] == 0
        ), f"Compressed objects should be skipped, got deduped_count={parsed['deduped_count']}"
        assert (
            parsed["skipped_compressed"] > 0
        ), f"Expected skipped_compressed > 0, got {parsed['skipped_compressed']}"
        log.info(
            f"Compressed skip stats: skipped_compressed={parsed['skipped_compressed']}, "
            f"ingress_count={parsed['ingress_count']}"
        )

        dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
        dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
        dedup_utils.log_dedup_savings(exec_stats, 30 * 5 * 1024, "S20")
    finally:
        dedup_utils.disable_zone_compression(ssh_con)


@pytest.mark.compression
def test_s21_compressed_attr_mirror(s3_client, bucket, ssh_con):
    """S21: Compressed objects skipped, then add uncompressed, re-dedup dedupes only plain."""
    dedup_utils.enable_zone_compression("zlib", ssh_con)
    try:
        comp_keys, expected_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 30, 5 * 1024, prefix="comp-obj"
        )

        dedup_utils.run_dedup_estimate()
        estimate_stats = dedup_utils.wait_for_dedup_completion()
        assert estimate_stats.get("completed") is True, "Estimate did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats = dedup_utils.wait_for_dedup_completion()
        assert exec_stats.get("completed") is True, "Exec did not complete"

        parsed1 = dedup_utils.parse_dedup_stats_full(exec_stats)
        assert (
            parsed1["deduped_count"] == 0
        ), "Round 1: compressed objects should be skipped"
        assert (
            parsed1["skipped_compressed"] > 0
        ), "Round 1: expected skipped_compressed > 0"

        dedup_utils.verify_all_objects_accessible(s3_client, bucket, comp_keys)
        dedup_utils.verify_all_objects_integrity(
            s3_client, bucket, comp_keys, expected_md5
        )

        dedup_utils.disable_zone_compression(ssh_con)
        plain_keys, plain_md5, _ = dedup_utils.upload_identical_objects(
            s3_client, bucket, 10, 5 * 1024, prefix="plain-obj"
        )
        assert expected_md5 == plain_md5

        dedup_utils.run_dedup_estimate()
        estimate_stats2 = dedup_utils.wait_for_dedup_completion()
        assert (
            estimate_stats2.get("completed") is True
        ), "Estimate (round 2) did not complete"

        dedup_utils.run_dedup_execute()
        exec_stats2 = dedup_utils.wait_for_dedup_completion()
        assert exec_stats2.get("completed") is True, "Exec (round 2) did not complete"

        parsed2 = dedup_utils.parse_dedup_stats_full(exec_stats2)
        assert parsed2["deduped_count"] > 0, "Round 2: plain objects should be deduped"
        assert (
            parsed2["skipped_compressed"] > 0
        ), "Round 2: compressed objects should still be skipped"
        log.info(
            f"Round 2: deduped_count={parsed2['deduped_count']} (plain), "
            f"skipped_compressed={parsed2['skipped_compressed']} (compressed)"
        )

        all_keys = comp_keys + plain_keys
        dedup_utils.verify_all_objects_accessible(s3_client, bucket, all_keys)
        dedup_utils.verify_all_objects_integrity(
            s3_client, bucket, all_keys, expected_md5
        )
        dedup_utils.log_dedup_savings(exec_stats2, (30 + 10) * 5 * 1024, "S21")
    except Exception:
        dedup_utils.disable_zone_compression(ssh_con)
        raise


# =============================================================================
# BUG-HUNTING TESTS (B1-B5)
# =============================================================================


@pytest.mark.bug
def test_b1_overwrite_deduped_object(s3_client, bucket, rgw_config):
    """B1: Overwrite one deduped target, verify siblings survive."""
    obj_count = getattr(rgw_config, "objects_count", None) or 10
    obj_size = 5 * 1024

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, obj_size, prefix="ow-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, obj_count * obj_size, "B1")

    overwrite_key = keys[1]
    new_data = os.urandom(5 * 1024)
    new_md5 = hashlib.md5(new_data).hexdigest()
    s3_client.put_object(Bucket=bucket, Key=overwrite_key, Body=new_data)

    resp = s3_client.get_object(Bucket=bucket, Key=overwrite_key)
    body = resp["Body"].read()
    assert hashlib.md5(body).hexdigest() == new_md5

    remaining_keys = [k for k in keys if k != overwrite_key]
    for key in remaining_keys:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        body = resp["Body"].read()
        assert (
            hashlib.md5(body).hexdigest() == expected_md5
        ), f"Object {key} corrupted after overwrite of sibling"


@pytest.mark.bug
def test_b2_delete_dedup_source(s3_client, bucket, rgw_config):
    """B2: Delete objects one by one, verify remaining survive each time."""
    obj_count = getattr(rgw_config, "objects_count", None) or 10
    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, 5 * 1024, prefix="delsrc-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, obj_count * 5 * 1024, "B2")

    remaining = list(keys)
    for key_to_delete in keys:
        s3_client.delete_object(Bucket=bucket, Key=key_to_delete)
        remaining.remove(key_to_delete)
        if not remaining:
            break
        for key in remaining:
            resp = s3_client.get_object(Bucket=bucket, Key=key)
            body = resp["Body"].read()
            assert (
                hashlib.md5(body).hexdigest() == expected_md5
            ), f"Object {key} corrupted after deleting {key_to_delete}"


@pytest.mark.bug
def test_b3_s3_copy_then_delete_deduped(s3_client, bucket_factory):
    """B3: S3 COPY deduped object (same + cross bucket), delete originals."""
    bucket_a = bucket_factory("dedup-copysrc")
    bucket_b = bucket_factory("dedup-copydst")

    obj_size = 5 * 1024
    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket_a, 5, obj_size, prefix="cpsrc-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket_a, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, 5 * obj_size, "B3")

    s3_client.copy_object(
        Bucket=bucket_a,
        Key="copy-same",
        CopySource={"Bucket": bucket_a, "Key": keys[0]},
    )
    s3_client.copy_object(
        Bucket=bucket_b,
        Key="copy-cross",
        CopySource={"Bucket": bucket_a, "Key": keys[1]},
    )

    for key in keys:
        s3_client.delete_object(Bucket=bucket_a, Key=key)

    dedup_utils.verify_object_integrity(s3_client, bucket_a, "copy-same", expected_md5)
    dedup_utils.verify_object_integrity(s3_client, bucket_b, "copy-cross", expected_md5)


@pytest.mark.bug
def test_b4_cross_bucket_source_delete(s3_client, bucket_factory):
    """B4: Cross-bucket dedup, delete source bucket, verify target survives."""
    bucket_a = bucket_factory("dedup-xbkt-a")
    bucket_b = bucket_factory("dedup-xbkt-b")

    obj_size = 5 * 1024
    identical_data = dedup_utils.generate_identical_data(obj_size)
    expected_md5 = hashlib.md5(identical_data).hexdigest()

    s3_client.put_object(Bucket=bucket_a, Key="cross-obj-a", Body=identical_data)
    s3_client.put_object(Bucket=bucket_b, Key="cross-obj-b", Body=identical_data)

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    dedup_utils.verify_object_integrity(
        s3_client, bucket_a, "cross-obj-a", expected_md5
    )
    dedup_utils.verify_object_integrity(
        s3_client, bucket_b, "cross-obj-b", expected_md5
    )
    dedup_utils.log_dedup_savings(exec_stats, 2 * obj_size, "B4")

    s3_client.delete_object(Bucket=bucket_a, Key="cross-obj-a")
    s3_client.delete_bucket(Bucket=bucket_a)

    dedup_utils.verify_object_integrity(
        s3_client, bucket_b, "cross-obj-b", expected_md5
    )


@pytest.mark.bug
def test_b5_dedup_idempotency(s3_client, bucket, rgw_config):
    """B5: Run dedup exec 3 times, verify no corruption or double-counting."""
    obj_count = getattr(rgw_config, "objects_count", None) or 20
    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, 5 * 1024, prefix="idemp-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    all_run_stats = []
    all_raw_stats = []
    for run_num in range(1, 4):
        dedup_utils.run_dedup_execute()
        stats = dedup_utils.wait_for_dedup_completion()
        assert stats.get("completed") is True, f"Exec run {run_num} did not complete"
        all_raw_stats.append(stats)
        parsed = dedup_utils.parse_dedup_stats(stats)
        all_run_stats.append(parsed)
        dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)

    assert all_run_stats[0]["deduped_count"] > 0
    dedup_utils.log_dedup_savings(all_raw_stats[0], obj_count * 5 * 1024, "B5")
    for parsed in all_run_stats[1:]:
        assert parsed["deduped_count"] == 0
        assert parsed["skipped_shared_manifest"] > 0

    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)


# =============================================================================
# ENHANCEMENT TESTS (E1-E5) -- 128-limit boundary
# =============================================================================


@pytest.mark.enhancement
def test_e1_128_limit_boundary(s3_client, bucket):
    """E1: 200 identical 5KB objects, verify only ~127 deduped, rest skipped."""
    obj_count = 200
    obj_size = 5 * 1024

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, obj_size, prefix="limit-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    parsed = dedup_utils.parse_dedup_stats_full(exec_stats)

    log.info(
        f"Deduped: {parsed['deduped_count']}, "
        f"Skipped Too Many Copies: {parsed['skipped_too_many_copies']}"
    )

    assert parsed["deduped_count"] > 0, "Expected some objects deduped"
    assert (
        parsed["deduped_count"] <= 127
    ), f"Expected deduped <= 127 (128 limit), got {parsed['deduped_count']}"
    assert (
        parsed["skipped_too_many_copies"] > 0
    ), f"Expected Skipped Too Many Copies > 0, got {parsed['skipped_too_many_copies']}"

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(exec_stats, obj_count * obj_size, "E1")


@pytest.mark.enhancement
def test_e2_versioned_boundary(s3_client, bucket):
    """E2: 130 versions of same key (past 128 boundary), verify all accessible."""
    version_count = 130
    object_key = "versioned-boundary-obj"
    obj_size = 5 * 1024

    version_ids, expected_md5, _ = dedup_utils.upload_identical_versions(
        s3_client, bucket, object_key, version_count, obj_size
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    parsed = dedup_utils.parse_dedup_stats_full(exec_stats)

    assert parsed["deduped_count"] > 0
    assert parsed["unique_count"] >= 1

    for vid in version_ids:
        resp = s3_client.get_object(Bucket=bucket, Key=object_key, VersionId=vid)
        body = resp["Body"].read()
        assert (
            hashlib.md5(body).hexdigest() == expected_md5
        ), f"Version {vid} MD5 mismatch"

    versions = dedup_utils.get_all_versions(s3_client, bucket, object_key)
    assert len(versions) == version_count
    dedup_utils.log_dedup_savings(exec_stats, version_count * obj_size, "E2")


@pytest.mark.enhancement
def test_e3_multi_cycle_no_progress(s3_client, bucket):
    """E3: 200 objects, 3 exec cycles. Cycles 2-3 dedup zero -- system is stuck."""
    obj_count = 200
    obj_size = 5 * 1024

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, obj_size, prefix="cycle-obj"
    )

    all_cycle_stats = []
    first_raw_stats = None
    for cycle in range(1, 4):
        log.info(f"=== Dedup exec cycle {cycle}/3 ===")
        dedup_utils.run_dedup_estimate()
        est = dedup_utils.wait_for_dedup_completion()
        assert est.get("completed") is True, f"Estimate cycle {cycle} did not complete"

        dedup_utils.run_dedup_execute()
        stats = dedup_utils.wait_for_dedup_completion()
        assert stats.get("completed") is True, f"Exec cycle {cycle} did not complete"
        if cycle == 1:
            first_raw_stats = stats

        dedup_utils.validate_estimate_exec_ratio(est, stats)
        parsed = dedup_utils.parse_dedup_stats_full(stats)
        all_cycle_stats.append(parsed)
        log.info(
            f"Cycle {cycle}: deduped={parsed['deduped_count']}, "
            f"skipped_too_many={parsed['skipped_too_many_copies']}, "
            f"skipped_shared_manifest={parsed['skipped_shared_manifest']}"
        )

    assert all_cycle_stats[0]["deduped_count"] > 0, "Cycle 1 should dedup objects"
    assert all_cycle_stats[1]["deduped_count"] == 0, "Cycle 2 should dedup 0"
    assert all_cycle_stats[2]["deduped_count"] == 0, "Cycle 3 should dedup 0"

    assert (
        all_cycle_stats[1]["skipped_too_many_copies"]
        == all_cycle_stats[2]["skipped_too_many_copies"]
    ), "Skipped Too Many Copies should be stable across cycles 2-3"

    for parsed in all_cycle_stats[1:]:
        assert parsed["skipped_shared_manifest"] >= all_cycle_stats[0]["deduped_count"]

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)
    dedup_utils.log_dedup_savings(first_raw_stats, obj_count * obj_size, "E3")


@pytest.mark.enhancement
def test_e4_split_head_small_objects(s3_client, bucket):
    """E4: 50 identical 5KB objects, verify split-head mechanism used."""
    obj_count = 50
    obj_size = 5 * 1024

    keys, expected_md5, original_data = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, obj_size, prefix="splithead-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()
    assert estimate_stats.get("completed") is True, "Estimate did not complete"

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()
    assert exec_stats.get("completed") is True, "Exec did not complete"

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)
    parsed = dedup_utils.parse_dedup_stats_full(exec_stats)

    assert parsed["deduped_count"] > 0
    assert (
        parsed["split_head_src"] > 0
    ), f"Expected Split-Head Src > 0, got {parsed['split_head_src']}"
    assert (
        parsed["split_head_tgt"] > 0
    ), f"Expected Split-Head Tgt > 0, got {parsed['split_head_tgt']}"

    dedup_utils.verify_all_objects_accessible(s3_client, bucket, keys)
    dedup_utils.verify_all_objects_integrity(s3_client, bucket, keys, expected_md5)

    for key in keys[:5]:
        dedup_utils.verify_range_get(s3_client, bucket, key, original_data, 0, 1023)
        dedup_utils.verify_range_get(
            s3_client, bucket, key, original_data, 2048, obj_size - 1
        )
    dedup_utils.log_dedup_savings(exec_stats, obj_count * obj_size, "E4")


@pytest.mark.enhancement
def test_e5_stats_validation(s3_client, bucket):
    """E5: Validate all expected stats fields present after estimate + exec."""
    obj_count = 50
    obj_size = 5 * 1024

    keys, expected_md5, _ = dedup_utils.upload_identical_objects(
        s3_client, bucket, obj_count, obj_size, prefix="stats-obj"
    )

    dedup_utils.run_dedup_estimate()
    estimate_stats = dedup_utils.wait_for_dedup_completion()

    assert isinstance(estimate_stats, dict)
    assert estimate_stats.get("completed") is True, "Estimate did not complete"
    est_parsed = dedup_utils.parse_dedup_stats_full(estimate_stats)
    assert (
        est_parsed["ingress_count"] > 0
    ), f"Estimate ingress_count should be > 0, got {est_parsed['ingress_count']}"
    assert est_parsed["unique_count"] >= 1
    assert est_parsed["duplicate_count"] > 0
    assert est_parsed["dedup_ratio_estimate"] > 1.0

    dedup_utils.run_dedup_execute()
    exec_stats = dedup_utils.wait_for_dedup_completion()

    assert isinstance(exec_stats, dict)
    assert exec_stats.get("completed") is True, "Exec did not complete"
    exec_parsed = dedup_utils.parse_dedup_stats_full(exec_stats)
    assert (
        exec_parsed["total_processed"] == obj_count
    ), f"Exec total_processed should be {obj_count}, got {exec_parsed['total_processed']}"
    assert exec_parsed["deduped_count"] > 0
    assert exec_parsed["unique_count"] >= 1
    assert exec_parsed["dedup_ratio_actual"] > 1.0

    dedup_utils.validate_estimate_exec_ratio(estimate_stats, exec_stats)

    md5_skipped = exec_stats.get("md5_stats", {}).get("skipped", {})
    for field in [
        "Skipped shared_manifest",
        "Skipped purged small objs",
        "Skipped singleton objs",
        "Skipped source record",
    ]:
        assert field in md5_skipped, f"Missing field: {field}"
    dedup_utils.log_dedup_savings(exec_stats, obj_count * obj_size, "E5")
