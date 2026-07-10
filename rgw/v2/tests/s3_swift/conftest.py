"""
Pytest conftest for RGW dedup tests.

Provides shared fixtures for S3 client setup, bucket management,
and cluster configuration used across all dedup pytest tests.

Usage:
  pytest test_dedup_pytest.py -c <config.yaml> -v
  pytest test_dedup_pytest.py -c <config.yaml> --rgw-node <hostname>
"""

import logging
import os
import random
import sys
import time

import pytest

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import dedup as dedup_utils
from v2.utils.log import configure_logging

log = logging.getLogger()

# ---------------------------------------------------------------------------
# Per-test resource tracking for cleanup and reporting
# ---------------------------------------------------------------------------

_test_context = {}
_test_passed = {}


def _get_ctx(node_id):
    if node_id not in _test_context:
        _test_context[node_id] = {
            "users": [],
            "buckets": [],
            "bucket_markers": {},
            "recorder": None,
        }
    return _test_context[node_id]


DEDUP_TEST_SCENARIOS = {
    "test_s1_sanity_large_objects": {
        "id": "S1",
        "category": "Sanity",
        "scenario": "Upload 50 identical 5KB objects, run dedup estimate+exec, verify deduped_count>0 and data integrity",
    },
    "test_s2_sanity_small_objects": {
        "id": "S2",
        "category": "Sanity",
        "scenario": "Upload identical objects at 5KB/8KB/10KB sizes, run dedup estimate+exec, verify ratio and integrity",
    },
    "test_s3_admin_ops_api": {
        "id": "S3",
        "category": "Sanity",
        "scenario": "Verify dedup Admin OPS REST API endpoints (estimate, stats, exec) with S3 V1 auth",
    },
    "test_s4_estimate_dry_run": {
        "id": "S4",
        "category": "Sanity",
        "scenario": "Run estimate only (no exec), verify ETags unchanged and no data modification",
    },
    "test_s5_data_integrity": {
        "id": "S5",
        "category": "Sanity",
        "scenario": "Upload 100 duplicates with known MD5, run exec, verify all MD5s match post-dedup",
    },
    "test_s6_multipart_objects": {
        "id": "S6",
        "category": "Feature",
        "scenario": "Upload 5 identical 20MB multipart objects, dedup, verify range GETs work post-dedup",
    },
    "test_s7_session_lifecycle": {
        "id": "S7",
        "category": "Feature",
        "scenario": "Test dedup pause/resume/abort controls during exec, verify data survives each action",
    },
    "test_s8_ssec_exclusion": {
        "id": "S8",
        "category": "Feature",
        "scenario": "SSE-C encrypted objects excluded from dedup, plain objects deduped, both accessible",
    },
    "test_s9_storage_class_dedup": {
        "id": "S9",
        "category": "Feature",
        "scenario": "Create custom storage class with data pool, upload objects, dedup with storage class filter",
    },
    "test_s10_lc_expiration": {
        "id": "S10",
        "category": "Feature",
        "scenario": "Dedup objects then apply lifecycle expiration, verify LC works on deduped objects",
    },
    "test_s11_versioned_objects": {
        "id": "S11",
        "category": "Feature",
        "scenario": "Upload 10 identical versions of same key, dedup, verify all versions accessible post-dedup",
    },
    "test_s12_s3_copy_dedup": {
        "id": "S12",
        "category": "Feature",
        "scenario": "S3 COPY to create 20 duplicates, dedup, verify all copies intact post-dedup",
    },
    "test_s14_same_content_diff_metadata": {
        "id": "S14",
        "category": "Feature",
        "scenario": "Same content with different metadata/tags across 2 users, dedup, verify metadata preserved",
    },
    "test_s15_concurrent_s3_ops": {
        "id": "S15",
        "category": "Feature",
        "scenario": "Run concurrent S3 workload (puts/gets/deletes) during dedup exec, verify <5% error rate",
    },
    "test_s16_compressed_sanity": {
        "id": "S16",
        "category": "Compression",
        "scenario": "Enable zlib compression, upload 50 identical objects, verify dedup skips all (skipped_compressed>0)",
    },
    "test_s17_compressed_cross_mode": {
        "id": "S17",
        "category": "Compression",
        "scenario": "Mixed plain + zlib-compressed same content, verify only plain deduped, compressed skipped",
    },
    "test_s18_compressed_algo_switch": {
        "id": "S18",
        "category": "Compression",
        "scenario": "Switch zlib->snappy, verify all compressed objects skipped regardless of algorithm",
    },
    "test_s19_compressed_multipart": {
        "id": "S19",
        "category": "Compression",
        "scenario": "Compressed 20MB multipart objects, verify dedup skips them, range GETs still work",
    },
    "test_s20_compressed_skip_verify": {
        "id": "S20",
        "category": "Compression",
        "scenario": "Verify compressed objects skipped via stats, validate skipped_compressed field populated",
    },
    "test_s21_compressed_attr_mirror": {
        "id": "S21",
        "category": "Compression",
        "scenario": "Compressed objects skipped in round 1, add plain objects, re-dedup dedupes only plain",
    },
    "test_b1_overwrite_deduped_object": {
        "id": "B1",
        "category": "Bug",
        "scenario": "Overwrite one deduped object with new content, verify sibling objects survive",
    },
    "test_b2_delete_dedup_source": {
        "id": "B2",
        "category": "Bug",
        "scenario": "Delete deduped objects one-by-one, verify each remaining object survives",
    },
    "test_b3_s3_copy_then_delete_deduped": {
        "id": "B3",
        "category": "Bug",
        "scenario": "S3 COPY deduped object (same + cross bucket), delete originals, verify copies survive",
    },
    "test_b4_cross_bucket_source_delete": {
        "id": "B4",
        "category": "Bug",
        "scenario": "Cross-bucket dedup, delete source bucket entirely, verify target bucket objects survive",
    },
    "test_b5_dedup_idempotency": {
        "id": "B5",
        "category": "Bug",
        "scenario": "Run dedup exec 3 times, verify run1 dedupes, runs 2-3 dedup 0 (no double-counting)",
    },
    "test_e1_128_limit_boundary": {
        "id": "E1",
        "category": "Enhancement",
        "scenario": "200 identical objects, verify deduped<=127 (128-limit), skipped_too_many_copies>0",
    },
    "test_e2_versioned_boundary": {
        "id": "E2",
        "category": "Enhancement",
        "scenario": "130 versions of same key (past 128 boundary), verify all versions accessible post-dedup",
    },
    "test_e3_multi_cycle_no_progress": {
        "id": "E3",
        "category": "Enhancement",
        "scenario": "200 objects, 3 exec cycles: cycle1 dedupes, cycles 2-3 dedup 0, stable skip counts",
    },
    "test_e4_split_head_small_objects": {
        "id": "E4",
        "category": "Enhancement",
        "scenario": "50 identical 5KB objects, verify split-head mechanism used (split_head_src>0, tgt>0)",
    },
    "test_e5_stats_validation": {
        "id": "E5",
        "category": "Enhancement",
        "scenario": "Validate stats fields: ingress_count for estimate, total_processed for exec, ratios, skipped fields",
    },
}


def pytest_addoption(parser):
    parser.addoption(
        "--config",
        "-C",
        dest="config",
        required=True,
        help="Path to RGW test YAML configuration file",
    )
    parser.addoption(
        "--rgw-node",
        dest="rgw_node",
        default="",
        help="RGW node hostname for SSH connection",
    )


@pytest.fixture(scope="session", autouse=True)
def setup_logging():
    configure_logging(f_name="test_dedup_pytest")


@pytest.fixture(scope="session")
def rgw_config(request):
    yaml_path = request.config.getoption("config")
    config = Config(yaml_path)
    config.read()
    return config


@pytest.fixture(scope="session")
def ssh_con(request):
    rgw_node = request.config.getoption("rgw_node")
    if rgw_node:
        return utils.connect_remote(rgw_node)
    return None


@pytest.fixture(scope="session")
def io_info():
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())


@pytest.fixture
def s3_client(rgw_config, ssh_con, io_info, request):
    user_info = s3lib.create_users(1)[0]
    ctx = _get_ctx(request.node.nodeid)
    ctx["users"].append(user_info)
    auth = reusable.get_auth(
        user_info,
        ssh_con,
        rgw_config.ssl,
        getattr(rgw_config, "haproxy", False),
    )
    return auth.do_auth_using_client()


@pytest.fixture
def s3_clients(rgw_config, ssh_con, io_info, request):
    all_users = s3lib.create_users(2)
    ctx = _get_ctx(request.node.nodeid)
    for user_info in all_users:
        ctx["users"].append(user_info)
    clients = []
    for user_info in all_users:
        auth = reusable.get_auth(
            user_info,
            ssh_con,
            rgw_config.ssl,
            getattr(rgw_config, "haproxy", False),
        )
        clients.append(auth.do_auth_using_client())
    return clients


@pytest.fixture
def bucket(s3_client, request):
    name = f"dedup-pytest-{random.randint(1, 9999)}"
    s3_client.create_bucket(Bucket=name)
    ctx = _get_ctx(request.node.nodeid)
    ctx["buckets"].append(name)
    marker = dedup_utils.get_bucket_marker(name)
    if marker:
        ctx["bucket_markers"][name] = marker
    yield name
    dedup_utils.cleanup_bucket(s3_client, name)


@pytest.fixture
def bucket_factory(s3_client, request):
    created = []

    def _create(prefix="dedup-pytest"):
        name = f"{prefix}-{random.randint(1, 9999)}"
        s3_client.create_bucket(Bucket=name)
        created.append(name)
        ctx = _get_ctx(request.node.nodeid)
        ctx["buckets"].append(name)
        marker = dedup_utils.get_bucket_marker(name)
        if marker:
            ctx["bucket_markers"][name] = marker
        return name

    yield _create

    for name in created:
        dedup_utils.cleanup_bucket(s3_client, name)


@pytest.fixture(scope="session", autouse=True)
def dedup_min_size_4k():
    dedup_utils.set_dedup_config("rgw_dedup_min_obj_size_for_dedup", "4096")
    yield
    dedup_utils.reset_dedup_config("rgw_dedup_min_obj_size_for_dedup")


@pytest.fixture
def admin_user(rgw_config, ssh_con, io_info, request):
    import json as _json

    admin_user = utils.exec_shell_cmd(
        "radosgw-admin user create --uid=dedup-admin --display-name='Dedup Admin' "
        "--caps='dedup=*'"
    )
    if admin_user is False:
        admin_user = utils.exec_shell_cmd("radosgw-admin user info --uid=dedup-admin")
    admin_info = _json.loads(admin_user)
    user_info = {
        "user_id": "dedup-admin",
        "access_key": admin_info["keys"][0]["access_key"],
        "secret_key": admin_info["keys"][0]["secret_key"],
    }
    ctx = _get_ctx(request.node.nodeid)
    ctx["users"].append(user_info)
    return user_info


@pytest.fixture
def endpoint_url(rgw_config, ssh_con, io_info, request):
    user_info = s3lib.create_users(1)[0]
    ctx = _get_ctx(request.node.nodeid)
    ctx["users"].append(user_info)
    auth = reusable.get_auth(
        user_info,
        ssh_con,
        rgw_config.ssl,
        getattr(rgw_config, "haproxy", False),
    )
    return auth.endpoint_url


@pytest.fixture(autouse=True)
def step_recorder(request):
    test_name = request.node.name
    scenario_info = DEDUP_TEST_SCENARIOS.get(test_name, {})
    test_id = scenario_info.get("id", "?")
    goal = scenario_info.get("scenario", request.node.obj.__doc__ or "No description")
    recorder = dedup_utils.TestStepRecorder(test_id, goal)
    ctx = _get_ctx(request.node.nodeid)
    ctx["recorder"] = recorder
    dedup_utils._active_recorder = recorder
    yield recorder
    dedup_utils._active_recorder = None


@pytest.fixture
def test_context(request):
    return _get_ctx(request.node.nodeid)


def _do_post_pass_cleanup(node_id):
    ctx = _test_context.get(node_id)
    if not ctx:
        return
    log.info("=" * 60)
    log.info("POST-PASS CLEANUP")
    log.info("=" * 60)

    for bkt_name, marker in ctx.get("bucket_markers", {}).items():
        log.info(f"RADOS cleanup for bucket {bkt_name} (marker={marker})")
        dedup_utils.cleanup_rados_objects_by_marker(marker)

    purged_uids = set()
    for user_info in ctx.get("users", []):
        uid = user_info.get("user_id", "")
        if uid and uid not in purged_uids:
            dedup_utils.purge_user(uid)
            purged_uids.add(uid)

    log.info("POST-PASS CLEANUP COMPLETE")
    log.info("=" * 60)
    _test_context.pop(node_id, None)


# ---------------------------------------------------------------------------
# Pytest hooks for test scenario logging and summary
# ---------------------------------------------------------------------------

_test_results = []


def pytest_runtest_setup(item):
    test_name = item.name
    scenario_info = DEDUP_TEST_SCENARIOS.get(test_name, {})
    test_id = scenario_info.get("id", "?")
    category = scenario_info.get("category", "Unknown")
    scenario = scenario_info.get("scenario", item.obj.__doc__ or "No description")
    log.info("=" * 80)
    log.info(f"TEST START: [{test_id}] {test_name}")
    log.info(f"  Category : {category}")
    log.info(f"  Scenario : {scenario}")
    log.info("=" * 80)


def pytest_runtest_makereport(item, call):
    if call.when == "call":
        test_name = item.name
        node_id = item.nodeid
        scenario_info = DEDUP_TEST_SCENARIOS.get(test_name, {})
        test_id = scenario_info.get("id", "?")
        category = scenario_info.get("category", "Unknown")
        scenario = scenario_info.get("scenario", "")
        duration = round(call.duration, 2)

        if call.excinfo is None:
            status = "PASSED"
            error_msg = ""
            _test_passed[node_id] = True
        else:
            status = "FAILED"
            error_msg = str(call.excinfo.value)[:120]
            _test_passed[node_id] = False

        _test_results.append(
            {
                "id": test_id,
                "name": test_name,
                "category": category,
                "scenario": scenario,
                "status": status,
                "duration": duration,
                "error": error_msg,
            }
        )

        ctx = _test_context.get(node_id, {})
        recorder = ctx.get("recorder")
        if recorder:
            for line in recorder.get_report_lines(status, duration, error_msg):
                log.info(line)

        log.info("-" * 80)
        log.info(f"TEST RESULT: [{test_id}] {test_name} => {status} ({duration}s)")
        if error_msg:
            log.info(f"  Error: {error_msg}")
        log.info("-" * 80)

    elif call.when == "teardown":
        node_id = item.nodeid
        if _test_passed.get(node_id, False):
            _do_post_pass_cleanup(node_id)
        else:
            _test_context.pop(node_id, None)
        _test_passed.pop(node_id, None)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if not _test_results:
        return

    passed = [r for r in _test_results if r["status"] == "PASSED"]
    failed = [r for r in _test_results if r["status"] == "FAILED"]

    summary_lines = [
        "",
        "=" * 100,
        "DEDUP TEST SUITE SUMMARY",
        "=" * 100,
        f"{'ID':<5} {'Category':<14} {'Test Name':<42} {'Status':<8} {'Duration':<10} {'Error'}",
        "-" * 100,
    ]
    for r in _test_results:
        err_short = r["error"][:40] + "..." if len(r["error"]) > 40 else r["error"]
        summary_lines.append(
            f"{r['id']:<5} {r['category']:<14} {r['name']:<42} {r['status']:<8} {r['duration']:<10} {err_short}"
        )
    summary_lines.append("-" * 100)
    summary_lines.append(
        f"Total: {len(_test_results)} | Passed: {len(passed)} | Failed: {len(failed)}"
    )
    summary_lines.append("=" * 100)

    if failed:
        summary_lines.append("")
        summary_lines.append("FAILED TEST DETAILS:")
        summary_lines.append("-" * 100)
        for r in failed:
            summary_lines.append(f"  [{r['id']}] {r['name']}")
            summary_lines.append(f"       Scenario: {r['scenario']}")
            summary_lines.append(f"       Error   : {r['error']}")
            summary_lines.append("")

    if dedup_utils._savings_registry:
        summary_lines.append("")
        summary_lines.append("DEDUP STORAGE SAVINGS:")
        summary_lines.append("-" * 100)
        summary_lines.append(
            f"{'ID':<5} {'Uploaded':<14} {'Deduped Bytes':<14} {'Savings %':<12} "
            f"{'Ratio':<10} {'Deduped Objs':<14} {'Skipped Comp'}"
        )
        summary_lines.append("-" * 100)
        for test_id, s in sorted(dedup_utils._savings_registry.items()):
            ratio_str = f"{s['dedup_ratio']:.2f}x" if s["dedup_ratio"] > 0 else "N/A"
            comp_str = (
                str(s["skipped_compressed"]) if s["skipped_compressed"] > 0 else "-"
            )
            summary_lines.append(
                f"{s['test_id']:<5} "
                f"{dedup_utils._format_bytes(s['total_uploaded']):<14} "
                f"{dedup_utils._format_bytes(s['deduped_bytes']):<14} "
                f"{s['savings_pct']:<11.1f}% "
                f"{ratio_str:<10} "
                f"{s['deduped_count']:<14} "
                f"{comp_str}"
            )
        summary_lines.append("=" * 100)

    summary_text = "\n".join(summary_lines)
    log.info(summary_text)
    terminalreporter.write_line(summary_text)
