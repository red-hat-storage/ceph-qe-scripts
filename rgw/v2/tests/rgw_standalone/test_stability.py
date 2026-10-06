"""Zipper build stability — health probes before/after workload."""

import pytest

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.stability, pytest.mark.sanity]


def test_zipper_health_before(container, endpoint, rgw_config):
    expect_nginx = "developer-experience" in (
        rgw_config.get("image") or ""
    ) or bool(rgw_config.get("browser_port"))
    detail = zs.zipper_health(container, endpoint, expect_nginx=expect_nginx)
    assert detail.startswith("ok")


def test_zipper_health_after_smoke(
    container, endpoint, s3_client_factory, rgw_config
):
    """Run a tiny workload then re-check restart_count / processes."""
    client = s3_client_factory("normal")
    bkt = zs.unique_name("stab")
    zs.ensure_bucket(client, bkt)
    try:
        for i in range(10):
            client.put_object(Bucket=bkt, Key=f"k{i}", Body=b"stability")
        for i in range(10):
            client.get_object(Bucket=bkt, Key=f"k{i}")
        client.list_objects_v2(Bucket=bkt)
    finally:
        zs.wipe_bucket(client, bkt)

    detail = zs.zipper_health(container, endpoint)
    assert "ok" in detail
    # restart_count must remain 0 during smoke
    import subprocess

    out = subprocess.run(
        [
            "podman",
            "inspect",
            container,
            "--format",
            "{{.RestartCount}}",
        ],
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert out == "0", f"unexpected restart_count={out}"
