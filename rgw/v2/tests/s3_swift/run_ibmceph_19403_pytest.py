"""
run_ibmceph_19403_pytest.py — Thin wrapper to run IBMCEPH-19403 race-condition
tests via pytest, compatible with cephci's sanity_rgw.py invocation style.

Covers all 10 bugs reproduced under IBMCEPH-19403 epic:
  19405   Lock renewal failure + concurrent complete → data loss
  19406   RGW crash between head-write and meta-delete → ghost object
  19406v  Same as 19406 on versioning-SUSPENDED bucket
  19407   Failed meta-delete + retry from second RGW → data loss (SIGKILL)
  19407bl Failed meta-delete + retry → data loss (OSD blocklist method)
  19410   Lifecycle AbortMPU ignores completion lock → premature GC
  19412   DeleteObject racing overwrite deletes new data
  19414   CopyObject-self racing overwrite deletes data
  19416   Stalled write lost from bucket index
  19417   DeleteObject lost RADOS-level ID-tag guard
  19424   8 concurrent conditional PUTs (If-Match) all succeed (at most 1 should)

cephci invokes:
  python run_ibmceph_19403_pytest.py -c <config.yaml> --rgw-node <ip>

Suite YAML entry example:
  - test:
      name: IBMCEPH-19403 RGW Race Condition Suite (pytest)
      desc: Reproduce all 10 overwrite/race bugs from IBMCEPH-19403 epic
      module: sanity_rgw.py
      config:
        script-name: run_ibmceph_19403_pytest.py
        config-file-name: test_ibmceph_19403.yaml
        timeout: 7200

Environment variable overrides (optional):
  IBMCEPH_PYTEST_MARKER  — run only tests with this marker
                           (ibmceph_mpu | ibmceph_race | ibmceph_cond | ibmceph_all)
  IBMCEPH_PYTEST_KEYWORD — pytest -k expression (e.g. "19424 or 19407bl")
  IBMCEPH_PYTEST_JUNIT   — path to write JUnit XML report
"""

import argparse
import os
import sys

import pytest


def main():
    parser = argparse.ArgumentParser(
        description="IBMCEPH-19403 RGW Race Condition Pytest Runner for cephci"
    )
    parser.add_argument("-c", dest="config", required=True, help="RGW test YAML config")
    parser.add_argument(
        "--rgw-node",
        dest="rgw_node",
        default="",
        help="RGW-A node hostname (informational)",
    )
    parser.add_argument("-log_level", dest="log_level", default="info")
    args = parser.parse_args()

    test_dir = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(test_dir, "test_ibmceph_19403_pytest.py")

    config_path = os.path.abspath(args.config)

    pytest_args = [
        test_file,
        f"-C={config_path}",
        "-v",
        "--tb=short",
        f"--log-cli-level={args.log_level.upper()}",
    ]

    if args.rgw_node:
        pytest_args.append(f"--rgw-node={args.rgw_node}")

    # Optional: run only a subset via env vars (same pattern as dedup runner)
    marker = os.environ.get("IBMCEPH_PYTEST_MARKER", "")
    if marker:
        pytest_args.extend(["-m", marker])

    keyword = os.environ.get("IBMCEPH_PYTEST_KEYWORD", "")
    if keyword:
        pytest_args.extend(["-k", keyword])

    junit_path = os.environ.get("IBMCEPH_PYTEST_JUNIT", "")
    if junit_path:
        pytest_args.append(f"--junitxml={junit_path}")

    exit_code = pytest.main(pytest_args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
