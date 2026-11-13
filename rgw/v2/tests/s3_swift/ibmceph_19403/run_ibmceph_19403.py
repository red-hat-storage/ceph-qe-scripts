#!/usr/bin/env python3
# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
run_ibmceph_19403.py - cephci runner for the IBMCEPH-19403 RGW race suite.

cephci's sanity_rgw.py invokes:
    python run_ibmceph_19403.py -c <config.yaml> --rgw-node <ip>

The suite is in ibmceph_19403/ and is isolated from the dedup conftest one
directory up (--confcutdir).  Lab tests (gdb, SIGKILL, lifecycle) need the
cluster layout described in the config; tests that cannot run SKIP.

Suite YAML entry:
  - test:
      name: IBMCEPH-19403 RGW race / data-loss suite
      desc: Reproduce the IBMCEPH-19403 multipart / overwrite / index races
      module: sanity_rgw.py
      config:
        script-name: ibmceph_19403/run_ibmceph_19403.py
        config-file-name: test_ibmceph_19403.yaml
        timeout: 7200

The suite is sequential by design (no pytest-xdist, no random order, one run per
host at a time via a lock file).

Settings left unset in the config (RGW daemons, hosts, cephadm shell arguments,
S3 keys) are discovered from the orchestrator by ibmceph_discover.py.

Environment variable overrides (optional):
  IBMCEPH_PYTEST_MARKER   -m expression (ibmceph_mpu | ibmceph_race | ibmceph_cond |
                          ibmceph_cls | ibmceph_control | ibmceph_all)
  IBMCEPH_PYTEST_KEYWORD  -k expression, e.g. "19411 or 19412"
  IBMCEPH_PYTEST_JUNIT    path of a JUnit XML report
  ACCESS_KEY, SECRET_KEY  S3 credentials when the config does not hold them
"""

import argparse
import os
import sys

import pytest


def main():
    parser = argparse.ArgumentParser(
        description="IBMCEPH-19403 RGW race suite runner for cephci"
    )
    parser.add_argument("-c", dest="config", required=True, help="suite YAML config")
    parser.add_argument(
        "--rgw-node", dest="rgw_node", default="", help="RGW node (informational)"
    )
    parser.add_argument("-log_level", dest="log_level", default="info")
    args = parser.parse_args()

    test_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, test_dir)

    pytest_args = [
        test_dir,
        f"--rootdir={test_dir}",
        f"--confcutdir={test_dir}",
        "-c",
        os.path.join(test_dir, "pytest.ini"),
        f"--ibmceph-config={os.path.abspath(args.config)}",
        f"--rgw-node={args.rgw_node}",
        "--tb=short",
        f"--log-cli-level={args.log_level.upper()}",
    ]

    marker = os.environ.get("IBMCEPH_PYTEST_MARKER", "")
    if marker:
        pytest_args.extend(["-m", marker])

    keyword = os.environ.get("IBMCEPH_PYTEST_KEYWORD", "")
    if keyword:
        pytest_args.extend(["-k", keyword])

    junit_path = os.environ.get("IBMCEPH_PYTEST_JUNIT", "")
    if junit_path:
        pytest_args.append(f"--junitxml={junit_path}")

    sys.exit(pytest.main(pytest_args))


if __name__ == "__main__":
    main()
