"""
run_rgw_standalone_pytest.py - Thin wrapper for cephci sanity_rgw.py.

cephci invokes:
  python run_rgw_standalone_pytest.py -c <config.yaml> --rgw-node <ip>

Suite YAML:
  - test:
      module: sanity_rgw.py
      config:
        test-version: standalone
        script-name: run_rgw_standalone_pytest.py
        config-file-name: test_rgw_standalone_all.yaml
        use-standalone: true
        pytest-results: true
"""

import argparse
import os
import sys

import pytest


def main():
    parser = argparse.ArgumentParser(
        description="RGW Standalone (Zipper) Pytest Runner for cephci"
    )
    parser.add_argument("-c", dest="config", required=True, help="YAML config")
    parser.add_argument(
        "--rgw-node", dest="rgw_node", default="", help="Node hostname/IP"
    )
    parser.add_argument("-log_level", dest="log_level", default="info")
    args = parser.parse_args()

    test_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.abspath(args.config)

    pytest_args = [
        test_dir,
        f"--rootdir={test_dir}",
        f"-C={config_path}",
        "-v",
        "--tb=short",
        f"--log-cli-level={args.log_level.upper()}",
    ]

    if args.rgw_node:
        pytest_args.append(f"--rgw-node={args.rgw_node}")

    marker = os.environ.get(
        "RGW_STANDALONE_PYTEST_MARKER",
        os.environ.get("PYTEST_MARKER", ""),
    )
    if marker:
        pytest_args.extend(["-m", marker])

    keyword = os.environ.get(
        "RGW_STANDALONE_PYTEST_KEYWORD",
        os.environ.get("PYTEST_KEYWORD", ""),
    )
    if keyword:
        pytest_args.extend(["-k", keyword])

    junit_path = os.environ.get(
        "PYTEST_JUNIT",
        os.environ.get("DEDUP_PYTEST_JUNIT", ""),
    )
    if junit_path:
        pytest_args.append(f"--junitxml={junit_path}")

    # Avoid collecting this runner itself
    pytest_args.extend(["--ignore", os.path.abspath(__file__)])

    exit_code = pytest.main(pytest_args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
