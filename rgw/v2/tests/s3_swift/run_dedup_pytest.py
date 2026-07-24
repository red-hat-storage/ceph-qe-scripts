"""
run_dedup_pytest.py - Thin wrapper to run pytest-based dedup tests via cephci.

cephci's sanity_rgw.py invokes: python run_dedup_pytest.py -c <config.yaml> --rgw-node <ip>
This wrapper translates that into a pytest.main() call against test_dedup_pytest.py.

Suite YAML entry:
  - test:
      name: RGW Dedup Full Suite (pytest)
      desc: Run all 30 dedup tests via pytest framework
      module: sanity_rgw.py
      config:
        script-name: run_dedup_pytest.py
        config-file-name: test_dedup_all.yaml
        timeout: 7200
"""

import argparse
import os
import sys

import pytest


def main():
    parser = argparse.ArgumentParser(description="RGW Dedup Pytest Runner for cephci")
    parser.add_argument("-c", dest="config", required=True, help="RGW test YAML config")
    parser.add_argument(
        "--rgw-node", dest="rgw_node", default="", help="RGW node hostname"
    )
    parser.add_argument("-log_level", dest="log_level", default="info")
    args = parser.parse_args()

    test_dir = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(test_dir, "test_dedup_pytest.py")

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

    marker = os.environ.get("DEDUP_PYTEST_MARKER", "")
    if marker:
        pytest_args.extend(["-m", marker])

    keyword = os.environ.get("DEDUP_PYTEST_KEYWORD", "")
    if keyword:
        pytest_args.extend(["-k", keyword])

    junit_path = os.environ.get("DEDUP_PYTEST_JUNIT", "")
    if junit_path:
        pytest_args.append(f"--junitxml={junit_path}")

    exit_code = pytest.main(pytest_args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
