"""Subprocess entry point for standalone and cephCI callers."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from rgw_tests.config import Credentials, load_config


def command(config, artifacts, markers="sanity", keyword=None):
    suites = Path(__file__).resolve().parent / "suites"
    argv = [
        sys.executable,
        "-m",
        "pytest",
        "-c",
        str(suites / "pytest.ini"),
        str(suites),
        "--rgw-config",
        str(Path(config).resolve()),
        "--junitxml",
        str(artifacts / "junit.xml"),
        "--log-file",
        str(artifacts / "pytest.log"),
        "--log-file-level",
        "INFO",
        "--tb=short",
        "-ra",
        "-m",
        markers,
    ]
    if keyword:
        argv.extend(["-k", keyword])
    return argv


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="RGW v3 YAML")
    parser.add_argument("--artifacts", default="artifacts")
    parser.add_argument("-m", "--markers", default="sanity")
    parser.add_argument("-k", "--keyword")
    parser.add_argument("--collect-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        for prefix in cfg.identities.values():
            Credentials.from_env(prefix)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    artifacts = Path(args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    cmd = command(args.config, artifacts, args.markers, args.keyword)
    if args.collect_only:
        cmd.append("--collect-only")
    # Prevent implicit third-party pytest plugins or environment addopts from
    # introducing cluster-wide parallelism or credential-bearing tracebacks.
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="")
    return subprocess.run(cmd, env=env, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
