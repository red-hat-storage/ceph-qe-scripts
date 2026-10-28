# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
conftest.py for the IBMCEPH-19403 RGW race / data-loss suite.

This suite lives in its own directory so that it does not inherit the dedup
fixtures of ../conftest.py.  Run it with the runner (run_ibmceph_19403.py),
which passes --confcutdir so the parent conftest is not loaded, or directly:

  pytest --confcutdir=. -c pytest.ini test_overwrite_races.py \
      --ibmceph-config ../configs/test_ibmceph_19403.yaml
"""

import fcntl
import logging
import os
import tempfile

import ibmceph_lib
import pytest

log = logging.getLogger()


LOCK_PATH = os.path.join(tempfile.gettempdir(), "ibmceph_19403.lock")


def pytest_configure(config):
    """The suite must run one test at a time: refuse parallel workers."""
    if os.environ.get("PYTEST_XDIST_WORKER") or getattr(
        config.option, "numprocesses", None
    ):
        raise pytest.UsageError(
            "the IBMCEPH-19403 suite must run sequentially; do not use pytest-xdist (-n)"
        )


@pytest.fixture(scope="session", autouse=True)
def sequential_lock(request):
    """One suite run per host: tests change RGW config and attach gdb to RGW-A."""
    if request.config.getoption("collectonly", default=False):
        yield
        return
    fh = open(LOCK_PATH, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        pytest.exit(
            f"another IBMCEPH-19403 run holds {LOCK_PATH}; runs must be sequential",
            returncode=3,
        )
    try:
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def pytest_addoption(parser):
    parser.addoption(
        "--ibmceph-config",
        dest="ibmceph_config",
        default="",
        help="YAML config of the IBMCEPH-19403 suite (cluster, pools, keys)",
    )


@pytest.fixture(scope="session")
def env(request):
    """Connection details and helpers; no cluster access happens here."""
    cfg = ibmceph_lib.Cfg(request.config.getoption("ibmceph_config"))
    return ibmceph_lib.Env(cfg)


@pytest.fixture(scope="session")
def lab_session(env):
    """Lab-only: needs both RGWs, the orchestrator and ssh to RGW-A."""
    for side in ("a", "b"):
        if not env.wait_rgw(side, timeout=60):
            pytest.skip(f"RGW {side} ({env.url(side)}) does not answer")
    env.capture_env()
    return env


@pytest.fixture
def lab(lab_session):
    """Per-test: RGW-A answers; any gdb hold is released and gdb stopped after."""
    if not lab_session.wait_rgw("a", timeout=300):
        pytest.skip("RGW-A does not answer")
    yield lab_session
    lab_session.gdb_stop()


def pytest_runtest_setup(item):
    log.info("=" * 78)
    log.info("TEST START: %s", item.nodeid)
    doc = (item.obj.__doc__ or "").strip().splitlines()
    if doc:
        log.info("  %s", doc[0])


def pytest_runtest_logreport(report):
    if report.when == "call":
        log.info("TEST RESULT: %s => %s", report.nodeid, report.outcome.upper())
