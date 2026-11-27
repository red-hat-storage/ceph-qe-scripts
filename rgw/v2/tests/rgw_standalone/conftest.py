"""
Pytest fixtures for RGW Standalone (Zipper) automation.

Usage:
  pytest -C configs/test_rgw_standalone_all.yaml -v
  pytest -C configs/test_rgw_standalone_all.yaml --rgw-node <host>
"""

from __future__ import annotations

import logging
import os
import sys

import pytest
import yaml

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs
from v2.utils.log import configure_logging

log = logging.getLogger()

USER_LABELS = ("normal", "tenant", "subuser", "account_root", "account_user")


def pytest_addoption(parser):
    parser.addoption(
        "--config",
        "-C",
        dest="config",
        required=True,
        help="Path to RGW standalone YAML config",
    )
    parser.addoption(
        "--rgw-node",
        dest="rgw_node",
        default="",
        help="Node hostname/IP (informational; zipper uses local endpoint)",
    )


def pytest_configure(config):
    # markers already declared in pytest.ini; keep configure hook for future
    pass


@pytest.fixture(scope="session", autouse=True)
def setup_logging():
    configure_logging(f_name="test_rgw_standalone_pytest")


@pytest.fixture(scope="session")
def rgw_config(request):
    path = request.config.getoption("config")
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    cfg = data.get("config", data)
    # Allow env overrides for local runs
    if os.environ.get("RGW_ENDPOINT"):
        cfg["endpoint_url"] = os.environ["RGW_ENDPOINT"]
    if os.environ.get("RGW_CID"):
        cfg["container_id"] = os.environ["RGW_CID"]
        cfg["container_name"] = os.environ["RGW_CID"]
    return cfg


@pytest.fixture(scope="session")
def endpoint(rgw_config):
    if rgw_config.get("endpoint_url"):
        return rgw_config["endpoint_url"]
    ip = rgw_config.get("endpoint_ip", "127.0.0.1")
    port = rgw_config.get("endpoint_port", 7401)
    return f"http://{ip}:{port}"


@pytest.fixture(scope="session")
def container(rgw_config):
    return (
        rgw_config.get("container_name")
        or rgw_config.get("container_id")
        or os.environ.get("RGW_CID")
        or "rgw-standalone1"
    )


@pytest.fixture(scope="session")
def admin(rgw_config, container):
    return zs.ZipperAdmin(
        container=container,
        admin_bin=rgw_config.get("admin_bin", "rgw-standalone-admin"),
        conf=rgw_config.get("admin_conf"),
    )


@pytest.fixture(scope="session")
def users(admin, rgw_config):
    if rgw_config.get("skip_user_setup"):
        return zs.DEFAULT_USERS
    log.info("Creating zipper suite users (plain/tenant/subuser/account)")
    return zs.setup_default_users(admin)


@pytest.fixture(scope="session")
def object_sizes(rgw_config):
    sizes = rgw_config.get("object_sizes") or zs.OBJECT_SIZES
    return sizes


@pytest.fixture
def s3_client_factory(endpoint, users):
    def _make(label: str):
        ak, sk = zs.user_creds(users, label)
        return zs.make_s3_client(endpoint, ak, sk)

    return _make


@pytest.fixture
def account_root_client(endpoint, users):
    ak, sk = zs.user_creds(users, "account_root")
    return zs.make_s3_client(endpoint, ak, sk)


def pytest_generate_tests(metafunc):
    """Parametrize tests that declare 'user_label' across configured user types."""
    if "user_label" in metafunc.fixturenames:
        cfg_path = metafunc.config.getoption("config")
        labels = list(USER_LABELS)
        try:
            with open(cfg_path) as fh:
                data = yaml.safe_load(fh) or {}
            cfg = data.get("config", data)
            if cfg.get("user_labels"):
                labels = list(cfg["user_labels"])
        except Exception:
            pass
        metafunc.parametrize("user_label", labels, scope="function")
