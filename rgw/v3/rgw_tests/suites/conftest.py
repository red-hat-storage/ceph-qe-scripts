"""Integration-only fixtures; collection and unit tests never contact a cluster."""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from rgw_tests.admin import Admin
from rgw_tests.clients import make_client
from rgw_tests.config import Credentials, load_config
from rgw_tests.operations.buckets import Buckets
from rgw_tests.operations.crud import CRUD
from rgw_tests.operations.users import Users
from rgw_tests.resources import Resources


def pytest_addoption(parser):
    parser.addoption(
        "--rgw-config", help="RGW v3 YAML; absent means integration tests skip"
    )


def pytest_configure(config):
    try:
        config.rgw_v3 = load_config(config.getoption("--rgw-config"))
        for prefix in config.rgw_v3.identities.values():
            Credentials.from_env(prefix)
    except (ValueError, OSError) as exc:
        raise pytest.UsageError(str(exc)) from None
    for logger in ("boto3", "botocore", "urllib3"):
        logging.getLogger(logger).setLevel(logging.WARNING)


def pytest_generate_tests(metafunc):
    cfg = metafunc.config.rgw_v3
    if "user_kind" in metafunc.fixturenames:
        metafunc.parametrize("user_kind", cfg.user_types)
    if "bucket_state" in metafunc.fixturenames:
        metafunc.parametrize("bucket_state", cfg.bucket_states)


def pytest_collection_modifyitems(config, items):
    cfg = config.rgw_v3
    for item in items:
        if Path(__file__).parent not in Path(item.path).parents:
            continue
        item.add_marker(pytest.mark.integration)
        if not config.getoption("--rgw-config"):
            item.add_marker(
                pytest.mark.skip(reason="Supply --rgw-config for live RGW tests")
            )
        for tool in ("awscli", "elbencho"):
            if item.get_closest_marker(tool) and tool not in cfg.optional_tools:
                item.add_marker(
                    pytest.mark.skip(reason=f"Enable {tool} in optional_tools")
                )
        for feature in ("lifecycle", "gc", "notifications", "resharding"):
            if item.get_closest_marker(feature) and feature not in cfg.features:
                item.add_marker(
                    pytest.mark.skip(reason=f"Enable {feature} in features")
                )


@pytest.fixture(scope="session")
def cfg(pytestconfig):
    return pytestconfig.rgw_v3


@pytest.fixture(scope="session")
def admin(cfg):
    return Admin(cfg.admin_command, cfg.timeout)


@pytest.fixture
def resources():
    registry = Resources()
    try:
        yield registry
    finally:
        registry.close()


def build_context(cfg, admin, resources, kind, state):
    if kind in ("ldap", "sts") and kind not in cfg.identities:
        pytest.skip(f"{kind} requires pre-provisioned credentials in identities")
    credentials = Users(cfg, admin, resources).create(kind)
    client = make_client(cfg, credentials)
    resources.defer("S3 client", client.close)
    bucket = Buckets(client, resources).create(state)
    return SimpleNamespace(
        client=client,
        bucket=bucket,
        crud=CRUD(client, bucket),
        state=state,
        credentials=credentials,
    )


@pytest.fixture
def context(cfg, admin, resources, user_kind, bucket_state):
    return build_context(cfg, admin, resources, user_kind, bucket_state)


@pytest.fixture
def feature_context(cfg, admin, resources):
    return build_context(cfg, admin, resources, cfg.user_types[0], "normal")


@pytest.fixture
def versioned_context(cfg, admin, resources):
    return build_context(cfg, admin, resources, cfg.user_types[0], "versioned")
