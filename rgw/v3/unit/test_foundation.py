"""Offline checks for failure paths, isolation, and credential handling."""

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from rgw_tests.admin import Admin, AdminError
from rgw_tests.config import Credentials, load_config
from rgw_tests.polling import PollTimeout, wait_for
from rgw_tests.resources import CleanupError, Resources
from rgw_tests.runner import command, main


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "unknown: true",
        "objects: 0",
        "workers: true",
        "endpoint: ftp://example.com",
        "endpoint: https://user:secret@example.com",
        "user_types: [invalid]",
        "bucket_states: []",
        "multipart_part_size: 1024",
        "admin_command: radosgw-admin",
        "identities: {normal: 1}",
        "features: [notifications]",
        "features: [{}]",
    ],
)
def test_reject_invalid_configuration(tmp_path, text):
    path = tmp_path / "test.yaml"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_config(path)


def test_example_configs_validate():
    root = Path(__file__).resolve().parents[1]
    for path in (root / "configs").glob("*.yaml"):
        load_config(path)


def test_credentials_never_in_repr(monkeypatch):
    monkeypatch.setenv("TEST_ACCESS_KEY_ID", "access-sensitive")
    monkeypatch.setenv("TEST_SECRET_ACCESS_KEY", "secret-sensitive")
    monkeypatch.setenv("TEST_SESSION_TOKEN", "token-sensitive")
    credentials = Credentials.from_env("TEST")
    assert "sensitive" not in repr(credentials)
    monkeypatch.delenv("TEST_SECRET_ACCESS_KEY")
    with pytest.raises(ValueError, match="TEST_SECRET_ACCESS_KEY"):
        Credentials.from_env("TEST")


def test_cleanup_continues_after_failure_and_runs_once():
    order = []
    resources = Resources()
    resources.defer("first", order.append, "first")

    def fail():
        order.append("failed")
        raise RuntimeError("sensitive payload")

    resources.defer("failed resource", fail)
    resources.defer("last", order.append, "last")
    with pytest.raises(CleanupError, match="failed resource") as error:
        resources.close()
    assert "sensitive" not in str(error.value)
    assert order == ["last", "failed", "first"]
    resources.close()
    assert len(order) == 3


def test_poll_timeout_and_recovery(monkeypatch):
    clock = iter([0, 0, 2, 4])
    sleeps = []
    monkeypatch.setattr("rgw_tests.polling.time.monotonic", lambda: next(clock))
    monkeypatch.setattr("rgw_tests.polling.time.sleep", sleeps.append)
    with pytest.raises(PollTimeout, match="attempts=3"):
        wait_for(lambda: False, timeout=4, interval=2, description="test outcome")
    assert sleeps == [2, 2]
    monkeypatch.setattr("rgw_tests.polling.time.monotonic", lambda: 0)
    probe = Mock(side_effect=[False, {"ready": True}])
    assert wait_for(probe, timeout=4, interval=2, description="ready") == {
        "ready": True
    }


def test_poll_unexpected_error_is_not_hidden():
    with pytest.raises(PermissionError):
        wait_for(
            Mock(side_effect=PermissionError),
            timeout=1,
            interval=1,
            description="probe",
        )


def test_admin_argv_and_redacted_error(monkeypatch):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, '{"id": "account"}', ""))
    monkeypatch.setattr("rgw_tests.admin.subprocess.run", run)
    admin = Admin(["sudo", "radosgw-admin"])
    assert admin.run(
        "user", "create", uid="literal;$(touch nope)", account_root=True
    ) == {"id": "account"}
    argv = run.call_args.args[0]
    assert argv == [
        "sudo",
        "radosgw-admin",
        "user",
        "create",
        "--uid",
        "literal;$(touch nope)",
        "--account-root",
    ]
    assert "shell" not in run.call_args.kwargs
    run.return_value = subprocess.CompletedProcess([], 1, "secret-key", "secret-token")
    with pytest.raises(AdminError) as error:
        admin.run("user", "create")
    assert "secret" not in str(error.value)


def test_runner_preserves_arguments_and_return_code(tmp_path, monkeypatch):
    config = tmp_path / "config with spaces.yaml"
    config.write_text("{}")
    artifacts = tmp_path / "output with spaces"
    cmd = command(config, artifacts, "sanity or lifecycle", "copy and not abort")
    assert cmd[cmd.index("--rgw-config") + 1] == str(config)
    assert cmd[cmd.index("-m", 3) + 1] == "sanity or lifecycle"
    run = Mock(return_value=subprocess.CompletedProcess([], 5))
    monkeypatch.setattr("rgw_tests.runner.subprocess.run", run)
    assert main(["--config", str(config), "--artifacts", str(artifacts)]) == 5
    assert run.call_args.kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


def test_cephci_quotes_shell_arguments():
    import shlex

    from rgw_tests.cephci import run

    cluster = Mock()
    node = cluster.get_ceph_object.return_value.node
    node.exec_command.return_value = 5
    cfg = {
        "v3-python": "/venv with spaces/bin/python",
        "v3-config": "/tmp/config;literal.yaml",
        "v3-artifacts": "/tmp/output",
        "markers": "sanity or lifecycle",
    }
    assert run(cluster, config=cfg) == 5
    argv = shlex.split(node.exec_command.call_args.kwargs["cmd"])
    assert argv[0] == cfg["v3-python"]
    assert argv[argv.index("--config") + 1] == cfg["v3-config"]
    assert node.exec_command.call_args.kwargs["long_running"] is True


def test_tools_pass_secrets_only_in_environment(monkeypatch):
    from rgw_tests.config import Config
    from rgw_tests.operations.tools import AWSCLI, Elbencho, ToolError

    monkeypatch.setenv("AWS_SESSION_TOKEN", "unrelated-token")
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "{}", ""))
    monkeypatch.setattr("rgw_tests.operations.tools.subprocess.run", run)
    tool = AWSCLI(Config(), Credentials("sensitive-access", "sensitive-secret"))
    tool.call("list-objects-v2", bucket="owned-bucket")
    assert "sensitive" not in repr(run.call_args.args)
    env = run.call_args.kwargs["env"]
    assert "AWS_SESSION_TOKEN" not in env
    assert env["AWS_SECRET_ACCESS_KEY"] == "sensitive-secret"
    elbencho = Elbencho(Config(), Credentials("access", "secret", "temporary-token"))
    elbencho.phase("write", "owned-bucket")
    assert run.call_args.kwargs["env"]["AWS_SESSION_TOKEN"] == "temporary-token"
    assert run.call_args.args[0][-1] == "s3://owned-bucket"
    with pytest.raises(ValueError, match="restricted to CRUD"):
        elbencho.phase("arbitrary", "owned-bucket")
    run.return_value = subprocess.CompletedProcess([], 1, "secret", "secret")
    with pytest.raises(ToolError) as error:
        tool.call("list-objects-v2", bucket="owned-bucket")
    assert "secret" not in str(error.value)
