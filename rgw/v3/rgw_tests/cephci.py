"""cephCI run() adapter for a pre-provisioned v3 installation on a test node."""

import shlex


def run(ceph_cluster, **kwargs):
    config = kwargs["config"]
    node = ceph_cluster.get_ceph_object(config.get("node-role", "client")).node
    argv = [
        config["v3-python"],
        "-m",
        "rgw_tests.runner",
        "--config",
        config["v3-config"],
        "--artifacts",
        config["v3-artifacts"],
        "-m",
        config.get("markers", "sanity"),
    ]
    if config.get("keyword"):
        argv.extend(["-k", config["keyword"]])
    # cephCI's node API takes shell text; quote every argument individually.
    return node.exec_command(
        cmd=shlex.join(argv),
        long_running=True,
        timeout=config.get("timeout", 3600),
    )
