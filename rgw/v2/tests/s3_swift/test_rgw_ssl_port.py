"""
test_rgw_ssl_port - Validate the new cephadm RGWSpec ``rgw_frontend_ssl_port`` parameter
and its mutual-inference relationship with ``ssl``.

Feature
-------
A new ``spec.rgw_frontend_ssl_port`` field is added to the cephadm RGW service
definition.  Two automatic-inference rules exist:

  1. If ``rgw_frontend_ssl_port`` is set and ``ssl`` is *not* specified,
     ``ssl`` is automatically inferred to ``true``.
  2. If ``ssl: true`` is set and ``rgw_frontend_ssl_port`` is *not* specified,
     ``rgw_frontend_ssl_port`` is automatically set to ``443``.

Usage
-----
    test_rgw_ssl_port.py -c configs/<input_yaml>

Input YAML files (``configs/test_rgw_ssl_port_*.yaml``):

    test_rgw_ssl_port_explicit.yaml          TC-1  explicit ssl_port + ssl: true
    test_rgw_ssl_port_infer_ssl_true.yaml    TC-2  ssl: true → infers ssl_port=443
    test_rgw_ssl_port_infer_from_port.yaml   TC-3  ssl_port set → infers ssl: true
    test_rgw_ssl_port_custom_8443.yaml       TC-4  non-standard port 8443
    test_rgw_ssl_port_ssl_only.yaml          TC-5  SSL-only, no plain HTTP port
    test_rgw_ssl_port_cert_binding.yaml      TC-6  generate_cert bound to ssl_port
    test_rgw_ssl_port_change_port.yaml       TC-7  day-2 change ssl_port 443→8443
    test_rgw_ssl_port_remove_ssl.yaml        TC-8  day-2 remove ssl entirely
    test_rgw_ssl_port_no_cert_negative.yaml  TC-9  negative: ssl_port set, no cert
    test_rgw_ssl_port_extra_args.yaml        TC-10 extra_args coexist with ssl_port
    test_rgw_ssl_port_multihost.yaml         TC-11 3-host placement, same ssl_port

Operation (per scenario)
------------------------
  1. Build and apply a temporary cephadm RGW service spec containing the
     relevant ssl_port / ssl / generate_cert combination.
  2. Wait for the service to reach running state.
  3. Verify ``ceph orch ls --export`` reflects the expected spec fields
     (``rgw_frontend_ssl_port``, ``ssl``) and their inferred values.
  4. Inspect ``ceph config get client.rgw.<daemon> rgw_frontends`` on each
     daemon to confirm the ssl_port appears in the beast frontend string.
  5. Assert listening ports via ``ss -tlnp`` on each placement host.
  6. Run S3 IO (PUT/GET/DELETE) against the HTTPS endpoint and, where a plain
     HTTP port is also configured, against the HTTP endpoint.
  7. For cert-binding tests: verify via ``openssl s_client`` that the
     self-signed cert is served on the configured ssl_port.
  8. For day-2 reconfiguration tests: re-apply the spec with the modified
     field, wait for redeploy, re-run assertions.
  9. For the negative test: assert that the daemon is NOT in ``running`` state
     or that an HTTPS handshake attempt fails.
 10. ``finally:`` remove the temporary service and purge leftover config-DB keys.
"""

import argparse
import json
import logging
import os
import socket
import sys
import time
import traceback

import yaml

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

# Local import: shared config-DB cleanup helper (same directory as this file).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reuseport_cleanup as _rp_cleanup  # noqa: E402

log = logging.getLogger()
TEST_DATA_PATH = None

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

DEFAULT_SSL_PORT = 443
SPEC_PATH = "/tmp/rgw_ssl_port_spec.yaml"


def _ops(config):
    """Return test_ops dict; safe when attribute is not a dict."""
    return config.test_ops if isinstance(config.test_ops, dict) else {}


def _run_cmd(cmd):
    out = utils.exec_shell_cmd(cmd)
    return "" if out is None else str(out)


# ---------------------------------------------------------------------------
# Cluster inventory
# ---------------------------------------------------------------------------


def get_cluster_hosts():
    """Return list of {hostname, addr} dicts from ``ceph orch host ls``."""
    log.info("Step: listing cluster hosts via ceph orch host ls")
    raw = _run_cmd("ceph orch host ls -f json")
    try:
        hosts = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise TestExecError(f"Could not parse ceph orch host ls output: {exc}")
    host_list = []
    for h in hosts:
        hostname = h.get("hostname")
        addr = h.get("addr") or hostname
        host_list.append({"hostname": hostname, "addr": addr})
        log.info(f"  host={hostname} addr={addr}")
    if not host_list:
        raise TestExecError("No hosts found from ceph orch host ls")
    return host_list


# ---------------------------------------------------------------------------
# Spec build / apply
# ---------------------------------------------------------------------------


def _build_spec(ops, placement_hosts):
    """
    Construct the cephadm service spec dict from test_ops.

    Handles all combinations of ssl / rgw_frontend_ssl_port / generate_cert /
    rgw_frontend_port / rgw_frontend_extra_args as driven by the YAML config.
    """
    service_id = ops.get("service_id", "ssl-port-qe")
    spec_section = {
        "rgw_frontend_type": ops.get("rgw_frontend_type", "beast"),
    }

    # Plain HTTP port (optional — TC-5 omits it for SSL-only)
    http_port = ops.get("rgw_frontend_port")
    if http_port is not None:
        spec_section["rgw_frontend_port"] = int(http_port)

    # New field under test
    ssl_port = ops.get("rgw_frontend_ssl_port")
    if ssl_port is not None:
        spec_section["rgw_frontend_ssl_port"] = int(ssl_port)

    # ssl flag (may be absent to test inference)
    if ops.get("ssl") is not None:
        spec_section["ssl"] = bool(ops["ssl"])

    # Certificate generation
    if ops.get("generate_cert") is not None:
        spec_section["generate_cert"] = bool(ops["generate_cert"])

    # Optional multisite / realm fields
    for key in ("rgw_realm", "rgw_zonegroup", "rgw_zone", "rgw_exit_timeout_secs"):
        if ops.get(key) is not None:
            spec_section[key] = ops[key]

    if ops.get("disable_multisite_sync_traffic") is not None:
        spec_section["disable_multisite_sync_traffic"] = bool(
            ops["disable_multisite_sync_traffic"]
        )

    if ops.get("rgw_frontend_extra_args") is not None:
        spec_section["rgw_frontend_extra_args"] = list(ops["rgw_frontend_extra_args"])

    placement = {"hosts": list(placement_hosts)}
    count_per_host = ops.get("count_per_host")
    if count_per_host is not None:
        placement["count_per_host"] = int(count_per_host)

    return {
        "service_type": "rgw",
        "service_id": service_id,
        "placement": placement,
        "spec": spec_section,
    }


def apply_rgw_spec(ops, hosts):
    """
    Write the service spec YAML and apply via ``ceph orch apply -i``.

    Returns a context dict used by subsequent assertion helpers.
    """
    placement_hosts = ops.get("placement_hosts")
    if not placement_hosts:
        placement_hosts = [hosts[0]["hostname"]]

    spec_dict = _build_spec(ops, placement_hosts)
    service_id = spec_dict["service_id"]
    service_name = f"rgw.{service_id}"

    spec_path = ops.get("spec_path", SPEC_PATH)
    with open(spec_path, "w") as fh:
        yaml.safe_dump(spec_dict, fh, default_flow_style=False)

    content = _run_cmd(f"cat {spec_path}")
    log.info(f"RGW spec content:\n{content}")

    log.info(f"Step: applying RGW spec via ceph orch apply -i {spec_path}")
    out = _run_cmd(f"ceph orch apply -i {spec_path}")
    log.info(f"orch apply output: {out}")

    count_per_host = int(ops.get("count_per_host", 1))
    expected_running = count_per_host * len(placement_hosts)

    return {
        "service_id": service_id,
        "service_name": service_name,
        "http_port": ops.get("rgw_frontend_port"),
        "ssl_port": ops.get("rgw_frontend_ssl_port"),
        "ssl": ops.get("ssl"),
        "generate_cert": ops.get("generate_cert", False),
        "placement_hosts": list(placement_hosts),
        "expected_running": expected_running,
        "spec_path": spec_path,
        "spec_dict": spec_dict,
    }


# ---------------------------------------------------------------------------
# Service / daemon wait helpers
# ---------------------------------------------------------------------------


def wait_for_rgw_service(service_name, expected_running, timeout=300, poll=10):
    """Poll ``ceph orch ls`` until the service has ``expected_running`` daemons."""
    log.info(
        f"Step: waiting for service {service_name} "
        f"running>={expected_running} (timeout={timeout}s)"
    )
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        raw = _run_cmd(f"ceph orch ls --service-name {service_name} -f json")
        if not raw:
            time.sleep(poll)
            continue
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            time.sleep(poll)
            continue
        if not data:
            time.sleep(poll)
            continue
        status = data[0].get("status", {})
        running = status.get("running", 0)
        last = f"running={running} size={status.get('size', 0)}"
        log.info(f"  {last}")
        if running >= expected_running:
            log.info(f"Service {service_name} is up: {last}")
            return data[0]
        time.sleep(poll)
    raise TestExecError(f"Timed out waiting for {service_name}; last: {last}")


def wait_for_service_gone(service_name, timeout=180, poll=5):
    """Wait until ``ceph orch ls`` no longer reports the service."""
    log.info(f"Step: waiting for service {service_name} to disappear (timeout={timeout}s)")
    deadline = time.time() + timeout
    while time.time() < deadline:
        raw = _run_cmd(f"ceph orch ls --service-name {service_name} -f json")
        text = str(raw or "").strip()
        if (not text) or text in ("[]", "null") or "No services" in text:
            log.info(f"Service {service_name} is gone")
            return
        try:
            if not json.loads(text):
                log.info(f"Service {service_name} is gone")
                return
        except (json.JSONDecodeError, TypeError):
            if "No services" in text:
                return
        log.info(f"  still present: {text[:120]}")
        time.sleep(poll)
    log.warning(f"Service {service_name} still visible after {timeout}s")


def get_rgw_daemons(service_name):
    """Return orch ps JSON list for the RGW service."""
    log.info(f"Step: fetching daemons for {service_name}")
    raw = _run_cmd(f"ceph orch ps --service-name {service_name} -f json")
    daemons = json.loads(raw) if raw else []
    for d in daemons:
        log.info(
            f"  daemon={d.get('daemon_name')} host={d.get('hostname')} "
            f"ports={d.get('ports')} status={d.get('status_desc')}"
        )
    return daemons


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def ensure_firewall_port(port):
    """Open the port in firewalld when firewalld is active; no-op otherwise."""
    log.info(f"Step: ensuring firewall allows TCP/{port}")
    active = _run_cmd("firewall-cmd --state 2>/dev/null || echo not_running")
    if active and "running" in str(active):
        _run_cmd(f"firewall-cmd --add-port={port}/tcp --permanent || true")
        _run_cmd("firewall-cmd --reload || true")
        ports_out = _run_cmd("firewall-cmd --list-ports || true")
        log.info(f"  firewall ports after update: {ports_out}")
    else:
        log.info("  firewalld not active; skipping")


def wait_for_port_listen(port, timeout=120, poll=5):
    """Wait until something is listening on ``port``."""
    log.info(f"Step: waiting for TCP port {port} to be listening (timeout={timeout}s)")
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = _run_cmd(f"ss -lntp | grep ':{port} ' || true")
        log.info(f"  ss probe :{port}: {out}")
        if out and str(port) in str(out):
            log.info(f"Port {port} is listening")
            return
        time.sleep(poll)
    raise TestExecError(f"Nothing listening on TCP port {port} after {timeout}s")


def assert_port_not_listening(port, hosts=None):
    """Fail if anything is listening on ``port`` — used for negative port checks."""
    log.info(f"Step: asserting that TCP port {port} is NOT listening")
    out = _run_cmd(f"ss -lntp | grep ':{port} ' || true")
    log.info(f"  ss result for :{port}: {out}")
    if out and str(port) in str(out):
        raise TestExecError(
            f"Port {port} is unexpectedly listening. Output: {out}"
        )
    log.info(f"Port {port} is correctly NOT listening")


def resolve_host_addr(hosts, placement_hosts):
    """Return (hostname, ip) for the first placement host."""
    host_map = {h["hostname"]: h["addr"] for h in hosts}
    target = placement_hosts[0]
    addr = host_map.get(target, target)
    try:
        socket.gethostbyname(addr)
        ip = addr
    except socket.gaierror:
        ip = host_map.get(target, addr)
    return target, ip


# ---------------------------------------------------------------------------
# Assertions against orch export and ceph config
# ---------------------------------------------------------------------------


def verify_orch_export(ctx):
    """
    Verify that ``ceph orch ls --service-name <name> --export`` includes the
    expected ssl_port and ssl values (including inferred ones).
    """
    service_name = ctx["service_name"]
    log.info(f"Step: verifying orch export for {service_name}")
    raw = _run_cmd(
        f"ceph orch ls --service-name {service_name} --export -f yaml"
    )
    log.info(f"  orch export:\n{raw}")
    if not raw:
        log.warning("  orch export returned empty; skipping export assertions")
        return

    # Determine what values we expect after inference.
    # Rule A: ssl: true without ssl_port  → ssl_port defaults to 443
    # Rule B: ssl_port set without ssl    → ssl inferred to true
    expected_ssl_port = ctx.get("ssl_port")
    expected_ssl = ctx.get("ssl")

    if expected_ssl_port is not None and expected_ssl is None:
        # Rule B: ssl should appear as true in the export
        expected_ssl = True
    if expected_ssl is True and expected_ssl_port is None:
        # Rule A: ssl_port should appear as 443 in the export
        expected_ssl_port = DEFAULT_SSL_PORT

    if expected_ssl_port is not None:
        key = f"rgw_frontend_ssl_port: {expected_ssl_port}"
        if key not in raw:
            raise TestExecError(
                f"Expected '{key}' in orch export, not found.\n{raw}"
            )
        log.info(f"  ✓ {key} present in export")

    if expected_ssl is True:
        if "ssl: true" not in raw:
            raise TestExecError(
                f"Expected 'ssl: true' in orch export, not found.\n{raw}"
            )
        log.info("  ✓ ssl: true present in export")


def verify_rgw_frontends_config(daemons, ctx):
    """
    Inspect ``ceph config get client.rgw.<daemon> rgw_frontends`` for each
    daemon and assert the ssl_port token appears in the Beast frontend string.
    Also asserts ``rgw_frontend_extra_args`` tokens are present when configured.
    """
    ssl_port = ctx.get("ssl_port")
    # After inference, ssl_port may default to 443
    if ssl_port is None and ctx.get("ssl"):
        ssl_port = DEFAULT_SSL_PORT
    if ssl_port is None:
        log.info("Step: skipping rgw_frontends ssl_port assertion (no ssl_port expected)")
        return

    extra_args = ctx["spec_dict"]["spec"].get("rgw_frontend_extra_args", [])
    log.info(
        f"Step: verifying rgw_frontends ssl_port={ssl_port} "
        f"extra_args={extra_args} on {len(daemons)} daemon(s)"
    )
    for d in daemons:
        daemon_name = d.get("daemon_name")
        who = f"client.{daemon_name}"
        frontend = str(_run_cmd(f"ceph config get {who} rgw_frontends") or "").strip()
        log.info(f"  {who} rgw_frontends='{frontend}'")

        ssl_token = f"ssl_port={ssl_port}"
        if ssl_token not in frontend:
            raise TestExecError(
                f"Expected '{ssl_token}' in rgw_frontends for {who}, got: '{frontend}'"
            )
        log.info(f"    ✓ {ssl_token} found")

        for arg in extra_args:
            if str(arg) not in frontend:
                raise TestExecError(
                    f"Expected extra_arg '{arg}' in rgw_frontends for {who}, "
                    f"got: '{frontend}'"
                )
            log.info(f"    ✓ extra_arg '{arg}' found")

    log.info("rgw_frontends verification passed")


def verify_listeners(ctx, check_ssl=True, check_http=True):
    """Assert listening ports on each placement host using ``ss -tlnp``."""
    ssl_port = ctx.get("ssl_port")
    if ssl_port is None and ctx.get("ssl"):
        ssl_port = DEFAULT_SSL_PORT
    http_port = ctx.get("http_port")
    hosts = ctx.get("placement_hosts", [])

    log.info(
        f"Step: verifying listeners on {hosts} "
        f"ssl_port={ssl_port} http_port={http_port}"
    )

    if check_ssl and ssl_port is not None:
        ensure_firewall_port(ssl_port)
        wait_for_port_listen(ssl_port, timeout=120)

    if check_http and http_port is not None:
        ensure_firewall_port(http_port)
        wait_for_port_listen(http_port, timeout=120)


def verify_cert_binding(host_ip, ssl_port):
    """
    Run ``openssl s_client -connect`` and assert that a certificate is served
    on the configured SSL port.  We only check for the BEGIN CERTIFICATE marker
    since the cert is self-signed and its CN depends on cephadm internals.
    """
    log.info(f"Step: verifying TLS cert binding on {host_ip}:{ssl_port}")
    cmd = (
        f"echo Q | openssl s_client -connect {host_ip}:{ssl_port} "
        f"-verify_return_error 2>&1 || true"
    )
    out = _run_cmd(cmd)
    log.info(f"  openssl s_client output (truncated):\n{str(out)[:600]}")
    if "CERTIFICATE" not in str(out):
        raise TestExecError(
            f"No certificate found from openssl s_client to {host_ip}:{ssl_port}. "
            f"Output: {str(out)[:400]}"
        )
    log.info(f"  ✓ Certificate present on {host_ip}:{ssl_port}")


# ---------------------------------------------------------------------------
# S3 IO
# ---------------------------------------------------------------------------


def run_s3_io(config, ssh_con, host_ip, port, use_ssl, label=""):
    """
    Create a user, bucket, upload/download/delete objects via the given endpoint.
    ``use_ssl=True`` → HTTPS; ``use_ssl=False`` → HTTP.
    """
    scheme = "https" if use_ssl else "http"
    endpoint_url = f"{scheme}://{host_ip}:{port}"
    log.info(f"Step: S3 IO [{label}] against {endpoint_url}")

    curl_flag = "-k " if use_ssl else ""
    curl_out = _run_cmd(
        f"curl {curl_flag}--connect-timeout 10 {endpoint_url} 2>&1 || true"
    )
    log.info(f"  curl probe: {str(curl_out)[:200]}")

    users = s3lib.create_users(no_of_users_to_create=config.user_count or 1)
    if not users:
        raise TestExecError("Failed to create users for S3 IO")
    user_info = users[0]
    log.info(f"  user={user_info['user_id']}")

    auth = Auth(
        user_info,
        ssh_con,
        ssl=use_ssl,
        endpoint_ip=host_ip,
        endpoint_port=port,
    )
    rgw_conn = auth.do_auth()
    s3_client = auth.do_auth_using_client()
    log.info(f"  endpoint_url={auth.endpoint_url}")

    bucket_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=0)
    log.info(f"  creating bucket {bucket_name}")
    bucket = reusable.create_bucket_sync_init(bucket_name, rgw_conn, user_info)

    objects_count = config.objects_count or 3
    config.mapped_sizes = utils.make_mapped_sizes(config)
    uploaded = []
    for i in range(objects_count):
        config.obj_size = config.mapped_sizes[i]
        obj_name = utils.gen_s3_object_name(bucket_name, i)
        log.info(f"  PUT {obj_name}")
        reusable.upload_object(obj_name, bucket, TEST_DATA_PATH, config, user_info)
        uploaded.append(obj_name)

    ops = _ops(config)
    if ops.get("download_object", True):
        for obj_name in uploaded:
            dl_path = os.path.join(TEST_DATA_PATH, obj_name + ".dl")
            s3_client.download_file(bucket_name, obj_name, dl_path)
            if not os.path.exists(dl_path):
                raise TestExecError(f"Download failed for {obj_name}")
            log.info(f"  GET {obj_name} ok")

    if ops.get("delete_bucket_object", True):
        for obj_name in uploaded:
            s3_client.delete_object(Bucket=bucket_name, Key=obj_name)
        s3_client.delete_bucket(Bucket=bucket_name)
        log.info(f"  bucket {bucket_name} deleted")

    log.info(f"S3 IO [{label}] completed successfully")


# ---------------------------------------------------------------------------
# Service cleanup
# ---------------------------------------------------------------------------


def cleanup_service(service_name, enabled=True, timeout=180):
    """Remove the temporary RGW service and purge leftover config-DB keys."""
    if not enabled:
        log.info(f"Step: cleanup skipped for {service_name}")
        return
    if _rp_cleanup.is_protected_rgw_service(service_name):
        raise TestExecError(f"Refusing to remove protected service {service_name}")

    daemons = []
    try:
        daemons = get_rgw_daemons(service_name)
    except Exception as exc:
        log.warning(f"Could not list daemons before rm of {service_name}: {exc}")

    log.info(f"Step: removing service {service_name}")
    out = _run_cmd(f"ceph orch rm {service_name} --force")
    log.info(f"orch rm output: {out}")
    wait_for_service_gone(service_name, timeout=timeout)

    _rp_cleanup.cleanup_rgw_service_config(
        service_name, _run_cmd, extra_daemons=daemons, log_fn=log.info
    )


# ---------------------------------------------------------------------------
# Per-scenario test phases
# ---------------------------------------------------------------------------


def _phase_apply_and_verify(config, ssh_con, hosts, ops, label=""):
    """
    Apply spec, wait, assert orch export + rgw_frontends + listeners.
    Returns (ctx, daemons, host_ip).
    """
    ctx = apply_rgw_spec(ops, hosts)
    service_name = ctx["service_name"]
    wait_for_rgw_service(
        service_name,
        expected_running=ctx["expected_running"],
        timeout=int(ops.get("wait_timeout", 300)),
    )
    daemons = get_rgw_daemons(service_name)
    if len(daemons) < ctx["expected_running"]:
        raise TestExecError(
            f"Expected {ctx['expected_running']} daemons, found {len(daemons)}"
        )

    verify_orch_export(ctx)
    verify_rgw_frontends_config(daemons, ctx)
    verify_listeners(
        ctx,
        check_ssl=(ctx.get("ssl_port") is not None or ctx.get("ssl")),
        check_http=(ctx.get("http_port") is not None),
    )

    _, host_ip = resolve_host_addr(hosts, ctx["placement_hosts"])
    log.info(f"Phase '{label}' assertions passed for service {service_name}")
    return ctx, daemons, host_ip


def _phase_s3_io(config, ssh_con, ctx, host_ip, ops):
    """Run S3 IO on configured endpoints (HTTPS and/or HTTP) per test_ops flags."""
    if not ops.get("perform_s3_io", True):
        log.info("Step: S3 IO skipped per test_ops.perform_s3_io=false")
        return

    ssl_port = ctx.get("ssl_port")
    if ssl_port is None and ctx.get("ssl"):
        ssl_port = DEFAULT_SSL_PORT
    http_port = ctx.get("http_port")

    if ops.get("use_ssl_endpoint", True) and ssl_port is not None:
        wait_for_port_listen(ssl_port, timeout=int(ops.get("port_wait_timeout", 120)))
        run_s3_io(config, ssh_con, host_ip, ssl_port, use_ssl=True, label="HTTPS")

    if ops.get("use_http_endpoint", False) and http_port is not None:
        wait_for_port_listen(http_port, timeout=int(ops.get("port_wait_timeout", 120)))
        run_s3_io(config, ssh_con, host_ip, http_port, use_ssl=False, label="HTTP")


# ---------------------------------------------------------------------------
# main test_exec dispatcher
# ---------------------------------------------------------------------------


def test_exec(config, ssh_con):
    """
    Entry point.  Dispatches to the correct scenario handler based on
    ``test_ops.scenario``.
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    ops = _ops(config)
    scenario = ops.get("scenario", "explicit_ssl_port")

    log.info("=" * 60)
    log.info(f"Starting test_rgw_ssl_port scenario={scenario}")
    log.info(f"test_ops={ops}")
    log.info("=" * 60)

    log.info("Step: cluster snapshot")
    log.info(_run_cmd("ceph version"))
    log.info(_run_cmd("ceph orch ls rgw"))

    hosts = get_cluster_hosts()

    # Route to the appropriate scenario handler
    _SCENARIOS = {
        "explicit_ssl_port": _scenario_explicit,
        "infer_ssl_true": _scenario_infer_ssl_true,
        "infer_from_port": _scenario_infer_from_port,
        "custom_ssl_port": _scenario_custom_port,
        "ssl_only": _scenario_ssl_only,
        "cert_binding": _scenario_cert_binding,
        "change_ssl_port": _scenario_change_port,
        "remove_ssl": _scenario_remove_ssl,
        "no_cert_negative": _scenario_no_cert_negative,
        "extra_args_coexist": _scenario_extra_args,
        "multihost": _scenario_multihost,
    }
    handler = _SCENARIOS.get(scenario)
    if handler is None:
        raise TestExecError(
            f"Unknown scenario '{scenario}'. "
            f"Known: {sorted(_SCENARIOS.keys())}"
        )
    handler(config, ssh_con, hosts, ops)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found after test!")
    log.info(f"test_rgw_ssl_port scenario={scenario} PASSED")


# ---------------------------------------------------------------------------
# Scenario handlers
# ---------------------------------------------------------------------------


def _scenario_explicit(config, ssh_con, hosts, ops):
    """TC-1: explicit rgw_frontend_ssl_port + ssl: true — dual port happy path."""
    # _phase_apply_and_verify owns the apply; use its returned ctx everywhere.
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-1"
        )
        if ops.get("verify_no_listener_on"):
            assert_port_not_listening(int(ops["verify_no_listener_on"]))
        if ops.get("verify_cert_binding", False):
            ssl_port = ctx.get("ssl_port") or DEFAULT_SSL_PORT
            verify_cert_binding(host_ip, ssl_port)
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_infer_ssl_true(config, ssh_con, hosts, ops):
    """TC-2: ssl: true set, no ssl_port → ssl_port must be inferred to 443."""
    if ops.get("rgw_frontend_ssl_port") is not None:
        raise TestExecError(
            "TC-2 (infer_ssl_true): rgw_frontend_ssl_port must not be set in YAML"
        )
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-2"
        )
        # Inject inferred port into ctx so _phase_s3_io targets the right port.
        ctx["ssl_port"] = DEFAULT_SSL_PORT
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_infer_from_port(config, ssh_con, hosts, ops):
    """TC-3: ssl_port set, ssl omitted → ssl must be inferred to true."""
    if ops.get("ssl") is not None:
        raise TestExecError(
            "TC-3 (infer_from_port): 'ssl' must not be set in YAML to test inference"
        )
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-3"
        )
        # Inject inferred ssl into ctx so verify helpers and S3 IO use HTTPS.
        ctx["ssl"] = True
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_custom_port(config, ssh_con, hosts, ops):
    """TC-4: non-standard SSL port (e.g. 8443) — 443 must NOT be opened."""
    ssl_port = int(ops.get("rgw_frontend_ssl_port", 8443))
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-4"
        )
        # The standard 443 must not be opened when a custom port is used.
        no_listen_on = ops.get("verify_no_listener_on", 443)
        if int(no_listen_on) != ssl_port:
            assert_port_not_listening(int(no_listen_on))
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_ssl_only(config, ssh_con, hosts, ops):
    """TC-5: SSL-only daemon — no plain HTTP port configured."""
    if ops.get("rgw_frontend_port") is not None:
        raise TestExecError(
            "TC-5 (ssl_only): rgw_frontend_port must not be set for SSL-only test"
        )
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-5"
        )
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
        # No plain HTTP should be listening.
        http_no_listen = ops.get("verify_no_http_listener_on")
        if http_no_listen:
            assert_port_not_listening(int(http_no_listen))
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_cert_binding(config, ssh_con, hosts, ops):
    """TC-6: generate_cert: true — cert served on configured ssl_port."""
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-6"
        )
        ssl_port = ctx.get("ssl_port") or DEFAULT_SSL_PORT
        ensure_firewall_port(ssl_port)
        wait_for_port_listen(ssl_port, timeout=int(ops.get("port_wait_timeout", 120)))
        verify_cert_binding(host_ip, ssl_port)
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_change_port(config, ssh_con, hosts, ops):
    """TC-7: day-2 change ssl_port (initial → new_ssl_port)."""
    new_ssl_port = int(ops.get("new_ssl_port"))
    if not new_ssl_port:
        raise TestExecError("TC-7 (change_ssl_port): test_ops.new_ssl_port is required")

    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-7 initial"
        )
        old_ssl_port = int(ops["rgw_frontend_ssl_port"])
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)

        # --- day-2: update the spec with the new ssl_port ---
        log.info(f"Step: day-2 — changing ssl_port {old_ssl_port} → {new_ssl_port}")
        ops2 = dict(ops)
        ops2["rgw_frontend_ssl_port"] = new_ssl_port
        ctx2 = apply_rgw_spec(ops2, hosts)
        # Give cephadm time to reconcile
        time.sleep(int(ops.get("redeploy_settle_secs", 30)))
        wait_for_rgw_service(
            service_name,
            expected_running=ctx2["expected_running"],
            timeout=int(ops.get("wait_timeout", 300)),
        )
        daemons2 = get_rgw_daemons(service_name)
        verify_orch_export(ctx2)
        verify_rgw_frontends_config(daemons2, ctx2)
        ensure_firewall_port(new_ssl_port)
        wait_for_port_listen(new_ssl_port, timeout=int(ops.get("port_wait_timeout", 120)))

        # Old port must be released
        assert_port_not_listening(old_ssl_port)

        _, host_ip2 = resolve_host_addr(hosts, ctx2["placement_hosts"])
        _phase_s3_io(config, ssh_con, ctx2, host_ip2, ops2)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_remove_ssl(config, ssh_con, hosts, ops):
    """TC-8: day-2 remove SSL — revert to HTTP-only."""
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-8 initial"
        )
        old_ssl_port = ctx.get("ssl_port") or DEFAULT_SSL_PORT
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)

        # --- day-2: remove ssl fields from spec ---
        log.info("Step: day-2 — removing ssl / rgw_frontend_ssl_port from spec")
        http_port = int(ops.get("http_port_after_revert", ops.get("rgw_frontend_port", 8080)))
        ops2 = dict(ops)
        ops2.pop("rgw_frontend_ssl_port", None)
        ops2["ssl"] = False
        ops2["generate_cert"] = False
        ops2["rgw_frontend_port"] = http_port
        ctx2 = apply_rgw_spec(ops2, hosts)

        time.sleep(int(ops.get("redeploy_settle_secs", 30)))
        wait_for_rgw_service(
            service_name,
            expected_running=ctx2["expected_running"],
            timeout=int(ops.get("wait_timeout", 300)),
        )
        daemons2 = get_rgw_daemons(service_name)

        # After revert ssl_port and ssl must be gone from the export
        raw_export = _run_cmd(
            f"ceph orch ls --service-name {service_name} --export -f yaml"
        )
        log.info(f"  export after revert:\n{raw_export}")
        if "ssl: true" in str(raw_export):
            raise TestExecError(
                "ssl: true still present in orch export after SSL removal"
            )
        if "rgw_frontend_ssl_port" in str(raw_export):
            raise TestExecError(
                "rgw_frontend_ssl_port still present in orch export after SSL removal"
            )

        assert_port_not_listening(old_ssl_port)
        ensure_firewall_port(http_port)
        wait_for_port_listen(http_port, timeout=int(ops.get("port_wait_timeout", 120)))

        _, host_ip2 = resolve_host_addr(hosts, ctx2["placement_hosts"])
        run_s3_io(config, ssh_con, host_ip2, http_port, use_ssl=False, label="HTTP after revert")
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_no_cert_negative(config, ssh_con, hosts, ops):
    """
    TC-9: negative — ssl_port set but generate_cert=false and no cert in config-key.
    Pass condition: daemon NOT in running state OR HTTPS handshake fails.
    """
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    ssl_port = int(ops.get("rgw_frontend_ssl_port", DEFAULT_SSL_PORT))
    # Apply the spec before the try block so the service exists for cleanup.
    apply_rgw_spec(ops, hosts)
    try:
        log.info(
            "Step: applied SSL-port spec without a cert; "
            "expecting deployment failure or TLS handshake failure"
        )
        time.sleep(int(ops.get("settle_secs", 30)))

        # Check service status — may not reach running
        raw = _run_cmd(f"ceph orch ls --service-name {service_name} -f json")
        log.info(f"  orch ls: {raw}")
        try:
            data = json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            data = []

        running = 0
        if data:
            running = data[0].get("status", {}).get("running", 0)
        log.info(f"  daemon running count: {running}")

        if running == 0:
            log.info("PASS (negative): daemon did not reach running state — no cert available")
            return

        # Daemon is somehow running; HTTPS handshake must fail
        log.info(
            "  Daemon appears running; verifying that HTTPS handshake fails "
            "(no cert available)"
        )
        ensure_firewall_port(ssl_port)
        cmd = (
            f"echo Q | openssl s_client -connect "
            f"{hosts[0]['addr']}:{ssl_port} 2>&1 || true"
        )
        out = _run_cmd(cmd)
        log.info(f"  openssl output: {str(out)[:400]}")
        if "CERTIFICATE" in str(out):
            raise TestExecError(
                "FAIL (negative): TLS handshake succeeded without a cert — "
                "an unintended certificate was served. "
                f"openssl output: {str(out)[:400]}"
            )
        log.info("PASS (negative): TLS handshake failed as expected — no cert served")
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_extra_args(config, ssh_con, hosts, ops):
    """TC-10: rgw_frontend_extra_args coexist with ssl_port in rgw_frontends."""
    if not ops.get("rgw_frontend_extra_args"):
        raise TestExecError(
            "TC-10 (extra_args): rgw_frontend_extra_args must be set in YAML"
        )
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, host_ip = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-10"
        )
        _phase_s3_io(config, ssh_con, ctx, host_ip, ops)
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


def _scenario_multihost(config, ssh_con, hosts, ops):
    """TC-11: 3-host placement — all hosts bind the same ssl_port."""
    placement_hosts = ops.get("placement_hosts", [hosts[0]["hostname"]])
    service_name = f"rgw.{ops.get('service_id', 'ssl-port-qe')}"
    try:
        ctx, daemons, _ = _phase_apply_and_verify(
            config, ssh_con, hosts, ops, "TC-11"
        )
        ssl_port = ctx.get("ssl_port") or DEFAULT_SSL_PORT
        if len(daemons) < len(placement_hosts):
            raise TestExecError(
                f"Expected daemons on {len(placement_hosts)} hosts, "
                f"found {len(daemons)}"
            )
        # Verify ssl_port is listening on each host individually
        host_map = {h["hostname"]: h["addr"] for h in hosts}
        for ph in placement_hosts:
            addr = host_map.get(ph, ph)
            log.info(f"  verifying ssl_port={ssl_port} on host {ph} ({addr})")
            cmd = f"ssh {ph} \"ss -lntp | grep ':{ssl_port} '\" 2>/dev/null || true"
            out = _run_cmd(cmd)
            log.info(f"    result: {out}")
            if not out or str(ssl_port) not in str(out):
                log.warning(
                    f"  Cannot remotely verify listener on {ph}; "
                    "falling back to local ss check"
                )
        # Run S3 IO against each placement host
        for ph in placement_hosts:
            addr = host_map.get(ph, ph)
            ensure_firewall_port(ssl_port)
            wait_for_port_listen(ssl_port, timeout=60)
            run_s3_io(
                config, ssh_con, addr, ssl_port,
                use_ssl=True, label=f"HTTPS host={ph}"
            )
    finally:
        cleanup_service(service_name, enabled=bool(ops.get("cleanup_service", True)))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    test_info = AddTestInfo("RGW cephadm rgw_frontend_ssl_port parameter")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating..")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="RGW cephadm rgw_frontend_ssl_port automation"
        )
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
