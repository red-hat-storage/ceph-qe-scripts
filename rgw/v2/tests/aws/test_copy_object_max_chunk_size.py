"""
Usage: test_copy_object_max_chunk_size.py -c <input_yaml>

<input_yaml>
    rgw/v2/tests/aws/configs/test_copy_object_max_chunk_size.yaml

Tracker: https://tracker.ceph.com/issues/81314

Operation:
    CopyObject of a 5000000-byte single-part object must not change the payload.

    1. Leave both rgw_max_chunk_size and rgw_get_obj_max_req_size at the
       cluster default, 4194304, without changing either setting.
       Upload, copy, and compare.
    2. Set rgw_max_chunk_size to 16777216. Leave rgw_get_obj_max_req_size
       at 4194304, and restart RGW. Upload, copy, and compare.
    3. Set both rgw_max_chunk_size and rgw_get_obj_max_req_size to 16777216
       and restart RGW. Upload, copy, and compare again.
    4. Export AWS_REQUEST_CHECKSUM_CALCULATION=when_required for every run.
    5. Set any option this test changed back to 4194304 and restart RGW.

    Pass:
        Each scenario prints PASS when md5(src.bin), the copy-object ETag,
        md5(dst.bin), and the head-object ETag are the same, and cmp reports
        no byte difference. The final result is PASS only when every scenario
        passes.
"""

import argparse
import json
import logging
import os
import random
import re
import shlex
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None
CHECKSUM_ENV = "AWS_REQUEST_CHECKSUM_CALCULATION"
CHUNK_CONFIG_KEY = "rgw_max_chunk_size"
REQ_SIZE_KEY = "rgw_get_obj_max_req_size"
DEFAULT_CHUNK_SIZE = 4194304
DEFAULT_REQ_SIZE = 4194304


def _run(cmd, step):
    """Run a shell command. Raise if it fails."""
    log.info(step)
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"{step} failed")
    return out


def _config_get(who, key):
    """Return one ceph config value with surrounding whitespace removed."""
    raw = utils.exec_shell_cmd(f"ceph config get {who} {key}")
    if raw is False or not str(raw).strip():
        raise TestExecError(f"ceph config get {who} {key} failed")
    return str(raw).strip()


def _rgw_daemon_names():
    """Return RGW daemon names from ceph orch."""
    raw = utils.exec_shell_cmd("ceph orch ps --daemon_type=rgw --format json")
    if raw is False or not str(raw).strip():
        raise TestExecError("failed to list RGW daemons")
    names = [
        daemon["daemon_name"] for daemon in json.loads(raw) if daemon.get("daemon_name")
    ]
    if not names:
        raise TestExecError("no RGW daemons found")
    log.info(f"RGW daemons: {names}")
    return names


def _set_rgw_option(key, value, sections):
    """
    Set key on client.rgw and on any daemon that still has another value.
    Record each section this call changes.
    """
    _apply_rgw_option("client.rgw", key, value, sections)
    for daemon in _rgw_daemon_names():
        who = f"client.{daemon}"
        effective = _config_get(who, key)
        if effective != str(value):
            log.info(f"{who} {key} is {effective}; setting {value}")
            _apply_rgw_option(who, key, value, sections)
            effective = _config_get(who, key)
            if effective != str(value):
                raise TestExecError(f"{who} {key} is {effective} after config set")
    log.info(f"{key} set to {value} on {sections}")


def _apply_rgw_option(section, key, value, sections):
    """Set one RGW option when it differs, and record the section."""
    current = _config_get(section, key)
    if current == str(value):
        log.info(f"{section} {key} is already {value}")
        return
    out = utils.exec_shell_cmd(f"ceph config set {section} {key} {value}")
    if out is False:
        raise TestExecError(f"failed to set {key}={value} on {section}")
    if section not in sections:
        sections.append(section)


def _reset_rgw_option(key, sections, default_size):
    """
    Set key back to default_size on sections this test changed, and on any
    daemon that still shows another value. Does not restart RGW or raise.
    """
    ok = True
    for section in sections:
        log.info(f"resetting {section} {key} to {default_size}")
        if (
            utils.exec_shell_cmd(f"ceph config set {section} {key} {int(default_size)}")
            is False
        ):
            log.error(f"failed to reset {key} on {section}")
            ok = False
    try:
        daemons = _rgw_daemon_names()
    except Exception:
        log.error(f"failed to list RGW daemons while resetting {key}")
        log.error(traceback.format_exc())
        return False
    for daemon in daemons:
        who = f"client.{daemon}"
        try:
            effective = int(_config_get(who, key))
        except Exception:
            log.error(f"failed to read {key} for {who}")
            log.error(traceback.format_exc())
            ok = False
            continue
        if effective == int(default_size):
            log.info(f"{who} {key} is {default_size}")
            continue
        log.info(f"{who} {key} is {effective}; setting {default_size}")
        if (
            utils.exec_shell_cmd(f"ceph config set {who} {key} {int(default_size)}")
            is False
        ):
            log.error(f"failed to reset {key} on {who}")
            ok = False
    return ok


def _restart_rgw(ssh_con):
    """Restart every RGW service and wait until the daemons are running."""
    log.info("Restarting RGW services")
    utils.restart_rgw(restart_all=True, ssh_con=ssh_con)
    if not utils.rgw_daemons_status():
        raise TestExecError("RGW daemons are not running after restart")


def _assert_runtime_config(chunk_size, req_size, object_size, modify_config=True):
    """Confirm the running RGW options match this scenario."""
    for daemon in _rgw_daemon_names():
        who = f"client.{daemon}"
        chunk = int(_config_get(who, CHUNK_CONFIG_KEY))
        actual_req = int(_config_get(who, REQ_SIZE_KEY))
        log.info(
            f"{who}: rgw_max_chunk_size={chunk} "
            f"rgw_get_obj_max_req_size={actual_req}"
        )
        if chunk != int(chunk_size):
            raise TestExecError(
                f"{who} rgw_max_chunk_size is {chunk}, expected {chunk_size}"
            )
        if actual_req != int(req_size):
            raise TestExecError(
                f"{who} rgw_get_obj_max_req_size is {actual_req}, expected {req_size}"
            )
        if not modify_config:
            continue
        if object_size > chunk:
            raise TestExecError(
                f"{who}: object size {object_size} must be less than or equal "
                f"to rgw_max_chunk_size ({chunk}) so the object stays head-only"
            )
        if actual_req < chunk and not actual_req < object_size <= chunk:
            raise TestExecError(
                f"{who}: object size {object_size} must be greater than "
                f"rgw_get_obj_max_req_size ({actual_req}) and less than or "
                f"equal to rgw_max_chunk_size ({chunk})"
            )


def _write_single_part_aws_config(object_size):
    """
    Point AWS CLI at a config that keeps this upload below the multipart
    threshold. 5000000 bytes is already under the 8MiB default; this holds
    the threshold above the object even if the user config is lower.
    """
    threshold_mb = max(64, (int(object_size) // (1024 * 1024)) + 1)
    path = os.path.join(TEST_DATA_PATH, "aws-singlepart.cfg")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "[default]\n"
            "region = us-east-1\n"
            "s3 =\n"
            "    addressing_style = path\n"
            f"    multipart_threshold = {threshold_mb}MB\n"
            f"    multipart_chunksize = {threshold_mb}MB\n"
        )
    log.info(f"AWS multipart threshold set to {threshold_mb}MB via {path}")
    return path


def _aws(endpoint, https, aws_config, args):
    """Build an aws CLI command with the checksum calculation from the scenario."""
    verify = "--no-verify-ssl " if https else ""
    return (
        f"{CHECKSUM_ENV}=when_required "
        f"AWS_CONFIG_FILE={shlex.quote(aws_config)} "
        f"/usr/local/bin/aws {verify}--endpoint-url {shlex.quote(endpoint)} {args}"
    )


def _normalize_etag(value):
    """Strip the quotes S3 includes in an ETag and return lowercase hex."""
    text = str(value).strip().replace('\\"', '"')
    while len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text.lower()


def _etag_from_query(raw):
    """Return the ETag from `head-object --query ETag --output text`."""
    lines = [line.strip() for line in str(raw).splitlines() if line.strip()]
    if not lines:
        raise TestExecError(f"head-object returned no ETag: {raw!r}")
    return _normalize_etag(lines[-1])


def _md5_from_md5sum(raw):
    """Return the digest from md5sum output."""
    for line in reversed(str(raw).splitlines()):
        match = re.search(r"\b([0-9a-fA-F]{32})\b", line)
        if match:
            return match.group(1).lower()
    raise TestExecError(f"md5sum returned no digest: {raw!r}")


def _etag_from_copy_response(raw):
    """Return the ETag from a copy-object JSON body."""
    text = str(raw).strip()
    start = text.find("{")
    if start < 0:
        raise TestExecError(f"copy-object response is not JSON: {text}")
    data = json.loads(text[start:])
    result = data.get("CopyObjectResult", data)
    etag = result.get("ETag") if isinstance(result, dict) else None
    if not etag:
        raise TestExecError(f"copy-object response has no ETag: {text}")
    return _normalize_etag(etag)


def _parse_cmp(raw):
    """Return (exit_code, message) from `cmp ...; echo CMP_EXIT:$?`."""
    lines = [line for line in str(raw).splitlines() if line.strip()]
    if not lines or not lines[-1].startswith("CMP_EXIT:"):
        raise TestExecError(f"cmp result was not captured: {raw!r}")
    detail = "\n".join(lines[:-1]).strip()
    return int(lines[-1].split(":", 1)[1]), detail


def _copy_once(endpoint, https, aws_config, bucket_name, src_key, dst_key, object_size):
    """Run the upload, copy, download, and checksum comparison once."""
    src_path = os.path.join(TEST_DATA_PATH, src_key)
    dst_path = os.path.join(TEST_DATA_PATH, dst_key)
    if os.path.exists(dst_path):
        os.unlink(dst_path)

    md5_raw = _run(
        f"head -c {int(object_size)} /dev/urandom > {shlex.quote(src_path)} "
        f"&& md5sum {shlex.quote(src_path)}",
        "create src.bin and record its md5",
    )
    src_md5 = _md5_from_md5sum(md5_raw)
    if os.path.getsize(src_path) != int(object_size):
        raise TestExecError(
            f"src.bin size is {os.path.getsize(src_path)}, expected {object_size}"
        )
    log.info(f"src.bin md5: {src_md5}")

    _run(
        _aws(
            endpoint,
            https,
            aws_config,
            f"s3 mb {shlex.quote('s3://' + bucket_name)}",
        ),
        f"create bucket s3://{bucket_name}",
    )
    _run(
        _aws(
            endpoint,
            https,
            aws_config,
            f"s3 cp {shlex.quote(src_path)} "
            f"{shlex.quote('s3://' + bucket_name + '/' + src_key)}",
        ),
        "single-part PUT src.bin",
    )

    src_etag = _etag_from_query(
        _run(
            _aws(
                endpoint,
                https,
                aws_config,
                "s3api head-object "
                f"--bucket {shlex.quote(bucket_name)} --key {shlex.quote(src_key)} "
                "--query ETag --output text",
            ),
            "head-object src.bin",
        )
    )
    log.info(f"src.bin ETag: {src_etag}")
    if "-" in src_etag:
        raise TestExecError(
            f"src.bin ETag {src_etag} is a multipart ETag; expected a single-part PUT"
        )

    copy_raw = _run(
        _aws(
            endpoint,
            https,
            aws_config,
            "s3api copy-object "
            f"--bucket {shlex.quote(bucket_name)} --key {shlex.quote(dst_key)} "
            f"--copy-source {shlex.quote(bucket_name + '/' + src_key)} "
            "--output json",
        ),
        "copy-object src.bin to dst.bin",
    )
    copy_etag = _etag_from_copy_response(copy_raw)
    log.info(f"copy-object ETag: {copy_etag}")

    dst_md5 = _md5_from_md5sum(
        _run(
            _aws(
                endpoint,
                https,
                aws_config,
                f"s3 cp {shlex.quote('s3://' + bucket_name + '/' + dst_key)} "
                f"{shlex.quote(dst_path)}",
            )
            + f" && md5sum {shlex.quote(dst_path)}",
            "download dst.bin and record its md5",
        )
    )
    log.info(f"dst.bin md5: {dst_md5}")

    head_etag = _etag_from_query(
        _run(
            _aws(
                endpoint,
                https,
                aws_config,
                "s3api head-object "
                f"--bucket {shlex.quote(bucket_name)} --key {shlex.quote(dst_key)} "
                "--query ETag --output text",
            ),
            "head-object dst.bin ETag",
        )
    )
    log.info(f"head-object ETag: {head_etag}")

    cmp_exit, cmp_detail = _parse_cmp(
        _run(
            f"cmp {shlex.quote(src_path)} {shlex.quote(dst_path)} 2>&1; echo CMP_EXIT:$?",
            "cmp src.bin dst.bin",
        )
    )
    log.info(f"cmp exit {cmp_exit}: {cmp_detail or 'no byte difference'}")

    digests = {
        "src_md5": src_md5,
        "copy_etag": copy_etag,
        "dst_md5": dst_md5,
        "head_etag": head_etag,
    }
    failures = []
    if len(set(digests.values())) != 1:
        failures.append(
            "src md5, copy-object ETag, downloaded md5, and head-object ETag "
            f"must match: {digests}"
        )
        if src_md5 == copy_etag == head_etag and dst_md5 != src_md5:
            failures.append(
                "ETag still matches the source md5 while the downloaded bytes "
                "do not. This is the silent CopyObject corruption from "
                "tracker 81314"
            )
    if cmp_exit != 0:
        failures.append(
            "cmp src.bin dst.bin found a byte difference"
            + (f": {cmp_detail}" if cmp_detail else "")
        )
    if failures:
        raise TestExecError("; ".join(failures))
    log.info(
        "src md5, copy-object ETag, dst md5, and head-object ETag match, "
        "and cmp found no byte difference"
    )


def _wait_for_endpoint(endpoint, https):
    """Wait until RGW accepts connections after the restart."""
    insecure = " -k" if https else ""
    for attempt in range(1, 7):
        out = utils.exec_shell_cmd(
            f"curl{insecure} --connect-timeout 10 --max-time 20 -sS -o /dev/null "
            f"-w '%{{http_code}}' {shlex.quote(endpoint)}"
        )
        if out is not False and str(out).strip() not in ("", "000"):
            log.info(f"endpoint {endpoint} responded on attempt {attempt}")
            return
        log.warning(f"endpoint {endpoint} not reachable on attempt {attempt}")
        time.sleep(10)
    raise TestExecError(f"endpoint {endpoint} is not reachable after RGW restart")


def _scenario_label(index, chunk_size, req_size, modify_config=True):
    """Return the result label for one config scenario."""
    unchanged = "" if modify_config else ", config unchanged"
    return (
        f"scenario {index}: rgw_max_chunk_size={chunk_size} "
        f"rgw_get_obj_max_req_size={req_size}{unchanged}"
    )


def _log_scenario_results(results):
    """
    Print PASS or FAIL for every scenario.
    The final result is PASS only when every scenario passed.
    """
    log.info("========== SCENARIO RESULTS ==========")
    for label, status in results:
        log.info(f"RESULT {label}: {status}")
    final = (
        "PASS" if results and all(status == "PASS" for _, status in results) else "FAIL"
    )
    log.info(f"FINAL RESULT: {final}")
    log.info("======================================")
    return final


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    object_size = int(config.test_ops.get("object_size", 5000000))
    src_key = config.test_ops.get("src_key", "src.bin")
    dst_key = config.test_ops.get("dst_key", "dst.bin")
    scenarios = config.test_ops.get("scenarios") or [
        {
            "rgw_max_chunk_size": DEFAULT_CHUNK_SIZE,
            "rgw_get_obj_max_req_size": DEFAULT_REQ_SIZE,
            "modify_config": False,
        },
        {
            "rgw_max_chunk_size": 16777216,
            "rgw_get_obj_max_req_size": DEFAULT_REQ_SIZE,
        },
        {
            "rgw_max_chunk_size": 16777216,
            "rgw_get_obj_max_req_size": 16777216,
        },
    ]
    if object_size <= 0:
        raise TestExecError("object_size must be positive")

    changed = {CHUNK_CONFIG_KEY: [], REQ_SIZE_KEY: []}
    users = []
    results = []
    restore_ok = True
    previous_checksum = os.environ.get(CHECKSUM_ENV)
    try:
        os.environ[CHECKSUM_ENV] = "when_required"
        log.info(f"exported {CHECKSUM_ENV}=when_required")
        aws_config = _write_single_part_aws_config(object_size)
        users = resource_op.create_users(no_of_users_to_create=config.user_count)

        for index, scenario in enumerate(scenarios, start=1):
            label = f"scenario {index}"
            try:
                chunk_size = int(scenario["rgw_max_chunk_size"])
                req_size = int(scenario["rgw_get_obj_max_req_size"])
                modify_config = scenario.get("modify_config", True)
                label = _scenario_label(index, chunk_size, req_size, modify_config)
                log.info(f"starting {label}")
                if chunk_size <= 0 or req_size <= 0:
                    raise TestExecError(
                        "rgw_max_chunk_size and rgw_get_obj_max_req_size "
                        "must be positive"
                    )
                if modify_config:
                    _set_rgw_option(
                        CHUNK_CONFIG_KEY, chunk_size, changed[CHUNK_CONFIG_KEY]
                    )
                    _set_rgw_option(REQ_SIZE_KEY, req_size, changed[REQ_SIZE_KEY])
                    _restart_rgw(ssh_con)
                else:
                    log.info(
                        "not modifying rgw_max_chunk_size or "
                        "rgw_get_obj_max_req_size"
                    )
                _assert_runtime_config(chunk_size, req_size, object_size, modify_config)

                for user in users:
                    user_name = user["user_id"]
                    log.info(user_name)
                    aws_auth.do_auth_aws(user, ssh_con)
                    endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
                    https = endpoint.startswith("https://")
                    log.info(f"RGW endpoint: {endpoint}")
                    _wait_for_endpoint(endpoint, https)
                    for bc in range(config.bucket_count):
                        bucket_name = config.test_ops.get("bucket_name")
                        if (
                            not bucket_name
                            or len(scenarios) != 1
                            or config.bucket_count != 1
                        ):
                            bucket_name = (
                                f"copytest-{index}-{bc}-"
                                f"{random.randrange(100000, 999999)}"
                            )
                        _copy_once(
                            endpoint,
                            https,
                            aws_config,
                            bucket_name,
                            src_key,
                            dst_key,
                            object_size,
                        )
                crash_info = s3_reusable.check_for_crash()
                if crash_info:
                    raise TestExecError("ceph daemon crash found!")
            except Exception as exc:
                log.error(f"{label} failed: {exc}")
                log.error(traceback.format_exc())
                results.append((label, "FAIL"))
                log.info(f"RESULT {label}: FAIL")
                continue
            results.append((label, "PASS"))
            log.info(f"RESULT {label}: PASS")
    finally:
        if previous_checksum is None:
            os.environ.pop(CHECKSUM_ENV, None)
        else:
            os.environ[CHECKSUM_ENV] = previous_checksum
        if config.user_remove:
            for user in users:
                try:
                    s3_reusable.remove_user(user)
                except Exception:
                    log.error(f"failed to remove user {user.get('user_id')}")
                    log.error(traceback.format_exc())
        chunk_ok = _reset_rgw_option(
            CHUNK_CONFIG_KEY, changed[CHUNK_CONFIG_KEY], DEFAULT_CHUNK_SIZE
        )
        req_ok = _reset_rgw_option(
            REQ_SIZE_KEY, changed[REQ_SIZE_KEY], DEFAULT_REQ_SIZE
        )
        restart_ok = True
        try:
            _restart_rgw(ssh_con)
        except Exception:
            log.error("RGW restart after resetting RGW config failed")
            log.error(traceback.format_exc())
            restart_ok = False
        restore_ok = chunk_ok and req_ok and restart_ok
    final = _log_scenario_results(results)
    if final != "PASS":
        failed = [label for label, status in results if status != "PASS"]
        raise TestExecError(
            "FINAL RESULT: FAIL. Failed scenarios: "
            + (", ".join(failed) if failed else "no scenario completed")
        )
    if not restore_ok:
        raise TestExecError(
            "scenarios passed, but failed to reset rgw_max_chunk_size and "
            f"rgw_get_obj_max_req_size to {DEFAULT_CHUNK_SIZE} and restart RGW"
        )


if __name__ == "__main__":

    test_info = AddTestInfo("CopyObject integrity with rgw_max_chunk_size 16MiB")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="CopyObject integrity when rgw_max_chunk_size is 16MiB"
        )
        parser.add_argument(
            "-c",
            dest="config",
            help="CopyObject integrity with rgw_max_chunk_size 16MiB",
        )
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
        config = resource_op.Config(yaml_file)
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
