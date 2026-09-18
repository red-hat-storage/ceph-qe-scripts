"""
Usage: test_lua_postauth_cache.py -c <input_yaml>

<input_yaml>
    configs/test_aws_lua_postauth_cache.yaml

postAuth is not a radosgw-admin script context. Valid upload contexts are
prerequest, postrequest, background, getdata, and putdata. This test uploads a
large padded policy script to prerequest (the closest CLI equivalent), then
compares RGW debug logs:

  - preRequest: bytecode cache miss on the first request, cache hit after
    LuaBackground compiles (correct path).
  - postRequest: negative-entry cache when no postrequest script is stored.
  - postAuth (bug): read_script() is silent — no cache get / bytecode lines.
    After the fix, read_script_or_bytecode() emits
    "cache get: name=...script.postauth... hit" on subsequent requests,
    matching postrequest.
"""

import argparse
import json
import logging
import os
import re
import sys
import time
import traceback
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    endpoint = aws_reusable.get_endpoint(
        ssh_con, ssl=config.ssl, haproxy=config.haproxy
    )
    log.info(f"RGW endpoint: {endpoint}")

    lua_background_wait = int(config.test_ops.get("lua_background_wait", 10))
    measure_latency = config.test_ops.get("measure_latency", True)
    latency_iterations = int(config.test_ops.get("latency_iterations", 20))
    delete_bucket = config.test_ops.get("delete_bucket", True)

    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    user = user_info[0]
    cli_aws = AWS(ssl=config.ssl)
    bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=0)
    script_set = False
    bucket_created = False
    debug_set = False
    log_grep = (
        r"lua|bytecode|SCRIPT_URI|script\.prerequest|"
        r"script\.postauth|script\.postrequest|cache get"
    )
    all_lua_lines = []
    traces = {}

    try:
        aws_auth.do_auth_aws(user)

        # Lua 5.3/5.4 caps local variables per chunk at 200.
        # 199 local functions + local ok = 200 exactly.
        lua_lines = [
            "-- postAuth policy enforcement script",
            "-- padded to simulate a large real-world script",
            "",
        ]
        for i in range(199):
            lua_lines.append(f"local function check_rule_{i}(req)")
            lua_lines.append("  if req == nil then return false end")
            lua_lines.append("  return true")
            lua_lines.append("end")
            lua_lines.append("")
        lua_lines.append("local ok = true")
        for i in range(199):
            lua_lines.append(f"ok = ok and check_rule_{i}(Request)")
        lua_lines.extend(
            [
                "",
                "if not ok then",
                "  Request.Response.HTTPStatusCode = 403",
                "  return RGW_ABORT_REQUEST",
                "end",
                "",
            ]
        )
        lua_script = "\n".join(lua_lines)
        line_count = lua_script.count("\n") + 1
        log.info(
            f"Generated padded Lua script: {line_count} lines, {len(lua_script)} bytes"
        )
        if line_count < 200:
            raise TestExecError(
                f"Generated Lua script is too small ({line_count} lines)"
            )

        log.info("Enabling log_to_file and debug_rgw=20")
        utils.exec_shell_cmd("ceph config set global log_to_file true")
        out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
        rgw_daemons = json.loads(out_ps)
        services = set()
        for daemon in rgw_daemons:
            service_name = daemon.get("service_name")
            if service_name:
                services.add(service_name)
            daemon_name = daemon.get("daemon_name")
            if daemon_name:
                utils.exec_shell_cmd(
                    f"ceph config set client.{daemon_name} debug_rgw 20"
                )
        for service_name in services:
            utils.exec_shell_cmd(f"ceph config set client.{service_name} debug_rgw 20")
        debug_set = True
        time.sleep(3)

        log.info("Uploading script to prerequest")
        aws_reusable.set_lua_script(context="prerequest", script_content=lua_script)
        script_set = True
        retrieved = aws_reusable.get_lua_script(context="prerequest")
        log.info(f"Stored prerequest script ({len(retrieved.splitlines())} lines)")
        if "check_rule_0" not in retrieved or "local ok" not in retrieved:
            raise TestExecError("prerequest script was not stored correctly")

        fsid = utils.get_cluster_fsid()
        log_dir = f"/var/log/ceph/{fsid}"

        for phase in ("cold", "warm", "followup"):
            if phase == "cold":
                log.info(f"First request (cold): create-bucket {bucket_name}")
                phase_start = time.time()
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                bucket_created = True
            elif phase == "warm":
                log.info(f"Waiting {lua_background_wait}s for LuaBackground")
                time.sleep(lua_background_wait)
                log.info("Second request (warm): list-objects")
                phase_start = time.time()
                aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
            else:
                log.info("Follow-up request: list-objects (postAuth cache hit path)")
                phase_start = time.time()
                aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
            time.sleep(2)

            phase_lines = []
            search_all = config.haproxy
            if not search_all:
                if aws_reusable.check_log_directory_exists(log_dir, ssh_con):
                    rgw_log_files = aws_reusable.get_rgw_log_files(log_dir, ssh_con)
                    for log_file in rgw_log_files:
                        cmd = (
                            f"sudo grep -iE '{log_grep}' {log_file} "
                            "2>/dev/null || true"
                        )
                        if ssh_con:
                            _stdin, stdout, _stderr = ssh_con.exec_command(cmd)
                            out = stdout.read().decode()
                        else:
                            out = utils.exec_shell_cmd(cmd)
                            if out is False or out is None:
                                out = ""
                        if out and out.strip():
                            for raw in out.strip().split("\n"):
                                if raw.strip():
                                    phase_lines.append(raw.strip())
                if not phase_lines:
                    log.info("No lua/cache lines on local node; checking all RGW hosts")
                    search_all = True
            if search_all:
                phase_lines = []
                for host in aws_reusable.get_all_rgw_hosts():
                    try:
                        node_ssh = utils.connect_remote(host)
                        if not aws_reusable.check_log_directory_exists(
                            log_dir, node_ssh
                        ):
                            continue
                        rgw_log_files = aws_reusable.get_rgw_log_files(
                            log_dir, node_ssh, host
                        )
                        for log_file in rgw_log_files:
                            cmd = (
                                f"sudo grep -iE '{log_grep}' {log_file} "
                                "2>/dev/null || true"
                            )
                            _stdin, stdout, _stderr = node_ssh.exec_command(cmd)
                            out = stdout.read().decode()
                            if out and out.strip():
                                for raw in out.strip().split("\n"):
                                    if raw.strip():
                                        phase_lines.append(f"[{host}] {raw.strip()}")
                    except Exception as e:
                        log.warning(f"Failed to grep RGW logs on {host}: {e}")

            cutoff = phase_start - 1
            recent = []
            for line in phase_lines:
                raw = re.sub(r"^\[.*?\]\s+", "", line)
                ts_match = re.match(r"^(\S+)\s", raw)
                keep = True
                if ts_match:
                    ts = ts_match.group(1)
                    if ts.endswith("+0000"):
                        ts = ts[:-5] + "+00:00"
                    try:
                        keep = datetime.fromisoformat(ts).timestamp() >= cutoff
                    except ValueError:
                        keep = True
                if keep:
                    recent.append(line)
            traces[phase] = recent
            all_lua_lines.extend(recent)
            log.info(f"{phase} lua/cache trace: {len(recent)} matching line(s)")

        for phase in ("cold", "warm"):
            prerequest_ran = [
                ln
                for ln in traces[phase]
                if re.search(
                    r"Lua script executed|script\.prerequest", ln, re.IGNORECASE
                )
            ]
            if not prerequest_ran:
                raise TestExecError(
                    f"preRequest did not run on the {phase} request: no Lua script executed or script.prerequest lines in RGW logs"
                )
            log.info(f"preRequest ran on the {phase} request")

        postrequest_neg = [
            ln
            for ln in traces["cold"]
            if re.search(r"script\.postrequest", ln, re.IGNORECASE)
        ]
        if postrequest_neg:
            log.info(f"postRequest negative-cache lines: {len(postrequest_neg)}")

        prerequest_hit = [
            ln
            for ln in traces["warm"]
            if re.search(r"cache get:.*script\.prerequest.*hit", ln, re.IGNORECASE)
        ]
        if prerequest_hit:
            log.info(f"preRequest bytecode cache hit: {len(prerequest_hit)}")
        else:
            log.warning("No cache get hit for script.prerequest on the warm request")

        postauth_lines = [
            ln
            for ln in all_lua_lines
            if re.search(r"script\.postauth", ln, re.IGNORECASE)
        ]
        prereq_n = len(
            [
                ln
                for ln in all_lua_lines
                if re.search(r"script\.prerequest", ln, re.IGNORECASE)
            ]
        )
        postreq_n = len(
            [
                ln
                for ln in all_lua_lines
                if re.search(r"script\.postrequest", ln, re.IGNORECASE)
            ]
        )
        if not postauth_lines:
            raise TestExecError(
                f"postAuth calls read_script() so RGW is silent between granted access/normalizing buckets and init permissions (script.postauth=0, script.prerequest={prereq_n}, script.postrequest={postreq_n}). Expected after fix: cache get name=...script.postauth. hit on later requests (~6ms, no RADOS read), same as preRequest."
            )
        log.info(f"postAuth cache-path lines: {len(postauth_lines)}")
        postauth_hit = [
            ln
            for ln in all_lua_lines
            if re.search(r"cache get:.*script\.postauth.*hit", ln, re.IGNORECASE)
        ]
        if not postauth_hit:
            raise TestExecError(
                f"script.postauth logged ({len(postauth_lines)} line(s)) but no cache get script.postauth hit. Expected after LuaBackground: bytecode cache hit, ~6ms, no RADOS read (buggy postAuth stays cold ~17ms on every request)."
            )
        log.info("postAuth cache get hit observed")

        if measure_latency and latency_iterations > 0:
            log.info(
                f"Measuring {latency_iterations} list-objects with prerequest loaded"
            )
            start = time.perf_counter()
            for _ in range(latency_iterations):
                aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
            with_script = time.perf_counter() - start
            aws_reusable.remove_lua_script(context="prerequest")
            script_set = False
            log.info("Removed prerequest script for baseline")
            time.sleep(2)
            start = time.perf_counter()
            for _ in range(latency_iterations):
                aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
            baseline = time.perf_counter() - start
            log.info(
                f"Latency {latency_iterations}x list-objects: with prerequest {with_script:.3f}s, baseline {baseline:.3f}s"
            )
    finally:
        if script_set:
            try:
                aws_reusable.remove_lua_script(context="prerequest")
                log.info("Lua prerequest script removed")
            except Exception as e:
                log.warning(f"Failed to remove prerequest script: {e}")
        if bucket_created and delete_bucket:
            try:
                aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)
                log.info(f"Deleted bucket {bucket_name}")
            except Exception as e:
                log.warning(f"Failed to delete bucket {bucket_name}: {e}")
        if debug_set:
            try:
                log.info("Resetting debug_rgw to default")
                out_ps = utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
                rgw_daemons = json.loads(out_ps)
                services = set()
                for daemon in rgw_daemons:
                    service_name = daemon.get("service_name")
                    if service_name:
                        services.add(service_name)
                    daemon_name = daemon.get("daemon_name")
                    if daemon_name:
                        utils.exec_shell_cmd(
                            f"ceph config rm client.{daemon_name} debug_rgw"
                        )
                for service_name in services:
                    utils.exec_shell_cmd(
                        f"ceph config rm client.{service_name} debug_rgw"
                    )
                log.info("debug_rgw reset for all RGW daemons")
            except Exception as e:
                log.warning(f"Failed to reset debug_rgw: {e}")
        if config.user_remove is True:
            for u in user_info:
                try:
                    s3_reusable.remove_user(u)
                except Exception as e:
                    log.warning(f"Failed to remove user {u.get('user_id')}: {e}")

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Lua postAuth bytecode cache test with awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Lua postAuth bytecode cache test with awscli"
        )
        parser.add_argument(
            "-c", dest="config", help="Lua postAuth bytecode cache test with awscli"
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
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)
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
