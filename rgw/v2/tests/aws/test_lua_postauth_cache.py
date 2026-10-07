"""
Usage: test_lua_postauth_cache.py -c <input_yaml>

<input_yaml>
    configs/test_aws_lua_postauth_cache.yaml
    configs/test_aws_lua_prerequest_stale_bytecode_cache.yaml
    configs/test_aws_lua_prerequest_cache_invalidation.yaml

Operation:
    Lua bytecode cache scenarios via test_ops:
    - lua_postauth_cache: postAuth vs prerequest bytecode cache behaviour
    - prerequest_stale_bytecode_cache: script A warm-up, rm+put script B, verify
      B runs (tracker #80532 / PR #71873)
    - prerequest_cache_invalidation: upload blocking script, put_object must be
      blocked immediately (tracker #80576 / PR #71857)
"""

import argparse
import logging
import os
import re
import sys
import time
import traceback

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

MARKER_A = "LUA_SCRIPT_A_COPYFROM"
MARKER_B = "LUA_SCRIPT_B_INTERRUPT"
BLOCK_MARKER = "LUA_BLOCK_PREREQUEST_CACHE_INVALIDATION"

SCRIPT_A = f"""\
-- prerequest script A  ({MARKER_A})
RGW.Log(20, "Lua INFO: {MARKER_A} running in prerequest")
RGW.Log(20, "Lua INFO: op was: " .. Request.RGWOp)
RGW.Log(20, "Lua INFO: context was: prerequest")
return 0
"""

SCRIPT_B = f"""\
-- prerequest script B  ({MARKER_B})
RGW.Log(20, "Lua INFO: {MARKER_B} running in prerequest")
RGW.Log(20, "Lua INFO: op was: " .. Request.RGWOp)
RGW.Log(20, "Lua INFO: context was: prerequest")
Request.Response.HTTPStatusCode = 403
Request.Response.Message = "Forbidden by prerequest Lua script B"
return RGW_ABORT_REQUEST
"""

BLOCKING_SCRIPT = f"""\
-- prerequest blocking script ({BLOCK_MARKER})
RGW.Log(20, "Lua INFO: {BLOCK_MARKER} running in prerequest")
RGW.Log(20, "Lua INFO: op was: " .. Request.RGWOp)
RGW.Log(20, "Lua INFO: context was: prerequest")
if Request.RGWOp == "put_obj" then
  Request.Response.HTTPStatusCode = 403
  Request.Response.Message = "Blocked by prerequest cache invalidation test script"
  return RGW_ABORT_REQUEST
end
return 0
"""


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
    delete_bucket = config.test_ops.get("delete_bucket", True)

    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    user = user_info[0]
    cli_aws = AWS(ssl=config.ssl)
    bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=0)
    aws_auth.do_auth_aws(user)

    if config.test_ops.get("prerequest_cache_invalidation", False):
        script_set = False
        bucket_created = False
        debug_set = False
        objects = []
        try:
            aws_reusable.enable_rgw_debug_logging(level=20)
            debug_set = True

            try:
                aws_reusable.remove_lua_script(context="prerequest")
            except Exception as e:
                log.info(f"No leftover prerequest script to remove: {e}")

            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            bucket_created = True

            log.info(f"Upload blocking script ({BLOCK_MARKER}) to prerequest")
            aws_reusable.set_lua_script(
                context="prerequest", script_content=BLOCKING_SCRIPT
            )
            script_set = True
            stored = aws_reusable.get_lua_script(context="prerequest")
            if BLOCK_MARKER not in stored:
                raise TestExecError("blocking script was not stored in prerequest")

            blocked = os.path.join(TEST_DATA_PATH, "blocked.bin")
            with open(blocked, "wb") as fh:
                fh.write(b"should be blocked")
            log.info("put_object immediately after upload — expect 403 (fixed path)")
            aws_reusable.put_object_must_be_blocked(
                cli_aws,
                bucket_name,
                "blocked.bin",
                endpoint,
                body=blocked,
                fail_msg=(
                    "The put_object operation was not blocked by the Lua script "
                    "in the prerequest context (tracker #80576)."
                ),
            )

            time.sleep(2)
            lines = aws_reusable.grep_rgw_logs(
                BLOCK_MARKER,
                ssh_con=ssh_con,
                haproxy=config.haproxy,
            )
            log.info(f"Block-marker log lines found: {len(lines)}")
            for ln in lines[-10:]:
                log.info(ln)
            if not lines:
                raise TestExecError(
                    f"{BLOCK_MARKER} not found in RGW logs after blocked PUT. "
                    "Prerequest hook did not run the newly uploaded script."
                )
            log.info(f"{BLOCK_MARKER} observed — script active after upload")

            log.info("Remove blocking script and wait for cache invalidation")
            aws_reusable.remove_lua_script(context="prerequest")
            script_set = False
            time.sleep(lua_background_wait)

            unblocked = os.path.join(TEST_DATA_PATH, "unblocked.bin")
            with open(unblocked, "wb") as fh:
                fh.write(b"should pass")
            log.info("put_object after script removal — expect success")
            aws_reusable.put_object(
                cli_aws, bucket_name, "unblocked.bin", endpoint, body=unblocked
            )
            objects.append("unblocked.bin")

            if config.local_file_delete:
                utils.exec_shell_cmd(f"rm -f {blocked} {unblocked}")
        finally:
            if script_set:
                try:
                    aws_reusable.remove_lua_script(context="prerequest")
                except Exception as e:
                    log.warning(f"Failed to remove prerequest script: {e}")
            for key in objects:
                try:
                    aws_reusable.delete_object(cli_aws, bucket_name, key, endpoint)
                except Exception as e:
                    log.warning(f"delete_object {key}: {e}")
            if bucket_created and delete_bucket:
                try:
                    aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)
                except Exception as e:
                    log.warning(f"Failed to delete bucket {bucket_name}: {e}")
            if debug_set:
                try:
                    aws_reusable.reset_rgw_debug_logging()
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
        return

    if config.test_ops.get("prerequest_stale_bytecode_cache", False):
        script_set = False
        bucket_created = False
        debug_set = False
        objects = []
        try:
            aws_reusable.enable_rgw_debug_logging(level=20)
            debug_set = True

            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            bucket_created = True

            log.info(f"Upload script A ({MARKER_A}) to prerequest")
            aws_reusable.set_lua_script(context="prerequest", script_content=SCRIPT_A)
            script_set = True
            stored = aws_reusable.get_lua_script(context="prerequest")
            if MARKER_A not in stored:
                raise TestExecError("script A was not stored in prerequest")

            warmup = os.path.join(TEST_DATA_PATH, "warmup.bin")
            with open(warmup, "wb") as fh:
                fh.write(b"warmup")
            log.info("Warm-up PUT to compile script A bytecode")
            aws_reusable.put_object(
                cli_aws, bucket_name, "warmup.bin", endpoint, body=warmup
            )
            objects.append("warmup.bin")
            log.info(f"Waiting {lua_background_wait}s for LuaBackground")
            time.sleep(lua_background_wait)

            log.info("Remove script A and immediately upload script B (race window)")
            aws_reusable.remove_lua_script(context="prerequest")
            aws_reusable.set_lua_script(context="prerequest", script_content=SCRIPT_B)
            stored_b = aws_reusable.get_lua_script(context="prerequest")
            if MARKER_B not in stored_b:
                raise TestExecError("script B was not stored in prerequest")

            time.sleep(1)
            trigger = os.path.join(TEST_DATA_PATH, "trigger.bin")
            with open(trigger, "wb") as fh:
                fh.write(b"trigger")
            log.info(
                "Trigger PUT after script swap — expect 403 from script B (fixed path)"
            )
            aws_reusable.put_object_must_be_blocked(
                cli_aws,
                bucket_name,
                "trigger.bin",
                endpoint,
                body=trigger,
                fail_msg=(
                    "Trigger PUT returned success — stale script A bytecode likely "
                    "still served (tracker #80532). Expected 403 from script B."
                ),
            )

            time.sleep(2)
            lines = aws_reusable.grep_rgw_logs(
                f"{MARKER_A}|{MARKER_B}",
                ssh_con=ssh_con,
                haproxy=config.haproxy,
            )
            log.info(f"Marker log lines found: {len(lines)}")
            for ln in lines[-20:]:
                log.info(ln)
            if not any(MARKER_B in ln for ln in lines):
                raise TestExecError(
                    f"{MARKER_B} not found in RGW logs after trigger PUT. "
                    "Script B did not run (possible stale bytecode cache)."
                )
            log.info(f"{MARKER_B} observed — prerequest cache invalidated correctly")

            if config.local_file_delete:
                utils.exec_shell_cmd(f"rm -f {warmup} {trigger}")
        finally:
            if script_set:
                try:
                    aws_reusable.remove_lua_script(context="prerequest")
                except Exception as e:
                    log.warning(f"Failed to remove prerequest script: {e}")
            for key in objects:
                try:
                    aws_reusable.delete_object(cli_aws, bucket_name, key, endpoint)
                except Exception as e:
                    log.warning(f"delete_object {key}: {e}")
            if bucket_created and delete_bucket:
                try:
                    aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)
                except Exception as e:
                    log.warning(f"Failed to delete bucket {bucket_name}: {e}")
            if debug_set:
                try:
                    aws_reusable.reset_rgw_debug_logging()
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
        return

    if not config.test_ops.get("lua_postauth_cache", False):
        raise TestExecError(
            "Enable lua_postauth_cache, prerequest_stale_bytecode_cache, or "
            "prerequest_cache_invalidation in test_ops"
        )

    measure_latency = config.test_ops.get("measure_latency", True)
    latency_iterations = int(config.test_ops.get("latency_iterations", 20))
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

        aws_reusable.enable_rgw_debug_logging(level=20)
        debug_set = True

        log.info("Uploading script to prerequest")
        aws_reusable.set_lua_script(context="prerequest", script_content=lua_script)
        script_set = True
        retrieved = aws_reusable.get_lua_script(context="prerequest")
        log.info(f"Stored prerequest script ({len(retrieved.splitlines())} lines)")
        if "check_rule_0" not in retrieved or "local ok" not in retrieved:
            raise TestExecError("prerequest script was not stored correctly")

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

            recent = aws_reusable.grep_rgw_logs(
                log_grep,
                ssh_con=ssh_con,
                haproxy=config.haproxy,
                since_epoch=phase_start,
            )
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
                aws_reusable.reset_rgw_debug_logging()
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
    test_info = AddTestInfo("Lua bytecode cache tests with awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="Lua bytecode cache tests")
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
        config = resource_op.Config(yaml_file)
        config.read(ssh_con)
        if config.mapped_sizes is None and config.objects_size_range is not None:
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
