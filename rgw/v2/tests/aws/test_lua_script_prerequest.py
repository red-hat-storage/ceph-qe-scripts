"""
Usage: test_lua_script_prerequest.py -c <input_yaml>

<input_yaml>
    configs/test_aws_lua_object_placement_on_stoarge_class.yaml
    configs/test_aws_lua_object_lock.yaml
    configs/test_aws_lua_object_lock_governance.yaml
    configs/test_aws_lua_object_lock_minimal.yaml
    configs/test_aws_lua_block_object_lock_request.yaml
    configs/test_aws_lua_block_object_lock_request_governance.yaml

Operation:
    - object_placement_on_storage_class: Lua script auto-tiers objects by size.
    - lua_object_lock: Lua enable script on plain create-bucket; verify versioning + object lock.
    - lua_block_object_lock: Lua block script — negative plain create-bucket, positive
      --object-lock-enabled-for-bucket, optional verify without Lua (polarion CEPH-83632419).
"""


import argparse
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None
AWS_CLI = "/usr/local/bin/aws"


def _run_lua_block_object_lock_tests(config, user_info, endpoint, ssh_con):
    """RGW 9.1 Lua block: one negative create-bucket, positive object-lock bucket, optional w/out Lua."""
    script_removed = False
    for user in user_info:
        user_name = user["user_id"]
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        neg_bucket = utils.gen_bucket_name_from_userid(user_name, rand_no=900)
        pos_bucket = utils.gen_bucket_name_from_userid(user_name, rand_no=0)

        if config.test_ops.get("negative_create_without_lock", True):
            log.info(
                "Negative: create-bucket without object lock (expect AccessDenied)"
            )
            bucket_list = json.loads(utils.exec_shell_cmd("radosgw-admin bucket list"))
            if neg_bucket in bucket_list:
                raise AssertionError(
                    f"Bucket {neg_bucket} already exists before negative test"
                )
            neg_cmd = cli_aws.command(
                operation="create-bucket",
                params=[f"--bucket {neg_bucket} --endpoint-url {endpoint}"],
            )
            neg_start = time.time()
            neg_err = utils.exec_shell_cmd(neg_cmd, return_err=True)
            if neg_err is False:
                raise AssertionError(
                    f"create-bucket {neg_bucket}: command execution failed unexpectedly"
                )
            bucket_list = json.loads(utils.exec_shell_cmd("radosgw-admin bucket list"))
            if neg_bucket in bucket_list:

                raise AssertionError(
                    f"Bucket {neg_bucket} was created but Lua should have blocked it"
                )
            neg_err_str = str(neg_err)
            if (
                "Bucket must have object lock enabled" not in neg_err_str
                and "AccessDenied" not in neg_err_str
            ):
                raise AssertionError(
                    f"Expected AccessDenied/object lock message, got: {neg_err_str}"
                )
            time.sleep(3)
            neg_log_pattern = f"object lock is missing on bucket: {neg_bucket}"
            aws_reusable.check_rgw_debug_logs_and_reset(
                message_pattern=neg_log_pattern,
                ssh_con=ssh_con,
                haproxy=config.haproxy,
                check_all_rgw_nodes=True,
                expected_count=1,
                since_epoch=neg_start,
                exact_count=True,
            )

        log.info(f"Positive: create-bucket with object lock enabled: {pos_bucket}")
        aws_reusable.create_bucket(
            cli_aws, pos_bucket, endpoint, object_lock_enabled=True
        )
        aws_reusable.verify_bucket_object_lock_stats(pos_bucket)

        lock_cfg = aws_reusable.get_object_lock_configuration(
            cli_aws, pos_bucket, endpoint
        )
        olc = lock_cfg.get("ObjectLockConfiguration", {})
        if olc.get("ObjectLockEnabled") != "Enabled":
            raise AssertionError(f"Expected ObjectLockEnabled Enabled, got: {lock_cfg}")

        if config.test_ops.get("create_object", False):
            for oc, size in list(config.mapped_sizes.items()):
                key_name = f"obj-lock-{oc}"
                utils.exec_shell_cmd(f"fallocate -l {size} {key_name}")
                try:
                    aws_reusable.put_object(cli_aws, pos_bucket, key_name, endpoint)
                finally:
                    if os.path.exists(key_name):
                        os.remove(key_name)
            aws_reusable.verify_bucket_object_lock_stats(
                pos_bucket, expected_objects=config.objects_count
            )

        if config.test_ops.get("put_default_retention", False):
            mode = config.test_ops.get("lock_mode", "COMPLIANCE")
            days = int(config.test_ops.get("retention_days", 1))
            aws_reusable.put_object_lock_default_retention(
                cli_aws, pos_bucket, endpoint, mode=mode, days=days
            )
            lock_cfg = aws_reusable.get_object_lock_configuration(
                cli_aws, pos_bucket, endpoint
            )
            retention = (
                lock_cfg.get("ObjectLockConfiguration", {})
                .get("Rule", {})
                .get("DefaultRetention", {})
            )
            if retention.get("Mode") != mode or retention.get("Days") != days:
                raise AssertionError(f"Default retention mismatch: {lock_cfg}")

        if config.test_ops.get("verify_without_lua", False):
            log.info("Remove Lua script; create-bucket without lock should succeed")
            aws_reusable.remove_lua_script(context="prerequest")
            out = aws_reusable.get_lua_script(context="prerequest")
            if out and "no script exists" not in out.lower():
                raise AssertionError("Lua script was not removed")
            script_removed = True
            if config.test_ops.get("restart_rgw", True):
                utils.restart_rgw(restart_all=True)
                time.sleep(30)
            free_bucket = utils.gen_bucket_name_from_userid(user_name, rand_no=901)
            aws_reusable.create_bucket(cli_aws, free_bucket, endpoint)
            if free_bucket not in json.loads(
                utils.exec_shell_cmd("radosgw-admin bucket list")
            ):
                raise AssertionError(
                    f"Bucket {free_bucket} should exist after script removal"
                )
            log.info(f"Without Lua: bucket {free_bucket} created without object lock")

    return script_removed


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
        ssh_con: SSH connection object (optional)
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    user_name = (config.test_ops.get("user_name"), None)
    user_names = [user_name] if type(user_name) != list else user_name

    endpoint = aws_reusable.get_endpoint(
        ssh_con, ssl=config.ssl, haproxy=config.haproxy
    )

    lua_script_content = None
    lua_debug_message_pattern = None
    lua_object_lock_mode = False
    lua_block_object_lock_mode = False

    if config.test_ops.get("object_placement_on_storage_class", False):
        aws_reusable.create_storage_class_single_site(
            config.test_ops.get("pool_name"), config.test_ops.get("storage_class")
        )
        storage_class = config.test_ops.get("storage_class")
        lua_script_content = f"""
-- Lua script to auto-tier S3 object PUT/POST/INIT_MULTIPART requests

-- exit script quickly if it is not a PUT/POST/INIT_MULTIPART request
if Request.RGWOp ~= "put_obj" and Request.RGWOp ~= "post_obj" and Request.RGWOp ~= "init_multipart"
then
  return
end

local storage_class_status = "not set"

-- Apply storage class based on the objects size
if Request.ContentLength > 1048576 or Request.RGWOp == "init_multipart" then
  Request.HTTP.StorageClass = "{storage_class}"
  storage_class_status = "set to {storage_class}"
end

RGWDebugLog(Request.RGWOp ..
  " request. storage class " .. storage_class_status ..
  " for bucket: \\"" .. ((Request.Bucket and Request.Bucket.Name) or "") ..
  "\\" and object: \\"" ..  ((Request.Object and Request.Object.Name) or "") ..
  "\\" of size: " .. Request.ContentLength)
"""
        lua_debug_message_pattern = aws_reusable.extract_debug_pattern_from_lua_script(
            lua_script_content, storage_class=storage_class
        )
    elif config.test_ops.get("lua_object_lock", False):
        lua_object_lock_mode = True
        lua_script_content = aws_reusable.LUA_ENABLE_OBJECT_LOCK_PREREQUEST
        lua_debug_message_pattern = aws_reusable.LUA_ENABLE_OBJECT_LOCK_DEBUG_PATTERN
    elif config.test_ops.get("lua_block_object_lock", False):
        lua_block_object_lock_mode = True
        lua_script_content = aws_reusable.LUA_BLOCK_OBJECT_LOCK_PREREQUEST
        lua_debug_message_pattern = aws_reusable.LUA_BLOCK_OBJECT_LOCK_DEBUG_PATTERN

    if config.test_ops.get("user_name", False):
        op = json.loads(utils.exec_shell_cmd("radosgw-admin user list"))
        log.info(f"user {config.test_ops['user_name']} exist in cluster {op}")
        if config.test_ops["user_name"] not in op:
            log.info(f"number of user to create is {config.user_count}")
            user_info = resource_op.create_users(
                no_of_users_to_create=config.user_count,
                user_names=user_names,
            )
        elif config.user_count == 1:
            out = json.loads(
                utils.exec_shell_cmd(
                    f"radosgw-admin user info --uid={config.test_ops['user_name']}"
                )
            )
            user_info = [
                {
                    "user_id": out["user_id"],
                    "display_name": out["display_name"],
                    "access_key": out["keys"][0]["access_key"],
                    "secret_key": out["keys"][0]["secret_key"],
                }
            ]
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    log.info("Enabling RGW file logging and debug_rgw=20 for Lua RGWDebugLog")
    try:
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
        log.info("log_to_file and debug_rgw set for all RGW services and daemons")
    except Exception as e:
        raise TestExecError(f"Failed to enable RGW Lua debug logging: {e}")

    if not lua_script_content:
        raise TestExecError(
            "No Lua script configured. Set object_placement_on_storage_class, "
            "lua_object_lock, or lua_block_object_lock in test_ops."
        )
    log.info("Setting lua script prerequest (inline)")
    aws_reusable.set_lua_script(context="prerequest", script_content=lua_script_content)
    log.info("Lua script prerequest has been set")
    retrieved_script = aws_reusable.get_lua_script(context="prerequest")
    log.info(f"Retrieved lua script prerequest: {retrieved_script}")
    if not retrieved_script:
        raise AssertionError(
            "Failed to retrieve lua script prerequest - script was not set correctly"
        )
    if (
        lua_object_lock_mode
        and "x-amz-bucket-object-lock-enabled" not in retrieved_script
    ):
        raise AssertionError(
            "Object lock Lua script was not set correctly (missing x-amz-bucket-object-lock-enabled)"
        )
    if lua_block_object_lock_mode and "RGW_ABORT_REQUEST" not in retrieved_script:
        raise AssertionError(
            "Block object lock Lua script was not set correctly (missing RGW_ABORT_REQUEST)"
        )

    if lua_block_object_lock_mode:
        if config.test_ops.get("restart_rgw", True):
            utils.restart_rgw(restart_all=True)
            time.sleep(30)
        script_removed = _run_lua_block_object_lock_tests(
            config, user_info, endpoint, ssh_con
        )
        if not script_removed:
            aws_reusable.remove_lua_script(context="prerequest")
            log.info("Lua script prerequest has been removed")
    else:
        if lua_object_lock_mode and config.test_ops.get("restart_rgw", False):
            utils.restart_rgw(restart_all=True)
            time.sleep(20)
        buckets_created_count = 0
        for user in user_info:
            user_name = user["user_id"]
            log.info(user_name)
            cli_aws = AWS(ssl=config.ssl)
            aws_auth.do_auth_aws(user)

            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                buckets_created_count += 1
                log.info(f"Bucket {bucket_name} created")
                if config.test_ops.get("enable_version", False):
                    log.info(f"bucket versioning test on bucket: {bucket_name}")
                    aws_reusable.put_get_bucket_versioning(
                        cli_aws, bucket_name, endpoint
                    )

                if lua_object_lock_mode:
                    out = utils.exec_shell_cmd(
                        f"radosgw-admin bucket stats --bucket {bucket_name}"
                    )
                    data = json.loads(out)
                    info = data[0] if isinstance(data, list) else data
                    if info.get("versioning") != "enabled":
                        raise AssertionError(
                            f"Bucket {bucket_name}: expected versioning enabled, got {info.get('versioning')}"
                        )
                    if not info.get("object_lock_enabled"):
                        raise AssertionError(
                            f"Bucket {bucket_name}: expected object_lock_enabled true, got {info.get('object_lock_enabled')}"
                        )
                    log.info(
                        f"Bucket {bucket_name}: versioning=enabled, object_lock_enabled=true"
                    )
                    ver_out = utils.exec_shell_cmd(
                        f"{AWS_CLI} s3api get-bucket-versioning --bucket {bucket_name} --endpoint-url {endpoint}"
                    )
                    if "Enabled" not in ver_out:
                        raise AssertionError(
                            f"get-bucket-versioning for {bucket_name} did not show Enabled: {ver_out}"
                        )
                    lock_out = utils.exec_shell_cmd(
                        f"{AWS_CLI} s3api get-object-lock-configuration --bucket {bucket_name} --endpoint-url {endpoint}"
                    )
                    if "ObjectLockEnabled" not in lock_out or "Enabled" not in lock_out:
                        raise AssertionError(
                            f"get-object-lock-configuration for {bucket_name} did not show Enabled: {lock_out}"
                        )
                    if config.test_ops.get("put_default_retention"):
                        mode = config.test_ops.get("lock_mode", "COMPLIANCE")
                        days = config.test_ops.get("retention_days", 5)
                        obj_size_str = config.objects_size_range.get("min", "4K")
                        if isinstance(obj_size_str, str):
                            s = obj_size_str.strip().upper()
                            obj_size = (
                                int(s.replace("M", "")) * 1024 * 1024
                                if "M" in s
                                else int(s.replace("K", "") or "4") * 1024
                            )
                        else:
                            obj_size = int(obj_size_str) if obj_size_str else 4096
                        retain_until = (
                            datetime.now(timezone.utc) + timedelta(days=days)
                        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        key_early = f"obj-retention-{bc}"
                        key_name = f"obj-lock-{bc}"
                        utils.exec_shell_cmd(f"fallocate -l {obj_size} {key_early}")
                        if not config.test_ops.get("test_multipart", False):
                            utils.exec_shell_cmd(f"fallocate -l {obj_size} {key_name}")
                        try:
                            aws_reusable.put_object(
                                cli_aws, bucket_name, key_early, endpoint
                            )
                            utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api put-object-retention --bucket {bucket_name} --key {key_early} "
                                f"--endpoint-url {endpoint} --retention "
                                f'\'{{"Mode":"{mode}","RetainUntilDate":"{retain_until}"}}\''
                            )
                            ret_early = utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api get-object-retention --bucket {bucket_name} --key {key_early} --endpoint-url {endpoint}"
                            )
                            if (
                                "Retention" not in ret_early
                                or "RetainUntilDate" not in ret_early
                            ):
                                raise AssertionError(
                                    f"get-object-retention after put-object-retention for {key_early} failed: {ret_early}"
                                )
                            log.info(
                                f"Object-level put-object-retention and get-object-retention verified for {key_early}"
                            )
                            lock_cfg = (
                                '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"'
                                + mode
                                + '","Days":'
                                + str(days)
                                + "}}}"
                            )
                            utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api put-object-lock-configuration --bucket {bucket_name} "
                                f"--endpoint-url {endpoint} --object-lock-configuration '{lock_cfg}'"
                            )
                            log.info(
                                f"Set default retention {mode} {days} days on {bucket_name}"
                            )
                            lock_get = utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api get-object-lock-configuration --bucket {bucket_name} --endpoint-url {endpoint}"
                            )
                            if (
                                "Rule" not in lock_get
                                or "DefaultRetention" not in lock_get
                            ):
                                raise AssertionError(
                                    f"get-object-lock-configuration should return Rule/DefaultRetention: {lock_get}"
                                )
                            if config.test_ops.get("test_multipart", False):
                                config.obj_size = config.objects_size_range["max"]
                                log.info(
                                    "Uploading object with default retention via multipart: %s",
                                    key_name,
                                )
                                aws_reusable.upload_multipart_aws(
                                    cli_aws,
                                    bucket_name,
                                    key_name,
                                    TEST_DATA_PATH,
                                    endpoint,
                                    config,
                                )
                            else:
                                aws_reusable.put_object(
                                    cli_aws, bucket_name, key_name, endpoint
                                )
                            ret_out = utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api get-object-retention --bucket {bucket_name} --key {key_name} --endpoint-url {endpoint}"
                            )
                            if "Retention" not in ret_out:
                                log.warning(
                                    f"get-object-retention for {key_name} (may be NoneType on some versions): {ret_out}"
                                )
                            del_out = utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api delete-object --bucket {bucket_name} --key {key_name} --endpoint-url {endpoint}"
                            )
                            log.info(
                                "aws s3api delete-object (no version-id) output: %s",
                                del_out,
                            )
                            if "DeleteMarker" not in str(del_out):
                                log.warning(
                                    f"delete-object (no version-id) expected DeleteMarker: {del_out}"
                                )
                            else:
                                log.info(
                                    "delete-object without version-id returned DeleteMarker as expected"
                                )
                            list_ver = utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api list-object-versions --bucket {bucket_name} --endpoint-url {endpoint} "
                                f"--query \"Versions[?Key=='{key_name}']\" --output json"
                            )
                            try:
                                ver_list = json.loads(list_ver) if list_ver else []
                            except (json.JSONDecodeError, TypeError):
                                ver_list = []
                            ver_list = ver_list or []
                            if ver_list and ver_list[0].get("VersionId"):
                                vid = ver_list[0]["VersionId"]
                                err = utils.exec_shell_cmd(
                                    f"{AWS_CLI} s3api delete-object --bucket {bucket_name} --key {key_name} "
                                    f"--version-id {vid} --endpoint-url {endpoint}",
                                    return_err=True,
                                )
                                log.info(
                                    "aws s3api delete-object (version-id %s, locked) output: %s",
                                    vid,
                                    err,
                                )
                                if err and (
                                    "forbidden by object lock" in str(err).lower()
                                    or "AccessDenied" in str(err)
                                ):
                                    log.info(
                                        "Delete of locked object version correctly forbidden"
                                    )
                                else:
                                    log.warning(
                                        f"Expected AccessDenied/forbidden when deleting locked version: {err}"
                                    )
                            list_early = utils.exec_shell_cmd(
                                f"{AWS_CLI} s3api list-object-versions --bucket {bucket_name} --endpoint-url {endpoint} "
                                f"--query \"Versions[?Key=='{key_early}']\" --output json"
                            )
                            try:
                                early_list = (
                                    json.loads(list_early) if list_early else []
                                )
                            except (json.JSONDecodeError, TypeError):
                                early_list = []
                            early_list = early_list or []
                            if early_list and early_list[0].get("VersionId"):
                                vid_early = early_list[0]["VersionId"]
                                err_early = utils.exec_shell_cmd(
                                    f"{AWS_CLI} s3api delete-object --bucket {bucket_name} --key {key_early} "
                                    f"--version-id {vid_early} --endpoint-url {endpoint}",
                                    return_err=True,
                                )
                                log.info(
                                    "aws s3api delete-object (version-id %s, object-level retention) output: %s",
                                    vid_early,
                                    err_early,
                                )
                                if err_early and (
                                    "forbidden by object lock" in str(err_early).lower()
                                    or "AccessDenied" in str(err_early)
                                ):
                                    log.info(
                                        "Delete of object-level retention version correctly forbidden"
                                    )
                        finally:
                            for f in (key_early, key_name):
                                if os.path.exists(f):
                                    try:
                                        os.remove(f)
                                    except OSError:
                                        pass

                if config.test_ops.get("object_placement_on_storage_class", False):
                    object_count = config.objects_count // 2
                    log.info(f"uploading some small objects to bucket {bucket_name}")
                    for sobj in range(object_count):
                        config.obj_size = config.objects_size_range["min"]
                        small_key_name = f"small-object-{sobj}"
                        utils.exec_shell_cmd(
                            f"fallocate -l {config.obj_size} {small_key_name}"
                        )
                        log.info(f"upload s3 object: {small_key_name}")
                        aws_reusable.put_object(
                            cli_aws, bucket_name, small_key_name, endpoint
                        )
                        if config.test_ops.get("enable_version", False):
                            aws_reusable.put_object(
                                cli_aws, bucket_name, small_key_name, endpoint
                            )

                    log.info(f"uploading some large objects to bucket {bucket_name}")
                    for mobj in range(object_count):
                        config.obj_size = config.objects_size_range["max"]
                        key_name = f"large-object-{mobj}"
                        log.info(f"upload s3 object: {key_name}")
                        aws_reusable.upload_multipart_aws(
                            cli_aws,
                            bucket_name,
                            key_name,
                            TEST_DATA_PATH,
                            endpoint,
                            config,
                        )
                        if config.test_ops.get("enable_version", False):
                            aws_reusable.upload_multipart_aws(
                                cli_aws,
                                bucket_name,
                                key_name,
                                TEST_DATA_PATH,
                                endpoint,
                                config,
                            )

                    log.info("Verifying lua script prerequest is working as expected")
                    standalone_dir = os.path.abspath(
                        os.path.join(__file__, "../../../../standalone")
                    )
                    validation_script_path = os.path.join(
                        standalone_dir,
                        "boto_s3_list_object_validation.py",
                    )

                    if config.test_ops.get("enable_version", False):
                        validation_script_path = os.path.join(
                            standalone_dir,
                            "boto_s3_list_ver_object_validation.py",
                        )

                    if not os.path.exists(validation_script_path):
                        raise TestExecError(
                            f"Validation script not found at {validation_script_path}. Cannot validate object storage classes."
                        )

                    log.info(f"Running validation script: {validation_script_path}")
                    validation_output = f"list_validate_{bucket_name}.log"
                    env = os.environ.copy()
                    env["BUCKET_NAME"] = bucket_name
                    env["OUTPUT_FILE"] = validation_output
                    env["S3_ENDPOINT"] = endpoint
                    env["AWS_ACCESS_KEY_ID"] = user["access_key"]
                    env["AWS_SECRET_ACCESS_KEY"] = user["secret_key"]
                    env["EXPECTED_STORAGE_CLASS"] = config.test_ops.get(
                        "storage_class", None
                    )
                    validation_cmd = f"{sys.executable} {validation_script_path}"
                    log.info(f"Executing: {validation_cmd}")
                    try:
                        result = subprocess.run(
                            validation_cmd,
                            shell=True,
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=3600,
                        )
                        if result.returncode != 0:
                            raise TestExecError(
                                f"Validation script returned non-zero exit code: {result.returncode}. "
                                f"Stderr: {result.stderr}"
                            )
                        log.info("Validation script completed successfully")
                    except subprocess.TimeoutExpired:
                        raise TestExecError("Validation script timed out after 1 hour")
                    except Exception as e:
                        raise TestExecError(f"Error running validation script: {e}")

                    if not os.path.exists(validation_output):
                        raise TestExecError(
                            f"Validation output file {validation_output} not found after script execution"
                        )
                    try:
                        with open(validation_output, "r") as f:
                            validation_content = f.read()
                            error_count = validation_content.count("ERROR")
                            pass_count = validation_content.count("PASS")
                            log.info(
                                f"Validation results - PASS: {pass_count}, ERROR: {error_count}"
                            )

                            if error_count > 0:
                                error_lines = [
                                    line
                                    for line in validation_content.split("\n")
                                    if "ERROR" in line
                                ]
                                for error_line in error_lines[
                                    :10
                                ]:  # Show first 10 errors
                                    log.warning(f"Validation error: {error_line}")
                                raise AssertionError(
                                    f"Validation failed: {error_count} objects have incorrect storage class. "
                                    f"Check {validation_output} for details"
                                )
                            else:
                                log.info(
                                    "All objects validated successfully - storage classes are correct"
                                )
                    finally:
                        try:
                            if os.path.exists(validation_output):
                                os.remove(validation_output)
                        except Exception as e:
                            log.warning(
                                f"Failed to remove validation output file {validation_output}: {e}"
                            )

        if lua_debug_message_pattern:
            if lua_object_lock_mode:
                expected_message_count = buckets_created_count
                log.info(
                    f"Expected lua debug message count: {expected_message_count} "
                    "(object lock: one per bucket)"
                )
            else:
                # Small objects: one put_obj log each; large objects: one init_multipart log each
                # (upload_part ops are not handled by the Lua prerequest script).
                object_count = config.objects_count // 2
                expected_message_count = (
                    object_count + object_count
                ) * config.bucket_count
                if config.test_ops.get("enable_version", False):
                    expected_message_count = expected_message_count * 2
                log.info(
                    f"Expected lua debug message count: {expected_message_count} "
                    f"(small_objects={object_count}, large_objects={object_count}, "
                    f"bucket_count={config.bucket_count}, "
                    f"versioning={config.test_ops.get('enable_version', False)})"
                )
            aws_reusable.check_rgw_debug_logs_and_reset(
                message_pattern=lua_debug_message_pattern,
                ssh_con=ssh_con,
                haproxy=config.haproxy,
                expected_count=expected_message_count,
            )

        aws_reusable.remove_lua_script(context="prerequest")
        log.info("Lua script prerequest has been removed")
    if config.user_remove is True:
        for user in user_info:
            s3_reusable.remove_user(user)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Lua script prerequest test with awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Lua script prerequest test with awscli"
        )
        parser.add_argument(
            "-c", dest="config", help="Lua script prerequest test with awscli"
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
