"""
Usage: test_aws.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_aws_lua_object_placement_on_stoarge_class.yaml

Operation:

"""


import argparse
import json
import logging
import math
import os
import random
import re
import subprocess
import sys
import traceback

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

    log.info("Setting log_to_file to true to enable logging to file")
    try:
        log_to_file_cmd = "ceph config set global log_to_file true"
        log.info(f"Setting log_to_file: {log_to_file_cmd}")
        utils.exec_shell_cmd(log_to_file_cmd)
        log.info("log_to_file set to true")
    except Exception as e:
        raise TestExecError(f"Failed to set log_to_file to true: {e}")

    log.info("Setting debug_rgw to 20 to enable lua debug messages")
    try:
        cmd_ps = "ceph orch ps --daemon_type rgw -f json"
        out_ps = utils.exec_shell_cmd(cmd_ps)
        rgw_daemons = json.loads(out_ps)

        for daemon in rgw_daemons:
            daemon_name = daemon.get("service_name")
            if daemon_name:
                debug_cmd = f"ceph config set client.{daemon_name} debug_rgw 20"
                log.info(f"Setting debug_rgw for {daemon_name}: {debug_cmd}")
                utils.exec_shell_cmd(debug_cmd)

        log.info("debug_rgw set to 20 for all RGW daemons")
    except Exception as e:
        raise TestExecError(f"Failed to set debug_rgw to 20: {e}")

    log.info(f"Setting lua script prerequest: {lua_script_content}")
    aws_reusable.set_lua_script(context="prerequest", script_content=lua_script_content)
    log.info("Lua script prerequest has been set")
    retrieved_script = aws_reusable.get_lua_script(context="prerequest")
    log.info(f"Retrieved lua script prerequest: {retrieved_script}")
    if not retrieved_script:
        raise AssertionError(
            "Failed to retrieve lua script prerequest - script was not set correctly"
        )

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info(f"Bucket {bucket_name} created")
            if config.test_ops.get("enable_version", False):
                log.info(f"bucket versioning test on bucket: {bucket_name}")
                aws_reusable.put_get_bucket_versioning(cli_aws, bucket_name, endpoint)

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
                validation_script_path = os.path.join(
                    os.path.abspath(os.path.join(__file__, "../../../../standalone")),
                    "boto_s3_list_object_validation.py",
                )

                if config.test_ops.get("enable_version", False):
                    validation_script_path = os.path.join(
                        os.path.abspath(
                            os.path.join(__file__, "../../../../standalone")
                        ),
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
                            for error_line in error_lines[:10]:  # Show first 10 errors
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
        object_count = config.objects_count // 2
        small_object_messages = object_count
        split_size = getattr(config, "split_size", 5)
        large_object_size = config.objects_size_range["max"]
        size_mb = float(str(large_object_size).replace("M", "").replace("m", ""))
        num_parts = math.ceil(size_mb / split_size)
        large_object_messages = object_count * (1 + num_parts)
        messages_per_bucket = small_object_messages + large_object_messages
        expected_message_count = messages_per_bucket * config.bucket_count
        if config.test_ops.get("enable_version", False):
            expected_message_count = expected_message_count * 2

        log.info(
            f"Expected lua debug message count: {expected_message_count} "
            f"(objects_count={config.objects_count}, bucket_count={config.bucket_count}, "
            f"small_objects={object_count}, large_objects={object_count}, "
            f"large_object_size={large_object_size}, split_size={split_size}MB, "
            f"parts_per_large_object={num_parts}, versioning={config.test_ops.get('enable_version', False)})"
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
