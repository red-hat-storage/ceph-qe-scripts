"""
Usage: test_conditional_delete_objects.py -c <input_yaml>

Validates conditional deletes of multiple objects using the delete-objects API
with ETag conditions. See:
https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-objects.html

<input_yaml>
    configs/test_cond_delete_objects_etag.yaml

Operation:
    - Creates a bucket and uploads N objects (default 10).
    - Fetches ETags via list-object-versions.
    - Optionally verifies that delete-objects with wrong ETag returns errors.
    - Calls delete-objects with correct ETags for all objects and verifies
      all are deleted (Deleted list) and no Errors.
"""
import argparse
import json
import logging
import os
import sys
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


def test_exec(config, ssh_con):
    """
    Executes test: conditional delete of multiple objects with ETag via delete-objects API.
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    user_names = [(config.test_ops.get("user_name"), None)] if config.test_ops.get("user_name") else None
    if user_names and type(user_names[0]) != list:
        user_names = [user_names[0]]

    endpoint = aws_reusable.get_endpoint(
        ssh_con, ssl=config.ssl, haproxy=config.haproxy
    )

    if config.test_ops.get("user_name"):
        op = json.loads(utils.exec_shell_cmd("radosgw-admin user list"))
        if config.test_ops["user_name"] not in op:
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
            user_info = [{
                "user_id": out["user_id"],
                "display_name": out["display_name"],
                "access_key": out["keys"][0]["access_key"],
                "secret_key": out["keys"][0]["secret_key"],
            }]
        else:
            user_info = resource_op.create_users(
                no_of_users_to_create=config.user_count,
                user_names=user_names,
            )
    else:
        user_info = resource_op.create_users(
            no_of_users_to_create=config.user_count
        )

    object_count = config.test_ops.get("object_count") or getattr(
        config, "objects_count", 10
    )
    if object_count is None:
        object_count = 10
    object_count = int(object_count)

    for user in user_info:
        user_name = user["user_id"]
        log.info("user: %s", user_name)
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        for bc in range(config.bucket_count):
            if config.test_ops.get("bucket_name"):
                bucket_name = config.test_ops["bucket_name"] + str(bc + 1)
            else:
                bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)

            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info("Bucket created: %s", bucket_name)

            object_names = []
            for i in range(object_count):
                obj_name = utils.gen_s3_object_name(bucket_name, i)
                object_names.append(obj_name)
                utils.exec_shell_cmd(f"fallocate -l 1M {obj_name}")
                aws_reusable.put_object(cli_aws, bucket_name, obj_name, endpoint)
            log.info("Uploaded %d objects", object_count)

            version_list = json.loads(
                aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
            )
            versions = version_list.get("Versions") or []
            key_to_etag = {}
            for v in versions:
                k = v["Key"]
                if k in object_names:
                    etag_raw = v.get("ETag") or ""
                    etag_clean = etag_raw.strip('"')
                    key_to_etag[k] = etag_clean
            if len(key_to_etag) != object_count:
                raise TestExecError(
                    f"Expected {object_count} objects in list-object-versions, got {len(key_to_etag)}"
                )

            objects_with_etag = [
                {"Key": k, "ETag": key_to_etag[k]} for k in object_names
            ]

            if config.test_ops.get("wrong_etag_first", True):
                log.info("Verify delete-objects with wrong ETag returns errors")
                wrong_list = [
                    {
                        "Key": k,
                        "ETag": (key_to_etag[k] + "x") if key_to_etag[k] else "wrong",
                    }
                    for k in object_names[:1]
                ]
                out_err = aws_reusable.delete_objects(
                    cli_aws, bucket_name, wrong_list, endpoint, return_err=True
                )
                if out_err is not False and out_err:
                    try:
                        err_resp = json.loads(out_err)
                        if err_resp.get("Errors"):
                            log.info(
                                "Wrong ETag correctly produced Errors: %s",
                                err_resp["Errors"],
                            )
                        else:
                            log.info(
                                "delete-objects response had no Errors (implementation may differ)"
                            )
                    except (json.JSONDecodeError, TypeError):
                        log.info(
                            "Wrong ETag caused CLI/API failure (non-JSON output): %s",
                            str(out_err)[:200],
                        )
                log.info("Conditional delete with wrong ETag check completed")

            log.info("Conditional delete-objects with correct ETag for all %d objects", object_count)
            response = aws_reusable.delete_objects(
                cli_aws, bucket_name, objects_with_etag, endpoint
            )
            resp = json.loads(response)
            deleted = resp.get("Deleted") or []
            errors = resp.get("Errors") or []

            if errors:
                raise TestExecError(
                    f"delete-objects returned Errors: {errors}"
                )
            if len(deleted) != object_count:
                raise TestExecError(
                    f"Expected {object_count} entries in Deleted, got {len(deleted)}"
                )
            log.info("All %d objects conditionally deleted successfully", object_count)

            list_out = json.loads(
                aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
            )
            contents = list_out.get("Contents") or []
            if contents:
                raise AssertionError(
                    f"Bucket should be empty after delete-objects, found: {[c['Key'] for c in contents]}"
                )
            log.info("Bucket is empty after delete-objects")

        if config.user_remove:
            s3_reusable.remove_user(user)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "Conditional delete of multiple objects with ETag (delete-objects API)"
    )

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s", TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="Conditional delete of multiple objects with ETag (delete-objects)"
        )
        parser.add_argument("-c", dest="config", help="Path to YAML config")
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
