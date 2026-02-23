"""
Usage: test_conditional_delete_objects.py -c <input_yaml>

Validates conditional deletes of multiple objects using the delete-objects API
with ETag or LastModifiedTime conditions. See:
https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-objects.html

<input_yaml>
    configs/test_cond_delete_objects_etag.yaml
    configs/test_cond_delete_objects_lmt.yaml

Operation:
    - Creates a bucket and uploads N objects (default 10).
    - ETag mode: Fetches ETags via list-object-versions; optionally verifies
      wrong ETag returns errors; delete-objects with correct ETags.
    - LMT mode: Fetches LastModified via list-object-versions; optionally
      verifies wrong LastModifiedTime returns errors; delete-objects with
      correct LastModifiedTime for all objects.
"""
import argparse
import json
import logging
import os
import random
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
    Executes test: conditional delete of multiple objects with ETag or
    LastModifiedTime via delete-objects API.
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    use_lmt = config.test_ops.get("conditional_delete_objects_lmt", False)
    use_etag = config.test_ops.get("conditional_delete_objects_etag", False)
    if not use_lmt and not use_etag:
        use_etag = True  # default to ETag for backward compatibility

    ceph_version_id = []
    if use_lmt:
        ceph_version_id, _ = utils.get_ceph_version()
        ceph_version_id = ceph_version_id.split("-")[0].split(".")

    user_names = (
        [(config.test_ops.get("user_name"), None)]
        if config.test_ops.get("user_name")
        else None
    )

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
            user_info = [
                {
                    "user_id": out["user_id"],
                    "display_name": out["display_name"],
                    "access_key": out["keys"][0]["access_key"],
                    "secret_key": out["keys"][0]["secret_key"],
                }
            ]
        else:
            user_info = resource_op.create_users(
                no_of_users_to_create=config.user_count,
                user_names=user_names,
            )
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

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
            for i in range(config.objects_count):
                obj_name = utils.gen_s3_object_name(bucket_name, i)
                object_names.append(obj_name)
                utils.exec_shell_cmd(f"fallocate -l 1M {obj_name}")
                aws_reusable.put_object(cli_aws, bucket_name, obj_name, endpoint)
            log.info("Uploaded %d objects", config.objects_count)
            for obj in object_names:
                utils.exec_shell_cmd(f"rm -rf {obj}")
            version_list = json.loads(
                aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
            )
            versions = version_list.get("Versions") or []
            if len(versions) < config.objects_count:
                raise TestExecError(
                    f"Expected {config.objects_count} objects in list-object-versions, got {len(versions)}"
                )

            key_to_obj = {}
            for v in versions:
                k = v["Key"]
                if k in object_names and k not in key_to_obj:
                    key_to_obj[k] = v
            if len(key_to_obj) != config.objects_count:
                raise TestExecError(
                    f"Expected {config.objects_count} objects in list-object-versions, got {len(key_to_obj)}"
                )

            if use_etag:
                key_to_etag = {}
                for k, v in key_to_obj.items():
                    etag_raw = v.get("ETag") or ""
                    key_to_etag[k] = etag_raw.strip('"')
                objects_to_delete = [
                    {"Key": k, "ETag": key_to_etag[k]} for k in object_names
                ]
                if config.test_ops.get("wrong_etag_first", True):
                    log.info("Verify delete-objects with wrong ETag returns errors")
                    wrong_list = [
                        {
                            "Key": k,
                            "ETag": aws_reusable.wrong_etag(key_to_etag[k]),
                        }
                        for k in object_names[:1]
                    ]
                    log.info("Wrong ETag list: %s", wrong_list)
                    out_err = aws_reusable.delete_objects(
                        cli_aws, bucket_name, wrong_list, endpoint, return_err=True
                    )
                    if out_err is not False and out_err:
                        try:
                            err_resp = json.loads(out_err)
                            if err_resp.get("Errors"):
                                log.info(
                                    "Wrong ETag produced Errors: %s",
                                    err_resp["Errors"],
                                )
                                if (
                                    err_resp["Errors"][0]["Code"]
                                    != "PreconditionFailed"
                                ):
                                    raise AssertionError(
                                        "delete-objects did not fail with PreconditionFailed"
                                    )
                            else:
                                raise AssertionError(
                                    "delete-objects succeeded with wrong ETag"
                                )
                        except (json.JSONDecodeError, TypeError):
                            log.info(
                                "Wrong ETag caused CLI/API failure: %s",
                                str(out_err)[:200],
                            )
                    log.info("Conditional delete with wrong ETag check completed")
                log.info(
                    "Conditional delete-objects with correct ETag for all %d objects",
                    config.objects_count,
                )

            else:
                # LastModifiedTime conditional delete
                key_to_lmt = {}
                for k, v in key_to_obj.items():
                    raw = v.get("LastModified") or ""
                    key_to_lmt[k] = aws_reusable.normalize_last_modified(
                        raw, ceph_version_id
                    )
                objects_to_delete = [
                    {"Key": k, "LastModifiedTime": key_to_lmt[k]} for k in object_names
                ]
                if config.test_ops.get("wrong_lmt_first", True):
                    log.info(
                        "Verify delete-objects with wrong LastModifiedTime returns errors"
                    )
                    correct_lmt = key_to_lmt[object_names[0]]
                    wrong_lmt = (
                        correct_lmt[:-1]
                        if len(correct_lmt) > 1
                        else "1970-01-01T00:00:00"
                    )
                    wrong_list = [
                        {"Key": object_names[0], "LastModifiedTime": wrong_lmt}
                    ]
                    log.info("Wrong LastModifiedTime list: %s", wrong_list)
                    out_err = aws_reusable.delete_objects(
                        cli_aws, bucket_name, wrong_list, endpoint, return_err=True
                    )
                    if out_err is not False and out_err:
                        try:
                            err_resp = json.loads(out_err)
                            if err_resp.get("Errors"):
                                log.info(
                                    "Wrong LastModifiedTime produced Errors: %s",
                                    err_resp["Errors"],
                                )
                                if (
                                    err_resp["Errors"][0]["Code"]
                                    != "PreconditionFailed"
                                ):
                                    raise AssertionError(
                                        "delete-objects did not fail with PreconditionFailed"
                                    )
                            else:
                                raise AssertionError(
                                    "delete-objects succeeded with wrong LastModifiedTime"
                                )
                        except (json.JSONDecodeError, TypeError):
                            log.info(
                                "Wrong LastModifiedTime caused CLI/API failure: %s",
                                str(out_err)[:200],
                            )
                    log.info(
                        "Conditional delete with wrong LastModifiedTime check completed"
                    )
                log.info(
                    "Conditional delete-objects with correct LastModifiedTime for all %d objects",
                    config.objects_count,
                )

            log.info("Objects to delete: %s", objects_to_delete)
            response = aws_reusable.delete_objects(
                cli_aws, bucket_name, objects_to_delete, endpoint
            )
            resp = json.loads(response)
            deleted = resp.get("Deleted") or []
            errors = resp.get("Errors") or []

            if errors:
                raise TestExecError(f"delete-objects returned Errors: {errors}")
            if len(deleted) != config.objects_count:
                raise TestExecError(
                    f"Expected {config.objects_count} entries in Deleted, got {len(deleted)}"
                )
            log.info(
                "All %d objects conditionally deleted successfully",
                config.objects_count,
            )

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
        "Conditional delete of multiple objects with ETag or LastModifiedTime (delete-objects API)"
    )

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s", TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="Conditional delete of multiple objects with ETag or LastModifiedTime (delete-objects)"
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
