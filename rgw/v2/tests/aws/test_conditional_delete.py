"""
Usage: test_conditional_delete.py -c <input_yaml>
Polarion ID : 
<input_yaml>
    Note: Following yaml can be used
    configs/test_cond_delete_etag.yaml
    configs/test_cond_delete_lmt.yaml
    configs/test_cond_delete_size.yaml
    configs/test_cond_delete_correct_etag_and_incorrcet_size.yaml
    configs/test_cond_delete_correct_size_and_incorrcet_lmt.yaml
    configs/test_cond_delete_incorrect_etag_and_correct_lmt.yaml
    configs/test_cond_delete_all_correct.yaml
    configs/test_cond_put_if_none_match.yaml
    configs/test_cond_put_if_match.yaml
    configs/test_cond_put_if_none_match_ver.yaml
    configs/test_cond_put_if_match_ver.yaml

Operation:
Conditional delete scenarios
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

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)
        incorrect = False
        gc_verify = True

        for bc in range(config.bucket_count):
            if config.test_ops.get("regular_and_version", False):
                bkt_suffix = bc + 1
                reg_bucket_name = config.test_ops["reg_bucket_name"] + f"{bkt_suffix}"
                ver_bucket_name = config.test_ops["ver_bucket_name"] + f"{bkt_suffix}"
                aws_reusable.create_bucket(cli_aws, reg_bucket_name, endpoint)
                aws_reusable.create_bucket(cli_aws, ver_bucket_name, endpoint)
                log.info(f"Bucket {reg_bucket_name} and {ver_bucket_name} created")
                log.info(f"bucket versioning enabled on bucket: {ver_bucket_name}")
                aws_reusable.put_get_bucket_versioning(
                    cli_aws, ver_bucket_name, endpoint
                )

            else:
                if config.test_ops.get("bucket_name", False):
                    bkt_suffix = bc + 1
                    bucket_name = config.test_ops["bucket_name"] + f"{bkt_suffix}"
                else:
                    bucket_name = utils.gen_bucket_name_from_userid(
                        user_name, rand_no=bc
                    )
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                log.info(f"Bucket {bucket_name} created")

                if config.test_ops.get("enable_version", False):
                    log.info(f"bucket versioning test on bucket: {bucket_name}")
                    aws_reusable.put_get_bucket_versioning(
                        cli_aws, bucket_name, endpoint
                    )
                object_name = "testobj"
                utils.exec_shell_cmd(f"fallocate -l 6M {object_name}")
                aws_reusable.put_object(cli_aws, bucket_name, object_name, endpoint)
            if config.test_ops.get("conditional_put_if_none_match", False):
                if config.test_ops.get("enable_version", False):
                    gc_verify = False
                log.info("Validate conditional Put operations with if-none-match")
                object_name = "testobj-new"
                utils.exec_shell_cmd(f"fallocate -l 6M {object_name}")
                log.info("Validate conditional put with if-none-match * for 1st upload")
                aws_reusable.conditional_put_object(
                    cli_aws, bucket_name, object_name, endpoint
                )
                log.info("Validate conditional put with if-none-match * for 2nd upload")
                err = aws_reusable.conditional_put_object(
                    cli_aws, bucket_name, object_name, endpoint, return_err=True
                )
                if "argument of type 'NoneType' is not iterable" not in err:
                    raise AssertionError(f"2nd time upload of same object should fail!")
            if config.test_ops.get("conditional_put_if_match", False):
                if config.test_ops.get("enable_version", False):
                    gc_verify = False
                log.info("Validate conditional Put operations with if-match")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = version_list["Versions"][0]["ETag"].split('"')[1]
                incorrect_etag = etag[:-1]
                log.info("Validate conditional put with if-match with incorret etag")
                err = aws_reusable.conditional_put_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    etag=incorrect_etag,
                    return_err=True,
                )
                if "argument of type 'NoneType' is not iterable" not in err:
                    raise AssertionError(
                        f"conditional put with if-match with incorret etag should fail"
                    )
                log.info("Validate conditional put with if-match with correct Etag")
                aws_reusable.conditional_put_object(
                    cli_aws, bucket_name, object_name, endpoint, etag=etag
                )

            if config.test_ops.get("conditional_delete_with_etag", False):
                log.info("delete object using matching ETAG")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = version_list["Versions"][0]["ETag"].split('"')[1]
                log.info("Conditional delete object with incorrect Etag")
                incorrect_etag = etag[:-1]
                out = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    etag=incorrect_etag,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {out}")
                if not out:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect ETag"
                    )

                log.info("Conditional delete object with correct Etag")
                out = aws_reusable.conditional_delete_object(
                    cli_aws, bucket_name, object_name, endpoint, etag=etag
                )
                log.info(f"Conditional delete response is {out}")
            if config.test_ops.get("conditional_delete_with_lastmodifiedtime", False):
                log.info("delete object using matching Last Modified time")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                lmt = version_list["Versions"][0]["LastModified"].split(".")[0]
                log.info("Conditional delete object with incorrect Last modified time")
                incorrect_lmt = lmt[:-1]
                out = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    last_modified_time=incorrect_lmt,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {out}")
                if not out:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect Last modified time"
                    )

                log.info("Conditional delete object with correct Last modified time")
                out = aws_reusable.conditional_delete_object(
                    cli_aws, bucket_name, object_name, endpoint, last_modified_time=lmt
                )
                log.info(f"Conditional delete response is {out}")
            if config.test_ops.get("conditional_delete_with_size", False):
                log.info("delete object using matching size")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                size = version_list["Versions"][0]["Size"]
                log.info("Conditional delete object with incorrect Size")
                incorrect_size = str(size)[:-1]
                out = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    size=incorrect_size,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {out}")
                if not out:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect size"
                    )

                log.info("Conditional delete object with correct size")
                out = aws_reusable.conditional_delete_object(
                    cli_aws, bucket_name, object_name, endpoint, size=size
                )
                log.info(f"Conditional delete response is {out}")
            if config.test_ops.get("conditional_delete_with_multi_condition", False):
                log.info("delete object using combination of conditions")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = None
                lmt = None
                size = None
                if config.test_ops.get("size", False):
                    size = version_list["Versions"][0]["Size"]
                    if config.test_ops.get("size")[1] == "correct":
                        size = size
                    else:
                        incorrect = True
                        size = str(size)[:-1]
                if config.test_ops.get("etag", False):
                    etag = version_list["Versions"][0]["ETag"].split('"')[1]
                    if config.test_ops.get("etag")[1] == "correct":
                        etag = etag
                    else:
                        incorrect = True
                        etag = etag[:-1]
                if config.test_ops.get("last_modified_time", False):
                    lmt = version_list["Versions"][0]["LastModified"].split(".")[0]
                    if config.test_ops.get("last_modified_time")[1] == "correct":
                        lmt = lmt
                    else:
                        incorrect = True
                        lmt = lmt[:-1]

                err = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    etag=etag,
                    last_modified_time=lmt,
                    size=size,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {err}")
                if not err and incorrect:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect conditions"
                    )
            if not incorrect and gc_verify:
                aws_reusable.validate_gc()
        if config.user_remove is True:
            s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("Test Conditional Put and Delete using AWS")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Conditional Put and Delete using AWS"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW Conditional Put and Delete using using AWS"
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
