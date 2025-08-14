"""
Usage: test_aws.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_aws_non_ascii.yaml
    configs/test_aws_versioned_bucket_creation.yaml
    configs/test_aws_regular_and_versioned_bucket_creation.yaml
    configs/test_aws_buckets_creation.yaml
    configs/test_complete_multipart_upload_etag_not_empty.yaml
    configs/test_versioned_list_marker.yaml
    configs/test_aws_create_bucket_for_existing_bucket.yaml

Operation:

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

        if config.test_ops.get("verify_etag_for_complete_multipart_upload", False):
            log.info(
                f"Verifying ETag element for complete multipart upload is not empty string"
            )
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                key_name = utils.gen_s3_object_name(bucket_name, oc)
                complete_multipart_upload_resp = aws_reusable.upload_multipart_aws(
                    cli_aws,
                    bucket_name,
                    key_name,
                    TEST_DATA_PATH,
                    endpoint,
                    config,
                )
                if not complete_multipart_upload_resp["ETag"]:
                    raise AssertionError(
                        "Etag not generated during complete multipart upload operation"
                    )
                log.info(f"Download multipart object {key_name}")
                aws_reusable.get_object(cli_aws, bucket_name, key_name, endpoint)

        if config.test_ops.get("verify_non_ascii_character_upload", False):
            log.info(f"Object name and body containing non ascii character upload")
            object_name = "ˍ´--øÆ.txt"
            utils.exec_shell_cmd(f"fallocate -l 1K {object_name}")
            aws_reusable.put_object(cli_aws, bucket_name, object_name, endpoint)
            log.info("Object upload successful")
            aws_reusable.get_object(cli_aws, bucket_name, object_name, endpoint)
            log.info("Object download successful")

        if config.test_ops.get("versioned_list_objects_marker", False):
            log.info("Upload minimum of 3 objects onto a versioned bucket")
            object_names = ["1.txt", "2.txt", "3.txt"]
            for obj in object_names:
                utils.exec_shell_cmd(f"fallocate -l 1K {obj}")
                aws_reusable.put_object(cli_aws, bucket_name, obj, endpoint)
            log.info("Object uplod successful")
            log.info("List bucket with marker object 1.txt")
            marker = "1.txt"
            response = aws_reusable.list_objects(cli_aws, bucket_name, endpoint, marker)
            res_json = json.loads(response)
            log.info("The list should not have the marker object entry")
            for obj in res_json["Contents"]:
                log.info("Key :" + obj["Key"])
                if obj["Key"] == "1.txt":
                    raise Exception(f"Marker is being listed in the list objects")
            log.info("Marker entry not found")

        if config.test_ops.get("create_existing_bucket", False):
            log.info(
                "Verify with and without rgw_bucket_eexist_override set bucket creation"
            )
            log.info(
                f"Bucket {bucket_name} already exist, try craetion of bucket with same name"
            )
            response = json.loads(aws_reusable.list_buckets(cli_aws, endpoint))
            log.info(f"bucket list data {response}")
            log.info(f"Create bucket {bucket_name} which is alreday exist")
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info("BucketAlreadyExists error not seen as expected")
            log.info("set config rgw_bucket_eexist_override for rgw daemon service")
            ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_bucket_eexist_override,
                "True",
                ssh_con,
            )
            s3_reusable.restart_and_wait_until_daemons_up(ssh_con)

            log.info(f"Create existing bucket {bucket_name} post enabling config")
            try:
                resp = utils.exec_shell_cmd(
                    f"/usr/local/bin/aws s3api create-bucket --bucket {bucket_name} --endpoint-url {endpoint}",
                    return_err=True,
                )
            except Exception as e:
                log.info(f"cmd execution failed as expected {resp}")
            log.info(f"cmd execution failed as expected {resp}")
            if "BucketAlreadyExists" not in resp:
                raise TestExecError(
                    "with config, expected error msg BucketAlreadyExists for creation ofexiting bucket for same user"
                )
            log.info(
                "Error seen as expected for creting existing bucket from same owner"
            )
            log.info(
                "reset config rgw_bucket_eexist_override to default for rgw daemon service"
            )
            ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_bucket_eexist_override,
                "False",
                ssh_con,
            )
            s3_reusable.restart_and_wait_until_daemons_up(ssh_con)

        if config.user_remove is True:
            s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test bucket creation through awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 bucket creation using AWS")
        parser.add_argument(
            "-c", dest="config", help="RGW S3 bucket creation using AWS"
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
