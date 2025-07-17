"""
test_s3select_resharding.py - Test s3-select
Usage: test_s3select_resharding.py -c <input_yaml>
<input_yaml>
    Note: Following yaml can be used
    test_s3select_parquet_resharding.yaml

Operation:
    create user, bucket
    upload parquet files to objects so it triggers a reshard
    manually reshard a bucket with objects uploaded with parquet files
    verify that objects are accessible after resharding
"""

import os
import sys
import time

import botocore

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import traceback

import v2.lib.resource_op as s3lib
import v2.tests.s3_swift.reusables.s3select as s3select
import v2.tests.s3_swift.reusables.s3select_query_generation as query_generation
import v2.utils.utils as utils
import yaml
from v2.lib.exceptions import EventRecordDataError, RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())

    # create user
    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        # authenticate
        auth = reusable.get_auth(each_user, ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()

        # authenticate with s3 client
        rgw_s3_client = auth.do_auth_using_client()

        input_serialization = {
            "Parquet": {},
            "CompressionType": "NONE",
        }

        output_serialization = {"CSV": {}}

        if config.test_ops.get("create_bucket", False):
            objects_created_list = []
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                rgw_s3_client.create_bucket(Bucket=bucket_name)

                if config.test_ops.get("object_type") == "parquet":
                    # uploading data
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        dataset_dict = s3select.create_parquet_object(
                            parquet_obj_path=s3_object_path,
                            row_count=30,
                            column_count=4,
                            column_data_types=["int", "float", "string", "timestamp"],
                        )

                        response = rgw_s3_client.upload_file(
                            s3_object_path, bucket_name, s3_object_name
                        )
                        log.info(f"Uploaded object: {s3_object_name}")

                        objects_created_list.append((s3_object_name, s3_object_path))

                        result = s3select.execute_s3select_query(
                            rgw_s3_client,
                            bucket_name,
                            s3_object_name,
                            "select * from s3object;",
                            input_serialization,
                            output_serialization,
                        )
                        log.info(f"Result: {result}\n")

                        result = s3select.execute_s3select_query(
                            rgw_s3_client,
                            bucket_name,
                            s3_object_name,
                            "select count(*) from s3object;",
                            input_serialization,
                            output_serialization,
                        )
                        log.info(f"Result: {result}\n")

        bucket_stat_cmd = f"radosgw-admin bucket stats --bucket {bucket_name}"
        json_doc = json.loads(utils.exec_shell_cmd(bucket_stat_cmd))
        num_shards_created = json_doc["num_shards"]
        if num_shards_created > 1:
            log.info("Dynamic Re-sharding is successfull!")
        else:
            raise AssertionError("Dynamic Re-sharding FAILED!")

    log.info(objects_created_list)
    log.info("Verify object accessibility post-dynamic reshard")
    for obj_name, _ in objects_created_list:
        reusable.verify_object_accessibility(rgw_s3_client, bucket_name, obj_name)

    if config.sharding_type == "manual":
        log.info("sharding type is manual")
        cmd_exec = utils.exec_shell_cmd(
            "radosgw-admin bucket reshard --bucket=%s --num-shards=%s "
            "--yes-i-really-mean-it" % (bucket_name, config.shards)
        )
        if cmd_exec is False:
            raise TestExecError("manual resharding command execution failed")

        sleep_time = 180
        log.info(f"verification starts after waiting for {sleep_time} seconds")
        time.sleep(sleep_time)
        json_doc = json.loads(
            utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket_name}")
        )
        num_shards_created = json_doc["num_shards"]
        log.info(f"no_of_shards_created: {num_shards_created}")
        if config.shards != num_shards_created:
            raise TestExecError("expected number of shards not created")
        log.info("Expected number of shards created")

        log.info("Verify object accessibility post-manual reshard:")
        for obj_name, _ in objects_created_list:
            reusable.verify_object_accessibility(rgw_s3_client, bucket_name, obj_name)

            result = s3select.execute_s3select_query(
                rgw_s3_client,
                bucket_name,
                obj_name,
                "select * from s3object;",
                input_serialization,
                output_serialization,
            )
            log.info(f"Result: {result}\n")

            result = s3select.execute_s3select_query(
                rgw_s3_client,
                bucket_name,
                obj_name,
                "select count(*) from s3object;",
                input_serialization,
                output_serialization,
            )
            log.info(f"Result: {result}\n")


if __name__ == "__main__":
    test_info = AddTestInfo("test s3select")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 Automation")
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
        ceph_conf = CephConfOp(ssh_con)
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
