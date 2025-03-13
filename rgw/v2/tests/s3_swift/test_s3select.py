"""
test_s3select.py - Test s3-select
Usage: test_s3select.py -c <input_yaml>
<input_yaml>
    Note: any one of these yamls can be used
    test_s3select_query_gen_csv_depth1.yaml
    test_s3select_query_gen_csv_depth2.yaml
Operation:
    create user, bucket
    create csv object and upload it
    generate queries with/without expected result
    execute the queries and check for rgw crashes and validate the results
"""

import os
import sys
import time

import botocore

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
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
        auth = Auth(each_user, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn = auth.do_auth()

        # authenticate with s3 client
        rgw_s3_client = auth.do_auth_using_client()

        if config.test_ops.get("create_bucket", False):
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                rgw_s3_client.create_bucket(Bucket=bucket_name)

                output_serialization = {"CSV": {}}

                # create objects
                if config.test_ops.get("object_type") == "csv":
                    # uploading data
                    csv_matrix, csv_string = s3select.create_csv_object(
                        row_count=30,
                        column_count=4,
                        column_data_types=["int", "float", "string", "timestamp"],
                    )
                    s3_object_name = f"Key_{bucket_name}_csv"
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    with open(s3_object_path, "w") as fp:
                        fp.write(csv_string)

                    response = rgw_s3_client.put_object(
                        Bucket=bucket_name, Key=s3_object_name, Body=csv_string
                    )
                    log.info(f"upload object response: {response}")

                    input_serialization = {
                        "CSV": {
                            "RecordDelimiter": "\n",
                            "FieldDelimiter": ",",
                            "QuoteEscapeCharacter": "\\",
                            "QuoteCharacter": '"',
                            "FileHeaderInfo": "NONE",
                        },
                        "CompressionType": "NONE",
                    }

                if config.test_ops.get("object_type") == "parquet":
                    # uploading data
                    s3_object_name = f"Key_{bucket_name}_parquet"
                    log.info(f"s3 object name: {s3_object_name}")
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info(f"s3 object path: {s3_object_path}")
                    dataset_dict = s3select.create_parquet_object(
                        parquet_obj_path=s3_object_path,
                        row_count=30,
                        column_count=4,
                        column_data_types=["int", "float", "string", "timestamp"],
                    )

                    response = rgw_s3_client.upload_file(
                        s3_object_path, bucket_name, s3_object_name
                    )
                    log.info(f"upload object response: {response}")

                    input_serialization = {
                        "Parquet": {},
                        "CompressionType": "NONE",
                    }

                if config.test_ops.get("query_generation", False):
                    depth = config.test_ops.get("depth", 1)
                    s3_queries_path = f"/home/cephuser/s3select_gen_query_{config.test_ops.get('object_type')}_depth{depth}.yaml"
                    queries = query_generation.get_queries(
                        s3_object_name, s3_object_path, depth, s3_queries_path
                    )

                log.info(input_serialization)

                for query in queries["queries"]:
                    try:
                        log.info(f"Executing query{query['id']}: {query['query']}")
                        result = s3select.execute_s3select_query(
                            rgw_s3_client,
                            bucket_name,
                            s3_object_name,
                            query["query"],
                            input_serialization,
                            output_serialization,
                        )
                        log.info(f"Result: {result}\n")
                        query["result"] = result
                        query["status"] = "pass"
                    except botocore.exceptions.ClientError as e:
                        log.error(e)
                        query["exception"] = e
                        query["status"] = "fail"
                        crash_info = reusable.check_for_crash()
                        if crash_info:
                            raise TestExecError("ceph daemon crash found!")

                # writing queries output to yaml file
                log.info(f"writing queries output to yaml file: {s3_queries_path}")
                with open(s3_object_path, "w") as yaml_file:
                    yaml_file.write(yaml.dump(queries, default_flow_style=False))

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    if config.user_remove:
        for i in all_users_info:
            reusable.remove_user(i)


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

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
