"""
test_s3select_multipart_parquet.py - Test s3-select on multipart uploaded parquet objects
Usage: test_s3select_multipart_parquet.py -c <input_yaml>
<input_yaml>
    test_s3select_multipart_parquet.yaml
Operation:
    create user, bucket
    create large parquet object (~19M) and upload it using multipart upload
    query the object using S3 Select
    verify the query completes successfully without IncompleteRead errors
    This test validates fix for BZ 2118706 and CEPH-83575290
"""

import glob
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

        if config.test_ops.get("create_bucket", False):
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                rgw_s3_client.create_bucket(Bucket=bucket_name)
                bucket = s3lib.resource_op(
                    {
                        "obj": rgw_conn,
                        "resource": "Bucket",
                        "args": [bucket_name],
                    }
                )

                # Add bucket info to IO structure for tracking
                bucket_info = basic_io_structure.bucket(**{"name": bucket_name})
                write_bucket_io_info.add_bucket_info(
                    each_user["access_key"], bucket_info
                )

                output_serialization = {"CSV": {}}

                # Create large parquet object for multipart upload
                # Using row_count to generate ~19M file as mentioned in BZ 2118706
                row_count = config.test_ops.get("parquet_row_count", 100000)
                s3_object_name = f"Key_{bucket_name}_parquet_multipart"
                log.info(f"s3 object name: {s3_object_name}")
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info(f"s3 object path: {s3_object_path}")

                log.info(
                    f"Creating parquet object with {row_count} rows for multipart upload"
                )
                dataset_dict = s3select.create_parquet_object(
                    parquet_obj_path=s3_object_path,
                    row_count=row_count,
                    column_count=4,
                    column_data_types=["int", "float", "string", "timestamp"],
                )

                # Get file size to verify it's large enough for multipart
                file_size = os.path.getsize(s3_object_path)
                log.info(
                    f"Parquet file size: {file_size} bytes ({file_size / (1024*1024):.2f} MB)"
                )

                # Upload using multipart upload
                # We use boto3 multipart upload directly to preserve the parquet file
                log.info("Uploading parquet object using multipart upload")
                try:
                    # Get file info for upload_info
                    file_md5 = utils.get_md5(s3_object_path)
                    data_info = {
                        "name": s3_object_name,
                        "size": file_size,
                        "md5": file_md5,
                    }

                    # Create upload_info required by write_io_info module
                    upload_info = dict(
                        {
                            "access_key": each_user["access_key"],
                            "upload_type": "multipart",
                        },
                        **data_info,
                    )

                    # Initiate multipart upload
                    s3_obj = s3lib.resource_op(
                        {
                            "obj": bucket,
                            "resource": "Object",
                            "args": [s3_object_name],
                        }
                    )
                    mpu = s3lib.resource_op(
                        {
                            "obj": s3_obj,
                            "resource": "initiate_multipart_upload",
                            "args": None,
                            "extra_info": upload_info,
                        }
                    )

                    # Split file for multipart upload
                    split_size = (
                        config.split_size if hasattr(config, "split_size") else 5
                    )
                    mp_dir = os.path.join(TEST_DATA_PATH, s3_object_name + ".mp.parts")
                    log.info(f"mp part dir: {mp_dir}")
                    log.info("making multipart object part dir")
                    mkdir = utils.exec_shell_cmd(f"sudo mkdir -p {mp_dir}")
                    if mkdir is False:
                        raise TestExecError("mkdir failed creating mp_dir_name")

                    utils.split_file(s3_object_path, split_size, mp_dir + "/")
                    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
                    log.info(f"parts_list: {parts_list}")
                    log.info(f"no of parts: {len(parts_list)}")

                    # Upload each part
                    part_number = 1
                    parts_info = {"Parts": []}
                    for each_part in parts_list:
                        log.info(
                            f"uploading part {part_number} of object: {s3_object_name}"
                        )
                        part = mpu.Part(part_number)
                        with open(each_part, "rb") as part_file:
                            part_upload_response = s3lib.resource_op(
                                {
                                    "obj": part,
                                    "resource": "upload",
                                    "kwargs": dict(Body=part_file),
                                }
                            )
                        if part_upload_response is False:
                            raise TestExecError(f"Part {part_number} upload failed")

                        from v2.utils.utils import HttpResponseParser

                        response = HttpResponseParser(part_upload_response)
                        if response.status_code != 200:
                            raise TestExecError(
                                f"Part {part_number} upload failed with status {response.status_code}"
                            )

                        part_info = {
                            "PartNumber": part_number,
                            "ETag": part_upload_response["ETag"],
                        }
                        parts_info["Parts"].append(part_info)
                        if each_part != parts_list[-1]:
                            part_number += 1
                        log.info(f"curr part_number: {part_number}")

                    # Complete multipart upload
                    if len(parts_list) == part_number:
                        log.info(
                            "all parts upload completed, completing multipart upload"
                        )
                        mpu.complete(MultipartUpload=parts_info)
                        log.info("Multipart upload completed successfully")

                    # Cleanup multipart parts directory if configured
                    if (
                        config.local_file_delete
                        if hasattr(config, "local_file_delete")
                        else False
                    ):
                        log.info("deleting local file part")
                        utils.exec_shell_cmd(f"rm -rf {mp_dir}")

                except Exception as e:
                    log.error(f"Multipart upload failed: {e}")
                    raise TestExecError(f"Multipart upload failed: {e}")

                # Verify object exists
                try:
                    rgw_s3_client.head_object(Bucket=bucket_name, Key=s3_object_name)
                    log.info("Object verified to exist after multipart upload")
                except Exception as e:
                    log.error(f"Failed to verify object existence: {e}")
                    raise TestExecError(f"Object verification failed: {e}")

                input_serialization = {
                    "Parquet": {},
                    "CompressionType": "NONE",
                }

                # Query the multipart uploaded parquet object
                query = config.test_ops.get("query", "select * from s3object")
                log.info(
                    f"Executing S3 Select query on multipart parquet object: {query}"
                )

                try:
                    result = s3select.execute_s3select_query(
                        rgw_s3_client,
                        bucket_name,
                        s3_object_name,
                        query,
                        input_serialization,
                        output_serialization,
                    )
                    log.info(
                        f"Query executed successfully. Result length: {len(result)} characters"
                    )
                    log.info(f"Result preview (first 500 chars): {result[:500]}")

                    # Step 3: Verify the result is complete & correct
                    # Verify result is not empty (should have data)
                    if not result or len(result.strip()) == 0:
                        raise TestExecError(
                            "Query returned empty result. Expected data from parquet object."
                        )

                    # Verify result contains multiple rows (indicates complete data, not truncated)
                    result_lines = result.strip().split("\n")
                    log.info(f"Result contains {len(result_lines)} rows")
                    if len(result_lines) < 2:
                        raise TestExecError(
                            f"Query result appears incomplete. Expected multiple rows but got {len(result_lines)} row(s)."
                        )

                    # Verify CSV structure is correct (should have commas separating columns)
                    if "," not in result_lines[0]:
                        raise TestExecError(
                            "Query result does not have expected CSV structure (missing commas)."
                        )

                    # Check for the specific error mentioned in BZ 2118706
                    if "IncompleteRead" in result or "Connection broken" in result:
                        raise TestExecError(
                            f"Query failed with IncompleteRead error as seen in BZ 2118706. Result: {result}"
                        )

                    log.info(
                        "Query completed successfully without IncompleteRead errors"
                    )
                    log.info(
                        "Result verification passed: result is complete and correct"
                    )

                except botocore.exceptions.ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    error_message = str(e)
                    log.error(
                        f"S3 Select query failed with ClientError: {error_code} - {error_message}"
                    )

                    # Check for IncompleteRead in error message
                    if (
                        "IncompleteRead" in error_message
                        or "Connection broken" in error_message
                    ):
                        raise TestExecError(
                            f"Query failed with IncompleteRead error as seen in BZ 2118706: {error_message}"
                        )
                    raise

                except Exception as e:
                    error_message = str(e)
                    log.error(f"S3 Select query failed with exception: {error_message}")

                    # Check for IncompleteRead in error message
                    if (
                        "IncompleteRead" in error_message
                        or "Connection broken" in error_message
                    ):
                        raise TestExecError(
                            f"Query failed with IncompleteRead error as seen in BZ 2118706: {error_message}"
                        )
                    raise

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
    test_info = AddTestInfo("test s3select on multipart parquet objects")
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
