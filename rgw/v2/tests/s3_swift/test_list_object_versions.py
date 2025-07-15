import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import json
import logging
import time
import traceback

import botocore
from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift.reusables import (
    upload_object_via_s3client as put_object_s3client,
)
from v2.tests.s3_swift.reusables import list_fake_mp as bucket_list_incomplete_mp
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger()
TEST_DATA_PATH = None
password = "32characterslongpassphraseneeded".encode("utf-8")
encryption_key = hashlib.md5(password).hexdigest()


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_name = (config.test_ops.get("user_name"), None)
    user_names = [user_name] if type(user_name) != list else user_name
    if config.test_ops.get("user_name", False):
        user_info = resource_op.create_users(
            no_of_users_to_create=config.user_count,
            user_names=user_names,
        )
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl)
        endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
        aws_auth.do_auth_aws(user)
        auth = reusable.get_auth(user, ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        s3_client = auth.do_auth_using_client()

        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                log.info(f"Bucket {bucket_name} created")

                if config.test_ops.get("enable_version", False):
                    log.info(f"enable bucket versioning on bucket: {bucket_name}")
                    aws_reusable.put_get_bucket_versioning(
                        cli_aws, bucket_name, endpoint
                    )

                if config.test_ops.get("create_object", None) is True:
                    if config.test_ops.get("large_objects", None) is True:
                        object_args = list(config.mapped_sizes.items())
                        with ThreadPoolExecutor() as tp:
                            futures = [
                                tp.submit(
                                    lambda oc, size: (
                                        setattr(config, "obj_size", size),
                                        log.info(
                                            f"uploading object: {utils.gen_s3_object_name(bucket_name, oc)}"
                                        ),
                                        put_object_s3client.upload_object_via_s3client(
                                            s3_client,
                                            bucket_name,
                                            utils.gen_s3_object_name(bucket_name, oc),
                                            TEST_DATA_PATH,
                                            config,
                                            user,
                                        ),
                                    ),
                                    oc,
                                    size,
                                )
                                for oc, size in object_args
                            ]
                            for future in as_completed(futures):
                                try:
                                    future.result()
                                except Exception as e:
                                    log.error(f"Object upload failed: {e}")
                                    raise

    # List all object versions using your reusable method
    try:
        version_list = aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
    except ClientError as err:
        raise AssertionError(f"Failed to perform object version listing: {err}")

    # Check for any crashes during the execution
    crash_info = (
        reusable.check_for_crash()
    )
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Listing objects of a bucket via radosgw-admin and boto")
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
