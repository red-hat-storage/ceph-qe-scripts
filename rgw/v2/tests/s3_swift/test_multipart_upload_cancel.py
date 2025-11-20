"""
test_multipart_upload_cancel.py - Test multipart upload with cancel and download

Usage: test_multipart_upload_cancel.py -c <input_yaml>

Operation:
    Test multipart upload that cancels at a specific part number
    Then complete multipart upload
    Download the completed objects
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback
import warnings

# Suppress urllib3 HeaderParsingError warnings
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")
warnings.filterwarnings("ignore", message=".*HeaderParsingError.*")
# Suppress urllib3 connection warnings in logs - set to CRITICAL to suppress all warnings
urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.setLevel(logging.CRITICAL)
logging.getLogger("urllib3.connectionpool").setLevel(logging.CRITICAL)
logging.getLogger("urllib3.connection").setLevel(logging.CRITICAL)
logging.getLogger("urllib3.util.response").setLevel(logging.CRITICAL)

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
import yaml
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Test multipart upload with cancel and download
    """
    test_info = AddTestInfo("multipart Upload with cancel and download")
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:
        # test case starts
        test_info.started_info()

        # Create users
        all_user_details = s3lib.create_users(config.user_count)
        log.info("multipart upload enabled")

        # Authenticate users
        haproxy = getattr(config, "haproxy", False)

        for each_user in all_user_details:
            auth = reusable.get_auth(each_user, ssh_con, config.ssl, haproxy)
            rgw_conn = auth.do_auth()
            rgw_conn_c = auth.do_auth_using_client()

            # Create buckets
            bucket_names = []
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                bucket_names.append(bucket_name)
                bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)

            # Set objects_count to 1 for this test
            config.objects_count = 1
            config.mapped_sizes = utils.make_mapped_sizes(config)

            # For each bucket, do multipart upload operations
            for bucket_name in bucket_names:
                bucket = s3lib.resource_op(
                    {"obj": rgw_conn, "resource": "Bucket", "args": [bucket_name]}
                )

                # First: multipart upload that breaks at break_at_part_no
                if config.break_at_part_no > 0:
                    for oc, size in list(config.mapped_sizes.items())[
                        :1
                    ]:  # Only first object
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                        log.info(
                            "starting multipart upload that will break at part %s"
                            % config.break_at_part_no
                        )
                        reusable.upload_multipart_with_break(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            each_user,
                            break_at_part_no=config.break_at_part_no,
                        )

                # Second: complete multipart upload (break_at_part_no = 0)
                for oc, size in list(config.mapped_sizes.items())[
                    :1
                ]:  # Only first object
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                    log.info("starting complete multipart upload")
                    reusable.upload_multipart_with_break(
                        s3_object_name,
                        bucket,
                        TEST_DATA_PATH,
                        config,
                        each_user,
                        break_at_part_no=0,  # Complete the upload
                    )

                    # Download the completed object
                    log.info("downloading object: %s" % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    reusable.download_object(
                        s3_object_name, bucket, TEST_DATA_PATH, s3_object_path, config
                    )

        test_info.success_status("test completed")
    except AssertionError as e:
        log.error(e)
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)
    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    test_info = AddTestInfo("test multipart upload cancel")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW Automation")
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
        config.read(ssh_con)
        if yaml_file is None:
            config.user_count = 2
            config.bucket_count = 10
            config.objects_size_range = {"min": 300, "max": 500}
            config.break_at_part_no = 19
        else:
            if hasattr(config, "user_count") and config.user_count:
                pass
            else:
                config.user_count = 2
            if hasattr(config, "bucket_count") and config.bucket_count:
                pass
            else:
                config.bucket_count = 10
            if hasattr(config, "objects_size_range") and config.objects_size_range:
                pass
            else:
                config.objects_size_range = {"min": 300, "max": 500}
            if (
                hasattr(config, "break_at_part_no")
                and config.break_at_part_no is not None
            ):
                pass
            else:
                config.break_at_part_no = 19

        log.info(
            "user_count:%s\n"
            "bucket_count: %s\n"
            "object_min_size: %s\n"
            "break at part number: %s\n"
            % (
                config.user_count,
                config.bucket_count,
                config.objects_size_range,
                config.break_at_part_no,
            )
        )
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
