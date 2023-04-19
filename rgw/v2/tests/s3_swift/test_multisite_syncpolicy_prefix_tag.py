"""
Usage: test_syncpolicy_prefix_tag.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_syncpolicy_prefix_tag.yaml

Operation:
a. On a MS setup, create sync policy with configuration to sync objects having a prefix or tag or both.
b. Write objects having said prefix or tag as mentioned in the config.
"""


import argparse
import json
import logging
import os
import random
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v2.lib.resource_op as s3lib
from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

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
    user_info = s3lib.create_users(config.user_count)

    # Create Zonegroup policy
    log.info("Creating Zone group policy at Enabled state")
    group_id = "global_group"
    reusable.group_operation(group_id, "create", "enabled")
    reusable.flow_operation(group_id, "create")
    reusable.pipe_operation(group_id, "create")

    for user in user_info:
        auth = Auth(user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=bc)
            bucket = reusable.create_bucket(bucket_name, rgw_conn, user)
            log.info(f"Bucket {bucket_name} created")
            prefix = "foo"
            obj_tag = '{"TagSet":[{"Key":"colour", "Value":"red"}]}'
            # Create bucket sync policy
            group_id1 = "group-" + bucket_name
            reusable.group_operation(
                group_id1,
                "create",
                "enabled",
                bucket_name,
            )
            detail = ""
            if config.test_ops["has_prefix"]:
                detail = f"{detail} --prefix={prefix}"
            if config.test_ops["has_tag"]:
                detail = f"{detail} --tags-add={obj_tag}"
            log.info("Creating bucket policy with details")
            pipe_id = reusable.pipe_operation(
                group_id1,
                "create",
                bucket_name=bucket_name,
                policy_detail=detail,
            )
            time.sleep(60)

            log.info(f"Creating objects on bucket: {bucket_name}")
            log.info("s3 objects to create: %s" % config.objects_count)

            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                if config.test_ops["has_prefix"]:
                    # adding prefix
                    s3_object_name = prefix + s3_object_name
                log.info("s3 object name: %s" % s3_object_name)
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info("s3 object path: %s" % s3_object_path)

                if config.test_ops["has_tag"]:
                    obj_tag = ""
                    log.info("upload type: tagged")
                    reusable.upload_object_with_tagging(
                        s3_object_name,
                        bucket,
                        TEST_DATA_PATH,
                        config,
                        user,
                        obj_tag,
                    )
                else:
                    log.info("upload type: normal")
                    reusable.upload_object(
                        s3_object_name, bucket, TEST_DATA_PATH, config, user
                    )

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
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
