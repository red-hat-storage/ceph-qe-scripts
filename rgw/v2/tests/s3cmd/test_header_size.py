"""
test_header_size - Test to verify header size in Beast front end using s3cmd

Usage: test_header_size.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_header_size.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Performs object upload with header
    Verify object for its header
"""


import argparse
import json
import logging
import os
import random
import sys
import traceback
from string import ascii_lowercase, ascii_uppercase, digits

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3cmd import reusable as s3cmd_reusable
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
    s3cmd = "/home/cephuser/venv/bin/s3cmd"
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    for user in user_info:
        user_name = user["user_id"]

        ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
        s3_auth.do_auth(user, ip_and_port)

        if not config.header_size:
            return

        log.info(f"Number of buckets to create: {config.bucket_count}")
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            s3cmd_reusable.create_bucket(bucket_name)
            log.info(f"Bucket {bucket_name} created")
            utils.exec_shell_cmd(f"fallocate -l 25m obj25m")
            header = "".join(
                random.choices(ascii_uppercase + digits + ascii_lowercase, k=8192)
            )
            log.info(
                "Generate header within default max_header_size(16384) i.e, 8192(16384/2)"
            )
            obj_name = utils.gen_s3_object_name(bucket_name, 1)
            cmd = f"{s3cmd} put obj25m --add-header='X-AMZ-Metadata':{header} s3://{bucket_name}/{obj_name}"
            rc = utils.exec_shell_cmd(cmd)

            if rc is False:
                raise AssertionError(
                    "Failed to upload object, since given header size is greater than or equal to max_header_size"
                )

            # Uploaded the object in bucket
            bucket_info = utils.exec_shell_cmd(
                f"radosgw-admin object stat --bucket {bucket_name} --object {obj_name}"
            )

            if bucket_info is False:
                raise AssertionError(
                    f"Failed to get object data: {obj_name} from bucket :{bucket_name}"
                )

            data = json.loads(bucket_info)
            if "user.rgw.x-amz-metadata" not in data["attrs"].keys():
                raise AssertionError("Key not found")
            if header != data["attrs"]["user.rgw.x-amz-metadata"]:
                raise AssertionError(
                    "Object header does not match the given metadata header"
                )

            # negative scenario
            header = "".join(
                random.choices(ascii_uppercase + digits + ascii_lowercase, k=16384)
            )
            log.info(
                "Generate random character of size set to default max_header_size: 16384"
            )
            new_obj_name = utils.gen_s3_object_name(bucket_name, 2)
            cmd = f"{s3cmd} put obj25m --add-header='X-AMZ-Metadata':{header} s3://{bucket_name}/{new_obj_name}"
            rc = utils.exec_shell_cmd(cmd)

            if rc:
                raise AssertionError(
                    "Expected to fail but succeeded, since metadata header is equal to greater than default max_header_size"
                )


if __name__ == "__main__":

    test_info = AddTestInfo("test bucket stats consistency")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 bucket stats using s3cmd")
        parser.add_argument("-c", dest="config", help="RGW S3 bucket stats using s3cmd")
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
