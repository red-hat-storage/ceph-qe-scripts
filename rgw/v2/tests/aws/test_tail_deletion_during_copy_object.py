"""
Usage: test_tail_deletion_during_copy_object.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    ceph-qe-scripts/rgw/v2/tests/aws/configs/test_tail_deletion_during_copy_object_1g.yaml
    ceph-qe-scripts/rgw/v2/tests/aws/configs/test_tail_deletion_during_copy_object_10m.yaml
    ceph-qe-scripts/rgw/v2/tests/aws/configs/test_tail_deletion_during_copy_object_6m.yaml
    

Operation:
    Verifies tail object not deleted post performing copy_objject
    GC process
    object download is performed
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
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable
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
    s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_name = (config.test_ops.get("user_name"), None)
    user_names = [user_name] if type(user_name) != list else user_name
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    for user in user_info:
        user_name = user["user_id"]
        ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
        s3_auth.do_auth(user, ip_and_port)
        cli_aws = AWS(ssl=config.ssl)
        endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
        aws_auth.do_auth_aws(user)
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            s3cmd_reusable.create_bucket(bucket_name)
            log.info(f"Bucket {bucket_name} created")
            log.info("Upload a file")
            file_size = config.test_ops.get("file_size", 1024)
            cmd = f"fallocate -l {file_size} object1"
            utils.exec_shell_cmd(cmd)
            cmd = f"{s3cmd_path} put object1 s3://{bucket_name}/object1"
            utils.exec_shell_cmd(cmd)
            utils.exec_shell_cmd(f"{s3cmd_path} ls s3://{bucket_name}")
            out1 = aws_reusable.copy_object(cli_aws, bucket_name, "object1", endpoint)
            aws_reusable.perform_gc_process_and_list()
            out2 = aws_reusable.get_object(cli_aws, bucket_name, "object1", endpoint)
            md5sum_out = utils.exec_shell_cmd(f"md5sum 'out_object'").split(" ")[0]
            md5sum_in = utils.exec_shell_cmd(f"md5sum 'object1'").split(" ")[0]
            if md5sum_out != md5sum_in:
                raise AssertionError("md5sum mismatch with downloaded object")
        reusable.remove_user(user)


if __name__ == "__main__":

    test_info = AddTestInfo(
        "Test tail object not deleted post performing copy_objject through awscli"
    )

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Test tail object not deleted post performing copy_objject using AWS"
        )
        parser.add_argument(
            "-c",
            dest="config",
            help="Test tail object not deleted post performing copy_objject",
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
