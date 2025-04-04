"""
Usage: test_s5cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_s5cmd_basic_op.yaml

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
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s5cmd import auth as s5cmd_auth
from v2.lib.s5cmd.resource_op import S5CMD
from v2.tests.s3_swift import reusable as s3_reusable
from v2.tests.s5cmd import reusable as s5cmd_reusable
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
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        S5CMD(ssl=config.ssl)
        endpoint = s5cmd_reusable.get_endpoint(
            ssh_con, haproxy=config.haproxy, ssl=config.ssl
        )
        s5cmd_auth.do_auth_s5cmd(user)

        if config.test_ops.get("create_bucket", False):
            buckets_name = []
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
                log.info(f"creating bucket with name: {bucket_name}")
                s5cmd_reusable.create_bucket(bucket_name, endpoint)
                log.info(f"Bucket {bucket_name} created sucessfully")
                buckets_name.append(bucket_name)

                if config.test_ops.get("create_object", False):
                    source_file = "obj1_5k.txt"
                    utils.exec_shell_cmd(f"fallocate -l 5K {source_file}")
                    log.info(f"Number of objects to create: {config.objects_count}")
                    objects_name = []
                    for oc, size in list(config.mapped_sizes.items()):
                        object_name = utils.gen_s3_object_name(bucket_name, oc)
                        objects_name.append(object_name)
                        log.info(f"s3 object name: {object_name}")
                        s5cmd_reusable.put_object_via_copy(
                            bucket_name, endpoint, object_name, source_file
                        )

                bucket_stats = utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {bucket_name}"
                )
                data = json.loads(bucket_stats)
                log.info(f"bucket stats for bucket {bucket_name} :{data}")
                objects_num = data["usage"]["rgw.main"]["num_objects"]
                log.info(f"num objects :{objects_num}")
                if int(objects_num) != int(config.objects_count):
                    raise AssertionError(
                        f"Inconsistency found in number of objects to be craeted {config.objects_count} and objects {objects_num} in bucket {bucket_name}"
                    )
                list_response = s5cmd_reusable.list_objects(endpoint, bucket_name)
                log.info(f"objects in bucket :{list_response}")

        if config.user_remove is True:
            s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test basic operation through through s5cmd")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW operation through through s5cmd"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW operation through through s5cmd"
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
