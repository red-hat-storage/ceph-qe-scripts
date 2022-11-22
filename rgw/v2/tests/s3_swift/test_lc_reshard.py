"""
Test bucket lifecycle reshard (BB scenario)
Usage: test_lc_reshard.py -c configs/<input-yaml>
where : <input-yaml> are test_lc_reshard.yaml
Operation:
-Create a user and atleast 10 buckets and setlifecycle to it
-Check "radosgw-admin lc list" and note all the LC shards assigned to the buckets
-Remove the assigned LC shards using "rados rm"
-update "rgw_lc_max_objs to 40 (default= 32)"
-Run "radosgw-admin lc reshard fix" should create an entry for removed LC shards
-Remove the user at successful completion
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import LifecycleConfigError, RGWBaseException
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        # create buckets
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
                life_cycle_rule = {"Rules": config.lifecycle_conf}
                reusable.put_bucket_lifecycle(
                    bucket, rgw_conn, rgw_conn2, life_cycle_rule
                )

    log.info("Checking the LC shard IDs assigned to all the buckets")
    lc_data = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
    shard_data = []
    for shard_num in lc_data:
        shard_data.append(shard_num["shard"])

    # Check whether there are 32 lc shards
    numlc = utils.exec_shell_cmd("rados ls -p default.rgw.log -N lc | wc -l")
    log.info(f"Number of LC shards is {numlc}")
    if int(numlc.strip()) != 32:
        raise LifecycleConfigError("Number of LC shards not 32 by default")

    log.info("Remove the LC shards currently assigned to buckets")
    for data in shard_data:
        op = utils.exec_shell_cmd(f"rados rm -p default.rgw.log -N lc {data}")

    # Check there are less than 32 LC shards
    numlc = utils.exec_shell_cmd("rados ls -p default.rgw.log -N lc | wc -l")
    if int(numlc.strip()) >= 32:
        raise LifecycleConfigError("LC shards not deleted")

    # LC list should be empty
    lc_data = utils.exec_shell_cmd("radosgw-admin lc list")
    if lc_data == "":
        log.info("LC list empty as expected")

    # Run radosgw-admin lc reshard fix
    op = utils.exec_shell_cmd("radosgw-admin lc reshard fix")

    time.sleep(5)

    numlc = utils.exec_shell_cmd("rados ls -p default.rgw.log -N lc | wc -l")
    if int(numlc.strip()) != 32:
        raise LifecycleConfigError("LC shards not created back after reshard fix")

    lc_data = utils.exec_shell_cmd("radosgw-admin lc list")
    if lc_data:
        log.info("LC list populated back")
    else:
        raise LifecycleConfigError("LC list not populated back after reshard fix")


if __name__ == "__main__":

    test_info = AddTestInfo("LC shard test")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Test the RGW LC reshard fix command"
        )
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

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
