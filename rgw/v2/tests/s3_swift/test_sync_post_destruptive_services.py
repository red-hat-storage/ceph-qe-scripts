"""
test_sync_post_destruptive_services.py
          - Test sync consistent with the multisite setup post making rgw service destruptive

Usage : test_sync_post_destruptive_services.py -c <input_yaml>
<input_yaml>
    test_sync_consisitent_post_service_down_up.yaml
    test_sync_consistent_with_node_reboot.yaml
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    is_multisite = utils.is_cluster_multisite()
    if is_multisite:
        out = reusable.check_sync_status(return_while_sync_inprogress=True)
        if str(out) != "sync_progress":
            raise AssertionError("sync status is not in progress!!")
        rgw_service_name = config.test_ops.get("rgw_service_name")

        if config.test_ops.get("test_node_reboot", False):
            reusable.reboot_rgw_nodes(rgw_service_name)
        else:
            reusable.bring_down_all_rgws_in_the_site(rgw_service_name)
            log.info(f"Waiting for 10 min")
            time.sleep(600)
            reusable.bring_up_all_rgws_in_the_site(rgw_service_name)
        retry = config.test_ops.get("sync_retry", 25)
        delay = config.test_ops.get("sync_delay", 60)
        reusable.check_sync_status(retry, delay)

    else:
        log.info("Cluster is not a Multisite!")

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("Test Sync consistency post destruptive rgw services")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Test Sync consistency post destruptive rgw services"
        )
        parser.add_argument(
            "-c",
            dest="config",
            help="Test Sync consistency post destruptive rgw services",
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
