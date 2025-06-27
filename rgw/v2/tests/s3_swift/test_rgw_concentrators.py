# test_rgw_concentrators.py (main script)

"""test_rgw_concentrators.py - Test if RGW and HAProxy are on the same node and concentrator behavior

Usage: test_rgw_concentrators.py -c <input_yaml>

<input_yaml>
    test_rgw_concentrators.yaml

Operation:
    Check if RGW service is running
    Check if HAProxy concentrator is configured for RGW
    Verify RGW and HAProxy are running on the same node
    Test RGW service restart and HAProxy reconnection with traffic distribution
    Test stopping one RGW instance and verify traffic rerouting
    Test stopping HAProxy instance and verify traffic stops
    Test restarting HAProxy during traffic and verify even distribution
    Test removing RGW service and verify RGW and HAProxy are removed
    Report status of colocation and concentrator behavior checks
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_concentrators as concentrator_tests
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()


def test_exec(config, ssh_con, rgw_node):
    # Now call the functions from the imported module:
    if config.test_ops.get("rgw_with_concentrators", False):
        log.info("Running RGW and HAProxy colocation check")
        # Call the function and check its return value directly
        if not concentrator_tests.rgw_with_concentrators(
            ssh_con, rgw_node
        ):  # Ensure arguments are passed if the function in concentrator_tests expects them
            raise TestExecError("RGW and HAProxy colocation check failed")

    # Check if concentrator behavior test should be run
    if config.test_ops.get("test_concentrator_behavior", False):
        log.info("Running RGW and HAProxy concentrator behavior test")
        # Pass config, ssh_con, rgw_node to the imported function
        if not concentrator_tests.test_rgw_concentrator_behavior(
            config, ssh_con, rgw_node
        ):
            raise TestExecError("RGW and HAProxy concentrator behavior test failed")

    # Check if single RGW stop test should be run
    if config.test_ops.get("test_single_rgw_stop", False):
        log.info("Running single RGW instance stop test")
        if not concentrator_tests.test_single_rgw_stop(config, ssh_con, rgw_node):
            raise TestExecError("Single RGW instance stop test failed")

    # Check if HAProxy stop test should be run
    if config.test_ops.get("test_haproxy_stop", False):
        log.info("Running HAProxy instance stop test")
        if not concentrator_tests.test_haproxy_stop(config, ssh_con, rgw_node):
            raise TestExecError("HAProxy instance stop test failed")

    # Check if HAProxy restart test should be run
    if config.test_ops.get("test_haproxy_restart", False):
        log.info("Running HAProxy instance restart test during traffic")
        if not concentrator_tests.test_haproxy_restart(config, ssh_con, rgw_node):
            raise TestExecError("HAProxy instance restart test failed")

    # Check if RGW service removal test should be run
    if config.test_ops.get("test_rgw_service_removal", False):
        log.info("Running RGW service removal test")
        if not concentrator_tests.test_rgw_service_removal(config, ssh_con, rgw_node):
            raise TestExecError("RGW service removal test failed")

    if not (
        config.test_ops.get("rgw_with_concentrators", False)
        or config.test_ops.get("test_concentrator_behavior", False)
        or config.test_ops.get("test_single_rgw_stop", False)
        or config.test_ops.get("test_haproxy_stop", False)
        or config.test_ops.get("test_haproxy_restart", False)
        or config.test_ops.get("test_rgw_service_removal", False)
    ):
        log.info("Skipping RGW and HAProxy tests as per configuration")

    # Check for any crashes during execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("Ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "check RGW and HAProxy colocation and concentrator behavior"
    )
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        usage = """
        Usage:
          python3 test_rgw_concentrators.py -c test_rgw_concentrators.yaml
        """
        parser = argparse.ArgumentParser(description=usage)
        parser.add_argument("-c", dest="config", help=usage)
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
        # Corrected the local IP check for remote connection
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read(ssh_con)

        test_exec(config, ssh_con, rgw_node)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
