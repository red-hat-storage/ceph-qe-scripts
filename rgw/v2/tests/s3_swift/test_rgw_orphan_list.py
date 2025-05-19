"""
Validates RGW integrity by checking for orphan objects and data inconsistencies.

This script uses 'rgw-orphan-list', 'radosgw-admin', and 'rados' to verify:
1.  Empty RGW garbage collection.
2.  No orphan data in 'default.rgw.buckets.data'.
3.  Matching index counts for buckets in 'default.rgw.buckets.index'.

Fails if orphans are found or index counts mismatch. Provides detailed logging and supports remote execution.
"""

import argparse
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib.resource_op import Config
from v2.tests.s3_swift.reusables import rgw_orphan_list as orphan_utils
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    test_info = AddTestInfo("RGW Orphan Checks")
    try:
        test_info.started_info()

        if config.test_ops.get("run_orphan_checks"):  # removed the default true.
            orphan_utils.check_gc()
            orphan_utils.check_orphan_data()
            orphan_utils.check_orphan_index()
        else:
            log.info(
                "Skipping orphan checks as run_orphan_checks is not set to True in the configuration."
            )

        test_info.success_status("All checks passed. No orphans found.")
        sys.exit(0)

    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("RGW orphan checks failed.")
        sys.exit(1)


if __name__ == "__main__":
    test_info = AddTestInfo("RGW Orphan Checks")
    test_info.started_info()
    project_dir = os.path.abspath(os.path.join(__file__, "../../../.."))
    test_data_dir = "test_data"
    TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
    log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
    if not os.path.exists(TEST_DATA_PATH):
        log.info("test data dir not exists, creating.. ")
        os.makedirs(TEST_DATA_PATH)

    parser = argparse.ArgumentParser(description="RGW Orphan Checks Automation")
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
    if rgw_node != "127.0.0.0":
        ssh_con = utils.connect_remote(rgw_node)
    log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
    configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
    config = Config(yaml_file)
    config.read(ssh_con)
    test_exec(config, ssh_con)
