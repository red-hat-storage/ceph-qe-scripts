import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import traceback

import v2.lib.resource_op as s3lib
import yaml
from v2.lib.exceptions import RGWBaseException
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

lib_dir = os.path.abspath(os.path.join(__file__, "../"))
log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config):
    test_info = AddTestInfo("create users")
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_detail_file = os.path.join(lib_dir, "user_details.json")
    try:
        test_info.started_info()
        # create a non-tenanted user
        if config.user_type == "non-tenanted":
            all_users_info = s3lib.create_users(config.user_count)
            with open(user_detail_file, "w") as fout:
                json.dump(all_users_info, fout)
            test_info.success_status("non-tenanted users creation completed")
        else:
            log.info("create tenanted users")
            for i in range(config.user_count):
                tenant_name = "tenant" + str(i)
                all_users_info = s3lib.create_tenant_users(
                    config.user_count, tenant_name
                )
                with open(user_detail_file, "w") as fout:
                    json.dump(all_users_info, fout)
                test_info.success_status("tenanted users creation completed")

        test_info.success_status("test passed")
        sys.exit(0)
    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("user creation failed")
        sys.exit(1)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("user creation failed")
        sys.exit(1)


if __name__ == "__main__":
    test_info = AddTestInfo("user create test")
    test_info.started_info()
    project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
    test_data_dir = "test_data"
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
    args = parser.parse_args()
    yaml_file = args.config
    log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
    configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
    config = Config(yaml_file)
    config.read()
    #        if config.mapped_sizes is None:
    #           config.mapped_sizes = utils.make_mapped_sizes(config)
    with open(yaml_file, "r") as f:
        doc = yaml.safe_load(f)
        config.user_count = doc["config"]["user_count"]
        log.info("user_count:%s\n" % (config.user_count))
    test_exec(config)
