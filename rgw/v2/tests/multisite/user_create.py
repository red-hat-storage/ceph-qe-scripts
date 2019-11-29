import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import RGWService
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import time
import json


def test_exec(config):
    test_info = AddTestInfo('create users')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    try:
        test_info.started_info()
        all_users_info = s3lib.create_users(config.user_count, config.cluster_name)
        with open('user_details', 'w') as fout:
            json.dump(all_users_info, fout)
        test_info.success_status('user creation completed')
        sys.exit(0)
    except Exception as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('user creation failed')
        sys.exit(1)
    except TestExecError as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('user creation failed')
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RGW Automation')
    parser.add_argument('-c', dest="config",
                        help='RGW Test yaml configuration')
    parser.add_argument('-p', dest="port", default='8080',
                        help='port number where RGW is running')
    args = parser.parse_args()
    yaml_file = args.config
    config = Config()
    if yaml_file is None:
        config.cluster_name = 'ceph'
        config.user_count = 2
    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.cluster_name = doc['config']['cluster_name']
        config.user_count = doc['config']['user_count']
    log.info('user_count:%s\n' % (
        config.user_count))
    test_exec(config)
