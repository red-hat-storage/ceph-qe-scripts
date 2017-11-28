import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import lib.s3.rgw as rgw_lib
from lib.s3.rgw import Config
import utils.log as log
from utils.test_desc import AddTestInfo
import argparse
import yaml
import json
from lib.io_info import AddIOInfo

def test_exec(config):

    test_info = AddTestInfo('create users')

    add_io_info = AddIOInfo()
    add_io_info.initialize()

    try:
        test_info.started_info()

        all_user_details = rgw_lib.create_users(config.user_count, config.cluster_name)

        # dump the list of users into a file

        with open('user_details', 'w') as fout:
            json.dump(all_user_details, fout)

        test_info.success_status('user creation completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('user creation failed: %s' % e)
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