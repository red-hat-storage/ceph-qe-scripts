import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import Config
import utils.log as log
from lib.s3.rgw import RGW
import sys
from utils.test_desc import AddTestInfo
import lib.s3.rgw as rgw_lib
import argparse
import yaml


def test_exec(config):

    test_info = AddTestInfo('create m buckets, n objects and delete')

    try:

        # test case starts

        test_info.started_info()

        all_user_details = rgw_lib.create_users(config.user_count)

        for each_user in all_user_details:

            each_user['port'] = config.port

            rgw = RGW(each_user)

            rgw.create_bucket_with_keys(config)

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test failed: %s' % e)
        sys.exit(1)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='RGW Automation')

    parser.add_argument('-c', dest="config", default='yamls/config.yaml',
                        help='RGW Test yaml configuration')

    parser.add_argument('-p', dest="port", default='8080',
                        help='port number where RGW is running')

    args = parser.parse_args()

    yaml_file = args.config

    with open(yaml_file, 'r') as f:
        doc = yaml.load(f)

    config = Config()

    config.user_count = doc['config']['user_count']
    config.bucket_count = doc['config']['bucket_count']
    config.objects_count = doc['config']['objects_count']
    config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                 'max': doc['config']['objects_size_range']['max']}

    config.port = args.port

    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             'port: %s\n'
             % (config.user_count, config.bucket_count, config.objects_count, config.objects_size_range, config.port))

    test_exec(config)
