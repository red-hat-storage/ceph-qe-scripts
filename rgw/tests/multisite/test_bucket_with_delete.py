import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import ObjectOps
import lib.s3.rgw as rgw_lib
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.s3.rgw import Config
import argparse
import yaml
import simplejson
import time
from lib.read_io_info import ReadIOInfo
from lib.io_info import AddIOInfo


def test_exec(config):

    add_io_info = AddIOInfo()
    add_io_info.initialize()

    test_info = AddTestInfo('create m buckets, n objects and delete')

    try:

        # test case starts

        test_info.started_info()

        with open('user_details') as fout:
            all_user_details = simplejson.load(fout)

        for each_user in all_user_details:
            add_io_info.add_user_info(**{'user_id': each_user['user_id'],
                                         'access_key': each_user['access_key'],
                                         'secret_key': each_user['secret_key']})


        for each_user in all_user_details:

            rgw = ObjectOps(config, each_user)

            buckets = rgw.create_bucket()
            rgw.upload(buckets)

            rgw.delete_keys()
            time.sleep(15)
            rgw.delete_bucket()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test failed: %s' % e)
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
    config.port = args.port
    if yaml_file is None:
        config.bucket_count = 2
        config.objects_count = 10
        config.objects_size_range = {'min': 10, 'max': 50}
    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.bucket_count = doc['config']['bucket_count']
        config.objects_count = doc['config']['objects_count']
        config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                     'max': doc['config']['objects_size_range']['max']}

    log.info('bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (config.bucket_count, config.objects_count, config.objects_size_range))

    test_exec(config)
