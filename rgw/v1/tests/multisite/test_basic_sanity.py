import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v1.utils.log as log
import v1.utils.utils as utils
import sys
from v1.utils.test_desc import AddTestInfo
from v1.lib.s3.rgw import Config
from v1.lib.s3.rgw import ObjectOps
import v1.lib.s3.rgw as rgw_lib
import argparse
import yaml
import simplejson
from v1.lib.read_io_info import ReadIOInfo
from v1.lib.io_info import AddIOInfo


def test_exec(config):

    add_io_info = AddIOInfo()
    add_io_info.initialize()

    test_info = AddTestInfo('create m buckets, n keys and download')

    try:

        # test case starts

        test_info.started_info()

        with open('user_details') as fout:
            all_user_details = simplejson.load(fout)

        for each_user in all_user_details:

            rgw = ObjectOps(config, each_user)
            buckets = rgw.create_bucket()
            rgw.upload(buckets)
            rgw.download_keys()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError as e:
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

    config.bucket_count = doc['config']['bucket_count']
    config.objects_count = doc['config']['objects_count']
    config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                 'max': doc['config']['objects_size_range']['max']}

    log.info('bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
              % (config.bucket_count, config.objects_count, config.objects_size_range))

    test_exec(config)
