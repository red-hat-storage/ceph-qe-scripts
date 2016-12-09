import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import Config
from lib.rgw_config_opts import AddToCephConf, ConfigOpts
from lib.admin import QuotaMgmt
from utils.utils import RGWService
import utils.log as log
import socket
from lib.s3.rgw import ObjectOps
import sys
from utils.test_desc import AddTestInfo
import lib.s3.rgw as rgw_lib
import argparse
import yaml


def test_exec(config):

    test_info = AddTestInfo('create m buckets, n objects and delete')

    try:

        test_info.started_info()

        rgw_service = RGWService()
        quota_mgmt = QuotaMgmt()
        test_config = AddToCephConf()

        if config.shards:
            test_config.set_to_ceph_conf('global', ConfigOpts.rgw_override_bucket_index_max_shards, config.shards)

            rgw_service.restart()

            no_of_shards_for_each_bucket = int(config.shards) * int(config.bucket_count)

        all_user_details = rgw_lib.create_users(config.user_count)

        for each_user in all_user_details:

            if config.max_objects:
                quota_mgmt.set_bucket_quota(each_user['user_id'], config.max_objects)
                quota_mgmt.enable_bucket_quota(each_user['user_id'])

            rgw = ObjectOps(config, each_user)

            buckets = rgw.create_bucket()
            rgw.upload(buckets)

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

    # parser.add_argument('-p', dest="port", default='8080',
    #                  help='port number where RGW is running')

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

    config.shards = doc['config']['shards']
    config.max_objects = doc['config']['max_objects']

    print 'shard value: %s' % config.shards

    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             'shards: %s\n'
             'max_objects: %s\n'
             % (config.user_count, config.bucket_count, config.objects_count, config.objects_size_range, config.shards,
                config.max_objects))

    test_exec(config)
