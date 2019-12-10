import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v1.utils.log as log
import sys
from v1.utils.test_desc import AddTestInfo
from v1.lib.s3.rgw import Config
from v1.lib.s3.rgw import ObjectOps
import v1.lib.s3.rgw as rgw_lib
import argparse
import yaml
from v1.lib.io_info import AddIOInfo


# no of users 2 and not more.

def test_exec_read(config):
    """
    config.bucket_count = 3
    config.objects_count = 3
    config.objects_size_range = {'min': 50, 'max': 100}
    """
    grants = {'permission': 'READ', 'user_id': None, 'recursive': True}
    test_info = AddTestInfo('Test with read permission on buckets')
    add_io_info = AddIOInfo()
    add_io_info.initialize()
    try:
        # test case starts
        test_info.started_info()
        all_user_details = rgw_lib.create_users(config.user_count)
        user1 = all_user_details[0]
        log.info('user1: %s' % user1)
        user2 = all_user_details[1]
        log.info('user2: %s' % user2)
        u1 = ObjectOps(config, user1)
        u2 = ObjectOps(config, user2)
        u2_canonical_id = u2.canonical_id
        log.info('canonical id of u2: %s' % u2_canonical_id)
        grants['user_id'] = u2_canonical_id
        u1.grants = None
        u1.create_bucket()
        u1.set_bucket_properties()
        u2.bucket_names = u1.bucket_names
        u2.buckets_created = u1.buckets_created
        u2.grants = None
        u2.set_bucket_properties()
        # set permissions and read
        u1.grants = grants
        u1.set_bucket_properties()
        u2.bucket_names = u1.bucket_names
        u2.buckets_created = u1.buckets_created
        u2.grants = None
        u2.set_bucket_properties()
        test_info.success_status('test completed')
    except AssertionError as e:
        log.error(e)
        test_info.failed_status('test failed: %s' % e)
        sys.exit(1)


def test_exec_write(config):
    test_info = AddTestInfo('test with write persmission on objects and buckets')
    try:
        # test case starts
        test_info.started_info()
        all_user_details = rgw_lib.create_users(config.user_count)
        user1 = all_user_details[0]
        log.info('user1: %s' % user1)
        user2 = all_user_details[1]
        log.info('user2: %s' % user2)
        u1 = ObjectOps(config, user1)
        u2 = ObjectOps(config, user2)
        u2_canonical_id = u2.canonical_id
        log.info('canonical id of u2: %s' % u2_canonical_id)
        grants = {'permission': 'READ', 'user_id': None, 'recursive': True}
        log.info('write persmission are not set')
        grants['user_id'] = u2_canonical_id
        u1.grants = grants
        u1.create_bucket()
        u1.set_bucket_properties()
        u2.bucket_names = u1.bucket_names
        u2.buckets_created = u1.buckets_created
        u2.json_file_upload = u1.json_file_upload
        u2.json_file_download = u1.json_file_download
        u2.grants = None
        buckets = u2.set_bucket_properties()
        uploaded = u2.upload(buckets)
        if not uploaded:
            log.info('no write permission set and hence failing to create object')
        log.info('setting permission to write also')
        grants = {'permission': 'WRITE', 'user_id': u2_canonical_id, 'recursive': True}
        u1.grants = grants
        u1.set_bucket_properties()
        u2.bucket_names = u1.bucket_names
        u2.buckets_created = u1.buckets_created
        u2.grants = None
        buckets = u2.set_bucket_properties()
        uploaded = u2.upload(buckets)
        if uploaded:
            log.info('object created after permission set')
        test_info.success_status('test completed')
    except AssertionError as e:
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
    config.user_count = 2
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
    log.info(
        'bucket_count: %s\n'
        'objects_count: %s\n'
        'objects_size_range: %s\n'
        % (
            config.bucket_count, config.objects_count, config.objects_size_range))
    test_exec_read(config)
    test_exec_write(config)
