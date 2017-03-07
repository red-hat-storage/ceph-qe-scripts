import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.s3.rgw import Config
from lib.s3.rgw import ObjectOps
import lib.s3.rgw as rgw_lib
import argparse
import yaml


def test_exec_read(config):

    grants = {'permission': 'READ', 'user_id': None, 'recursive': True}

    test_info = AddTestInfo('Test with read permission on buckets for all users')

    try:

        # test case starts

        test_info.started_info()

        all_user_details = rgw_lib.create_users(config.user_count)

        user1 = all_user_details[0]
        log.info('user1: %s' % user1)

        all_user_details.pop(0)

        u1 = ObjectOps(config, user1)

        for each_user in all_user_details:

            u2 = ObjectOps(config, each_user)

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

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test failed: %s' % e)
        sys.exit(1)


def test_exec_write(config):

    test_info = AddTestInfo('test with write persmission on objects and buckets for all users')

    try:

        # test case starts

        test_info.started_info()

        all_user_details = rgw_lib.create_users(config.user_count)

        user1 = all_user_details[0]
        u1 = ObjectOps(config, user1)
        log.info('user1: %s' % user1)

        all_user_details.pop(0)

        for each_user in all_user_details:

            print 'iter ------------------>'

            log.info('user2: %s' % each_user)

            u2 = ObjectOps(config, each_user)

            u2_canonical_id = u2.canonical_id

            log.info('canonical id of u2: %s' % u2_canonical_id)

            log.info('setting only read permission')

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
            key_created = u2.upload(buckets)
            if not key_created:
                log.info('no write permission set and hence failing to create object')

            elif key_created:
                raise AssertionError,  "object created even with no permission"

            log.info('setting permission to write also')

            grants = {'permission': 'WRITE', 'user_id': u2_canonical_id, 'recursive': True}
            u1.grants = grants
            u1.set_bucket_properties()
            u2.bucket_names = u1.bucket_names
            u2.buckets_created = u1.buckets_created

            u2.grants = None
            buckets = u2.set_bucket_properties()
            key_created = u2.upload(buckets, object_base_name=str(u2.canonical_id) + ".key")
            if key_created:
                log.info('object created after permission set')

        test_info.success_status('test completed')

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
        config.user_count = 3
        config.objects_count = 4
        config.objects_size_range = {'min': 10, 'max': 50}
    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.bucket_count = doc['config']['bucket_count']
        config.user_count = doc['config']['user_count']
        config.objects_count = doc['config']['objects_count']
        config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                     'max': doc['config']['objects_size_range']['max']}


    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (
              config.user_count, config.bucket_count, config.objects_count, config.objects_size_range))

    test_exec_read(config)
    test_exec_write(config)
