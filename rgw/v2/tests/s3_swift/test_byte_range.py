# test basic creation of buckets with objects
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import v2.lib.manage_data as manage_data
import resuables

TEST_DATA_PATH = None


def test_exec(config):
    test_info = AddTestInfo('Test Byte range')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:
        test_info.started_info()
        # create user
        all_users_info = s3lib.create_users(config.user_count)
        for each_user in all_users_info:
            # authenticate
            auth = Auth(each_user)
            rgw_conn = auth.do_auth()
            rgw_conn2 = auth.do_auth_using_client()
            # create buckets
            log.info('no of buckets to create: %s' % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=1)
                bucket = resuables.create_bucket(bucket_name, rgw_conn, each_user)
                # uploading data
                log.info('s3 objects to create: %s' % config.objects_count)
                for oc in range(config.objects_count):
                    s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                    log.info('s3 object name: %s' % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info('s3 object path: %s' % s3_object_path)
                    s3_object_size = utils.get_file_size(config.objects_size_range['min'],
                                                         config.objects_size_range['max'])
                    data_info = manage_data.io_generator(s3_object_path, s3_object_size)
                    if data_info is False:
                        TestExecError("data creation failed")
                    log.info('uploading s3 object: %s' % s3_object_path)
                    upload_info = dict({'access_key': each_user['access_key']}, **data_info)
                    object_uploaded_status = s3lib.resource_op({'obj': bucket,
                                                                'resource': 'upload_file',
                                                                'args': [s3_object_path, s3_object_name],
                                                                'extra_info': upload_info})
                    if object_uploaded_status is False:
                        raise TestExecError("Resource execution failed: object upload failed")
                    if object_uploaded_status is None:
                        log.info('object uploaded')
                    log.info('testing for negative range')
                    response = rgw_conn2.get_object(Bucket=bucket.name, Key=s3_object_name, Range='-2--1')
                    log.info('response: %s\n' % response)
                    log.info('Content-Lenght: %s' % response['ContentLength'])
                    log.info('s3_object_size: %s' % (s3_object_size * 1024 * 1024))
                    if response['ContentLength'] != s3_object_size * 1024 * 1024:
                        TestExecError("Content Lenght not matched")
                    log.info('testing for one positive and one negative range')
                    response = rgw_conn2.get_object(Bucket=bucket.name, Key=s3_object_name, Range='-1-3')
                    log.info('response: %s\n' % response)
                    log.info('Content-Length: %s' % response['ContentLength'])
                    log.info('s3_object_size: %s' % (s3_object_size * 1024 * 1024))
                    if response['ContentLength'] != s3_object_size * 1024 * 1024:
                        TestExecError("Content Lenght not matched")

        test_info.success_status('test passed')

        sys.exit(0)

    except Exception, e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)

    except TestExecError, e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)


if __name__ == '__main__':
    project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
    test_data_dir = 'test_data'
    TEST_DATA_PATH = (os.path.join(project_dir, test_data_dir))
    log.info('TEST_DATA_PATH: %s' % TEST_DATA_PATH)
    if not os.path.exists(TEST_DATA_PATH):
        log.info('test data dir not exists, creating.. ')
        os.makedirs(TEST_DATA_PATH)
    parser = argparse.ArgumentParser(description='RGW S3 Automation')
    parser.add_argument('-c', dest="config",
                        help='RGW Test yaml configuration')
    args = parser.parse_args()
    yaml_file = args.config
    config = Config()
    with open(yaml_file, 'r') as f:
        doc = yaml.load(f)
    config.user_count = doc['config']['user_count']
    config.bucket_count = doc['config']['bucket_count']
    config.objects_count = doc['config']['objects_count']
    config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                 'max': doc['config']['objects_size_range']['max']}
    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (config.user_count, config.bucket_count, config.objects_count, config.objects_size_range))
    test_exec(config)
