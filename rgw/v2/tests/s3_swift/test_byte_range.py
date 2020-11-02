"""
test_byte_range - Download objects with a specified byte range and check boundary conditions for positive and negative byte ranges
Usage: test_byte_range.py -c <input_yaml>
<input_yaml>
        test_byte_range.yaml
Operation:
    Create specified number of users
    Create specified number of buckets
    Upload number of objects of size range mentioned in test_byte_range.yaml
    Download the object created above with a negative byte range and check whether the whole object is returned
    Download the object created above with a negative to positive byte range and check whether the whole object is returned
"""
# test basic creation of buckets with objects
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
from v2.utils.log import configure_logging
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import json
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import v2.lib.manage_data as manage_data
from v2.tests.s3_swift import reusable
import logging

log = logging.getLogger()

TEST_DATA_PATH = None

def test_exec(config):
    test_info = AddTestInfo('Test Byte range')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    test_info.started_info()
    # create user
    # use an already existing user
    all_users_info = None
    if config.user_create is False:
        log.info('Using an already existing user')
        with open('user_details') as f:
            all_users_info = json.load(f)
            all_users_info = s3lib.create_users(config.user_count, users_info_list=all_users_info)
    else:
        log.info('create a new user')
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
            bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
            # uploading data
            log.info('s3 objects to create: %s' % config.objects_count)
            for oc, size in config.mapped_sizes.items():
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                reusable.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, each_user)
                log.info('testing for negative range')
                response = rgw_conn2.get_object(Bucket=bucket.name, Key=s3_object_name, Range='-2--1')
                log.info('response: %s\n' % response)
                log.info('Content-Lenght: %s' % response['ContentLength'])
                log.info('s3_object_size: %s' % (config.obj_size * 1024 * 1024))
                if response['ContentLength'] != config.obj_size * 1024 * 1024:
                    TestExecError("Content Lenght not matched")
                log.info('testing for one positive and one negative range')
                response = rgw_conn2.get_object(Bucket=bucket.name, Key=s3_object_name, Range='-1-3')
                log.info('response: %s\n' % response)
                log.info('Content-Length: %s' % response['ContentLength'])
                log.info('s3_object_size: %s' % (config.obj_size * 1024 * 1024))
                if response['ContentLength'] != config.obj_size * 1024 * 1024:
                    TestExecError("Content Lenght not matched")


if __name__ == '__main__':

    test_info = AddTestInfo('test_byte_range ')
    test_info.started_info()

    try:
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
        parser.add_argument('-log_level', dest='log_level',
                            help='Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]',
                            default='info')
        args = parser.parse_args()
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name,
                          set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read()
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config)
        test_info.success_status('test passed')
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)
