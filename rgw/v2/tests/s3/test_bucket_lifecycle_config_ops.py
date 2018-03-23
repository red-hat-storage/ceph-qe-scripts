# test basic creation of buckets with objects
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.s3.s3lib import Config
import v2.lib.s3.s3lib as s3lib
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
import resuables
import json
from v2.lib.s3 import lifecycle as lc

TEST_DATA_PATH = None


def basic_lifecycle_config(prefix, days, id, status="Enabled"):
    rule = {}

    expiration = lc.gen_expiration()
    expiration['Expiration'].update(lc.gen_expiration_days(days))

    filter = lc.gen_filter()
    filter['Filter'].update(lc.gen_prefix(prefix))

    rule.update(lc.gen_id(id))
    rule.update(filter)
    rule.update(expiration)
    rule.update(lc.gen_status(status))

    lifecycle_config = lc.gen_lifecycle_configuration([rule])

    log.info('life_cycle config:\n%s' % lifecycle_config)

    return lifecycle_config


def test_exec(config):
    test_info = AddTestInfo('create m buckets with n objects with bucket life cycle')
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

            if config.test_ops['create_bucket'] is True:

                log.info('no of buckets to create: %s' % config.bucket_count)

                for bc in range(config.bucket_count):

                    bucket_name = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=1)
                    bucket = resuables.create_bucket(bucket_name, rgw_conn, each_user)

                    if config.test_ops['create_object'] is True:

                        # uploading data

                        log.info('s3 objects to create: %s' % config.objects_count)

                        for oc in range(config.objects_count):
                            s3_object_name = utils.gen_s3_object_name(bucket.name, oc)

                            resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, each_user)

                    bucket_life_cycle = s3lib.resource_op({'obj': rgw_conn,
                                                           'resource': 'BucketLifecycleConfiguration',
                                                           'args': [bucket.name]})

                    life_cycle = basic_lifecycle_config(prefix="key", days=20, id="rul1")

                    put_bucket_life_cycle = s3lib.resource_op({"obj": bucket_life_cycle,
                                                               "resource": "put",
                                                               "kwargs": dict(LifecycleConfiguration=life_cycle)})

                    log.info('put bucket life cycle:\n%s' % put_bucket_life_cycle)

                    if put_bucket_life_cycle is False:
                        raise TestExecError("Resource execution failed: bucket creation faield")

                    if put_bucket_life_cycle is not None:

                        response = HttpResponseParser(put_bucket_life_cycle)

                        if response.status_code == 200:
                            log.info('bucket life cycle added')

                        else:
                            raise TestExecError("bucket lifecycle addition failed")

                    else:
                        raise TestExecError("bucket lifecycle addition failed")

                    log.info('trying to retrieve bucket lifecycle config')

                    get_bucket_life_cycle_config = s3lib.resource_op({"obj": rgw_conn2,
                                                                      "resource": 'get_bucket_lifecycle_configuration',
                                                                      "kwargs": dict(Bucket=bucket.name)
                                                                      })
                    if get_bucket_life_cycle_config is False:
                        raise TestExecError("bucket lifecycle config retrieval failed")

                    if get_bucket_life_cycle_config is not None:

                        response = HttpResponseParser(get_bucket_life_cycle_config)

                        if response.status_code == 200:
                            log.info('bucket life cycle retrieved')

                        else:
                            raise TestExecError("bucket lifecycle config retrieval failed")

                    else:
                        raise TestExecError("bucket life cycle retrieved")

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
    config.shards = None
    config.max_objects = None
    if yaml_file is None:
        config.user_count = 2
        config.bucket_count = 10
        config.objects_count = 2
        config.objects_size_range = {'min': 10, 'max': 50}

    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.user_count = doc['config']['user_count']
        config.bucket_count = doc['config']['bucket_count']
        config.objects_count = doc['config']['objects_count']
        config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                     'max': doc['config']['objects_size_range']['max']}

        config.test_ops = doc['config']['test_ops']

    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (config.user_count, config.bucket_count, config.objects_count, config.objects_size_range))

    log.info('test_ops: %s' % config.test_ops)

    test_exec(config)
