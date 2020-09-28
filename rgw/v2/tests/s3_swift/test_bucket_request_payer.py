""" test_bucket_request_payer.py - Test requester pays buckets.

Usage: test_bucket_request_payer.py -c <input_yaml>

<input_yaml>
	Note: Any one of these yamls can be used
	test_bucket_request_payer.yaml
	test_bucket_request_payer_download.yaml

Operation:
	Create a bucket. Verify the Requester pays bucket is set to 'Requester' and upload objects
	Create a bucket. Verify the Requester pays bucket is set to 'Requester'.
""" 
# test S3 bucket request payer
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.utils as utils
from v2.utils.log import configure_logging
import traceback
import argparse
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.tests.s3_swift import reusable
from v2.utils.utils import HttpResponseParser
import yaml
import logging

log = logging.getLogger()


TEST_DATA_PATH = None


def test_exec(config, requester):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    log.info('requester type: %s' % requester)

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        # create buckets
        log.info('no of buckets to create: %s' % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=bc)
            log.info('creating bucket with name: %s' % bucket_name_to_create)
            # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)
            bucket = reusable.create_bucket(bucket_name=bucket_name_to_create, rgw=rgw_conn, user_info=each_user)
            bucket_request_payer = s3lib.resource_op({'obj': rgw_conn,
                                                      'resource': 'BucketRequestPayment',
                                                      'args': [bucket.name]
                                                      })
            # change the bucket request payer to 'requester'
            payer = {'Payer': requester}
            response = s3lib.resource_op({'obj': bucket_request_payer,
                                          'resource': 'put',
                                          'kwargs': dict(RequestPaymentConfiguration=payer)})
            log.info(response)
            if response is not None:
                response = HttpResponseParser(response)
                if response.status_code == 200:
                    log.info('bucket created')
                else:
                    raise TestExecError("bucket request payer modification failed")
            else:
                raise TestExecError("bucket request payer modification failed")
            payer = bucket_request_payer.payer
            log.info('bucket request payer: %s' % payer)
            if payer != 'Requester':
                TestExecError('Request payer is not set or changed properly ')
            log.info('s3 objects to create: %s' % config.objects_count)
            if config.objects_count is not None:
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                    reusable.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, each_user)


if __name__ == '__main__':

    test_info = AddTestInfo('Bucket Request Payer')
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
                            help='RGW Test yaml configuration', default=None)
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
        if (config.mapped_sizes is None) and (config.objects_count is not None):
            config.mapped_sizes = utils.make_mapped_sizes(config)

        requester = 'Requester'
        test_exec(config, requester)
        test_info.success_status('test passed')

        requester = 'BucketOwner'
        test_exec(config, requester)
        test_info.success_status('test passed')

        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)
