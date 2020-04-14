# test RGW with SSL configured on Beast or Civetweb
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.utils.log as log
import v2.utils.utils as utils
import traceback
import argparse
import time
import json
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.utils import RGWService
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.write_io_info import AddUserInfo, BucketIoInfo
from v2.lib.read_io_info import ReadIOInfo
from v2.lib.s3.auth import Auth
from v2.lib import pem
from v2.tests.s3_swift import resuables
import v2.lib.resource_op as s3lib

TEST_DATA_PATH = None


def test_exec(config):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        auth = Auth(each_user, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        bucket_name_to_create2 = utils.gen_bucket_name_from_userid(each_user['user_id'])
        log.info('creating bucket with name: %s' % bucket_name_to_create2)
        bucket = resuables.create_bucket(bucket_name_to_create2, rgw_conn, each_user)


if __name__ == '__main__':

    test_info = AddTestInfo('test frontends configuration')
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
        args = parser.parse_args()
        yaml_file = args.config
        config = Config(yaml_file)
        config.read()
        test_exec(config)

        test_info.success_status('test passed')
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)
