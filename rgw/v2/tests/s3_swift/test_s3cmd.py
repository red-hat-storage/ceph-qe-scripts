"""
test_s3cmd - Test s3cmd operation on cluster

Usage: test_s3cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload a file to bucket
    Delete uploaded object
    Delete bucket
"""


import argparse
import json
import logging
import os
import requests
import sys
import time
import traceback
import uuid
import yaml
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib.admin import UserMgmt
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.lib import manage_data
from v2.lib import resource_op as swiftlib
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.swift.auth import Auth
from v2.lib.s3.s3cmd import auth as s3_auth
from v2.lib.s3.s3cmd.resource_op import S3CMD
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.utils import HttpResponseParser, RGWService
from v2.utils.test_desc import AddTestInfo
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.test_swift_basic_ops import fill_container

log = logging.getLogger()


def test_exec(config):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    rgw_service = RGWService()
    # preparing data
    user_name = str(uuid.uuid1()).split('-')[0]
    tenant = 'tenant'
    tenant_user_info = umgmt.create_tenant_user(tenant_name=tenant,
                                                user_id=user_name,
                                                displayname=user_name)
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)

    auth = Auth(user_info)
    rgw = auth.do_auth()

    ip_and_port = rgw.authurl.split('/')[2]
    s3_auth.do_auth(tenant_user_info, ip_and_port)

    bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)

    #Create a bucket
    create_bucket = S3CMD(operation="mb")
    create_bucket.command(params=["s3://{}".format(bucket_name)])
    create_bucket_response = str(create_bucket.execute())
    expected_response = "Bucket 's3://{}/' created".format(bucket_name)
    error_message = 'Expected: %s, Actual: %s' % (
        expected_response, create_bucket_response)
    assert expected_response in create_bucket_response, error_message 

    #Create a file to upload to bucket
    file_name = 'test_s3cmd.txt'
    with open(file_name, 'w') as f:
        f.write('Test file')

    #Upload file to bucket
    upload_file = S3CMD(operation="put")
    remote_s3_path = "s3://{}/{}".format(bucket_name,file_name)
    upload_file.command(params=[file_name, remote_s3_path])
    upload_file_response = upload_file.execute()
    assert '100%' in str(upload_file_response), 'upload file operation not succeeded'

    #Delete file from bucket
    delete_file = S3CMD(operation="del")
    delete_file.command(params=[remote_s3_path])
    delete_file_response = str(delete_file.execute())
    expected_response = "delete: '{}'".format(remote_s3_path)
    error_message = 'Expected: %s, Actual: %s' % (
        expected_response, delete_file_response)
    assert expected_response in delete_file_response, error_message

    #Delete bucket
    delete_bucket = S3CMD(operation="rb")
    delete_bucket.command(params=["s3://{}".format(bucket_name)])
    delete_bucket_response = str(delete_bucket.execute())
    expected_response = "Bucket 's3://{}/' removed".format(bucket_name)
    error_message = 'Expected: %s, Actual: %s' % (
        expected_response, delete_file_response)
    assert expected_response in delete_bucket_response, error_message


    # check for any crashes during the execution
    crash_info=reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

if __name__ == '__main__':

    test_info = AddTestInfo('test swift user key gen')

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = 'test_data'
        TEST_DATA_PATH = (os.path.join(project_dir, test_data_dir))
        log.info('TEST_DATA_PATH: %s' % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info('test data dir not exists, creating.. ')
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description='RGW Swift Automation')
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
        config = swiftlib.Config(yaml_file)
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
