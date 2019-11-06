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
from v2.lib.exceptions import TestExecError
from v2.utils.utils import RGWService
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.write_io_info import AddUserInfo, BucketIoInfo
from v2.lib.read_io_info import ReadIOInfo
from v2.lib.s3.auth import Auth

import resuables
import v2.lib.resource_op as s3lib

TEST_DATA_PATH = None


def test_exec(config):
    test_info = AddTestInfo('test swift user key gen')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    try:
        test_info.started_info()
        # Create a .pem file
        frontend = ceph_conf.check_if_config_exists('rgw frontends')
        out = s3lib.create_pem()
        name_ip = utils.get_Host_name_IP()

        #ceph_conf.remove_from_ceph_conf('rgw frontends')
        # Configure rgw frontend
        if config.test_ops['use_civetweb'] is True:
            new_front = "civetweb port=" + name_ip[
                1] + ":443s ssl_certificate=/etc/ssl/certs/server.pem"
        elif config.test_ops['use_beast'] is True:
            new_front = "beast ssl_endpoint=" + name_ip[
                1] + ":443 ssl_certificate=/etc/ssl/certs/server.pem"
        section = 'client.rgw.' + name_ip[0]
        ceph_conf.set_to_ceph_conf(section, 'rgw frontends', new_front)
        log.info('trying to restart services ')
        srv_restarted = rgw_service.restart()
        time.sleep(10)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info('RGW service restarted')
        # create users
        all_users_info = s3lib.create_users(config.user_count)
        for each_user in all_users_info:
            auth = Auth(each_user)
            rgw_conn = auth.do_auth_ssl('/etc/ssl/certs/server.pem')
            bucket_name_to_create2 = utils.gen_bucket_name_from_userid(each_user['user_id'])
            log.info('creating bucket with name: %s' % bucket_name_to_create2)
            bucket = resuables.create_bucket(bucket_name_to_create2, rgw_conn, each_user)
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
    config = Config(yaml_file)
    config.read()
    test_exec(config)
