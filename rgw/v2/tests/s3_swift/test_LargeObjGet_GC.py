""" test_LargeObjGet_GC.py - Test large object download with and without the GC process and rgw_gc_obj_min_wait= 5

Usage: test_LargeObjGet_GC.py -c configs/<input-yaml>
where : <input-yaml> is test_LargeObjGet_GC.yaml
"""
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
from v2.utils.log import configure_logging
import v2.utils.utils as utils
from v2.utils.utils import RGWService
from v2.tests.s3_swift import reusable
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import json, time, hashlib
import logging

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    # create user
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = Auth(user_info, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    rgw_conn2 = auth.do_auth_using_client()
    log.info('no of buckets to create: %s' % config.bucket_count)
    # create buckets
    if config.test_ops['create_bucket'] is True:
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=bc)
            log.info('creating bucket with name: %s' % bucket_name_to_create)
            bucket = reusable.create_bucket(bucket_name_to_create, rgw_conn, user_info)
            if config.test_ops['create_object'] is True:
                # uploading data
                log.info('s3 objects to create: %s' % config.objects_count)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                    log.info('s3 object name: %s' % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info('s3 object path: %s' % s3_object_path)
                    if config.test_ops.get('upload_type') == 'multipart':
                        log.info('upload type: multipart')
                        reusable.upload_mutipart_object(s3_object_name, bucket, TEST_DATA_PATH, config,
                                                        user_info)
                    else:
                        log.info('upload type: normal')
                        reusable.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info)

                    if config.gc_verification is True:
                        log.info('making changes to ceph.conf')
                        config.rgw_gc_obj_min_wait = 5
                        ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_gc_obj_min_wait,
                                                   str(config.rgw_gc_obj_min_wait))
                        log.info('trying to restart services')
                        srv_restarted = rgw_service.restart()
                        time.sleep(30)
                        if srv_restarted is False:
                            raise TestExecError("RGW service restart failed")
                        else:
                            log.info('RGW service restarted')
                        log.info('download the large object again to populate gc list with shadow entries')
                        reusable.download_object(s3_object_name, bucket, TEST_DATA_PATH, s3_object_path, config)
                        time.sleep(60)
                        gc_list_output = json.loads(utils.exec_shell_cmd("radosgw-admin gc list --include-all"))

                        log.info(gc_list_output)
                        
                        if gc_list_output:
                            log.info("Shadow objects found after setting the rgw_gc_obj_min_wait to 5 seconds")
                            utils.exec_shell_cmd("radosgw-admin gc process")
                            log.info('Object download should not error out in 404 NoSuchKey error')
                            reusable.download_object(s3_object_name, bucket, TEST_DATA_PATH, s3_object_path, config)

        reusable.remove_user(user_info)


if __name__ == '__main__':

    test_info = AddTestInfo('bucket life cycle: test object expiration')
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

