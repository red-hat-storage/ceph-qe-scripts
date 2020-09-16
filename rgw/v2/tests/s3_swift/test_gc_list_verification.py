"""
test_gc_list_verification - Test gc list is working as expected

Usage: test_gc_list_verification.py -c <input_yaml>

<input_yaml>
    test_gc_list.yaml

Operation:
    1. delete existing gc queue
    2. update ceph.conf (modify queue size)
    3. start all gateway
    4. start IOs - (we did delete, read, list and write on 2 buckets )
    once queue is full it will wrap around and that's when it will hit issue - gc list will say invalid argument
"""

# test gc list
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.utils as utils
from v2.utils.log import configure_logging
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser, RGWService
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.tests.s3_swift import resuables
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure, BucketIoInfo
import random, time
import threading
import json
import logging

log = logging.getLogger()


TEST_DATA_PATH = None

def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    log.info('starting IO')
    config.bluestore_block_size = 1549267441664
    config.rgw_gc_max_queue_size = 367788
    config.rgw_gc_processor_max_time = 3600
    config.rgw_gc_max_concurrent_io = 10
    config.rgw_gc_max_trim_chunk = 32
    config.rgw_objexp_gc_interval = 10
    config.rgw_gc_obj_min_wait = 10
    config.rgw_gc_processor_period = 10
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = Auth(user_info, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    log.info('sharding configuration will be added now.')
    log.info('sharding type is dynamic')
    log.info('making changes to ceph.conf')
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.bluestore_block_size, str(config.bluestore_block_size))
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_gc_max_queue_size, str(config.rgw_gc_max_queue_size))
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_gc_processor_max_time, str(config.rgw_gc_processor_max_time))
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_gc_max_concurrent_io, str(config.rgw_gc_max_concurrent_io))
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_objexp_gc_interval, str(config.rgw_objexp_gc_interval))
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_gc_obj_min_wait, str(config.rgw_gc_obj_min_wait))
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_gc_processor_period, str(config.rgw_gc_processor_period))
    log.info('trying to restart services ')
    srv_restarted = rgw_service.restart()
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info('RGW service restarted')

    #Delete gc queue
    pool_name = utils.exec_shell_cmd('ceph df |awk \'{ print $1 }\'| grep rgw.log')
    pool_name = pool_name.replace("\n", "")
    utils.exec_shell_cmd('for q in {0..31}; do rados rm gc.${q} -p %s -N gc; done' % pool_name)

    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssl=config.ssl)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{'signature_version': 's3v4'})
        else:
            rgw_conn = auth.do_auth()

        log.info('no of buckets to create: %s' % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=bc)
            log.info('creating bucket with name: %s' % bucket_name_to_create)
            bucket = resuables.create_bucket(bucket_name_to_create, rgw_conn, each_user)
            # uploading data
            log.info('s3 objects to create: %s' % config.objects_count)
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                log.info('s3 object name: %s' % s3_object_name)
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info('s3 object path: %s' % s3_object_path)
                resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, each_user)
                # delete local object file
                utils.exec_shell_cmd('rm -rf %s' % s3_object_path)

            log.info('listing all objects in bucket: %s' % bucket.name)
            objects = s3lib.resource_op({'obj': bucket, 'resource': 'objects', 'args': None})
            log.info('objects :%s' % objects)
            all_objects = s3lib.resource_op({'obj': objects, 'resource': 'all', 'args': None})
            log.info('all objects: %s' % all_objects)
            for obj in all_objects:
                log.info('object_name: %s' % obj.key)

            log.info('deleting all objects in bucket')
            objects_deleted = s3lib.resource_op({'obj': objects, 'resource': 'delete', 'args': None})
            log.info('objects_deleted: %s' % objects_deleted)
            if objects_deleted is False:
                raise TestExecError('Resource execution failed: Object deletion failed')
            if objects_deleted is not None:
                response = HttpResponseParser(objects_deleted[0])
                if response.status_code == 200:
                    log.info('objects deleted ')
                else:
                    raise TestExecError("objects deletion failed")
            else:
                raise TestExecError("objects deletion failed")

    op=utils.exec_shell_cmd('radosgw-admin gc list')
    final_op = op.find('ERROR') or op.find('Invalid argument')     #ERROR: failed to list objs: (22) Invalid argument
    if final_op != -1:
        test_info.failed_status('test failed')
        sys.exit(1)


if __name__ == '__main__':

    test_info = AddTestInfo('RGW gc list test')
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
