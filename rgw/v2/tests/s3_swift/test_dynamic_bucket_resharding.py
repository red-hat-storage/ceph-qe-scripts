"""
test_dynamic_bucket_resharding - Test resharding operations on bucket

Usage: test_dynamic_bucket_resharding.py -c <input_yaml>

<input_yaml>
    Note: any one of these yamls can be used
    test_manual_resharding.yaml
    test_dynamic_resharding.yaml

Operation:
    Create user
    Perform IOs in specific bucket
    Initiate dynamic or manual sharding on bucket
    Restart RGW service
    Verify created shard numbers of bucket
"""

# test RGW dynamic bucket resharding
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.utils as utils
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser, RGWService
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.utils.log import configure_logging
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

    log.info('starting IO')
    config.user_count = 1
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = Auth(user_info, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    log.info('sharding configuration will be added now.')
    if config.sharding_type == 'dynamic':
        log.info('sharding type is dynamic')
        # for dynamic,
        # the number of shards  should be greater than   [ (no of objects)/(max objects per shard) ]
        # example: objects = 500 ; max object per shard = 10
        # then no of shards should be at least 50 or more
        time.sleep(15)
        log.info('making changes to ceph.conf')
        ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_max_objs_per_shard, str(config.max_objects_per_shard))
        ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_dynamic_resharding,
                                   'True')
        num_shards_expected = config.objects_count / config.max_objects_per_shard
        log.info('num_shards_expected: %s' % num_shards_expected)
        log.info('trying to restart services ')
        srv_restarted = rgw_service.restart()
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info('RGW service restarted')

    config.bucket_count = 1
    objects_created_list = []
    log.info('no of buckets to create: %s' % config.bucket_count)
    bucket_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=1)
    bucket = resuables.create_bucket(bucket_name, rgw_conn, user_info)
    if config.test_ops.get('enable_version', False):
        log.info('enable bucket version')
        resuables.enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info)
    log.info('s3 objects to create: %s' % config.objects_count)
    for oc, size in list(config.mapped_sizes.items()):
        config.obj_size = size
        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
        if config.test_ops.get('enable_version', False):
            resuables.upload_version_object(config, user_info, rgw_conn, s3_object_name, config.obj_size, bucket,
                                            TEST_DATA_PATH)
        else:
            resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info)
        objects_created_list.append((s3_object_name, s3_object_path))

    if config.sharding_type == 'manual':
        log.info('sharding type is manual')
        # for manual.
        # the number of shards will be the value set in the command.
        time.sleep(15)
        log.info('in manual sharding')
        cmd_exec = utils.exec_shell_cmd('radosgw-admin bucket reshard --bucket=%s --num-shards=%s '
                                        '--yes-i-really-mean-it'
                                        % (bucket.name, config.shards))
        if cmd_exec is False:
            raise TestExecError("manual resharding command execution failed")

    sleep_time = 600
    log.info(f'verification starts after waiting for {sleep_time} seconds')
    time.sleep(sleep_time)
    op = utils.exec_shell_cmd("radosgw-admin metadata get bucket:%s" % bucket.name)
    json_doc = json.loads(op)
    bucket_id = json_doc['data']['bucket']['bucket_id']
    op2 = utils.exec_shell_cmd("radosgw-admin metadata get bucket.instance:%s:%s" % (bucket.name, bucket_id))
    json_doc2 = json.loads((op2))
    num_shards_created = json_doc2['data']['bucket_info']['num_shards']
    log.info('no_of_shards_created: %s' % num_shards_created)
    if config.sharding_type == 'manual':
        if config.shards != num_shards_created:
            raise TestExecError("expected number of shards not created")
        log.info('Expected number of shards created')
    if config.sharding_type == 'dynamic':
        log.info('Verify if resharding list is empty')
        reshard_list_op = json.loads(utils.exec_shell_cmd("radosgw-admin reshard list"))
        if not reshard_list_op:
            log.info(
                'for dynamic number of shards created should be greater than or equal to number of expected shards')
            log.info('no_of_shards_expected: %s' % num_shards_expected)
            if int(num_shards_created) >= int(num_shards_expected):
                log.info('Expected number of shards created')
        else:
            raise TestExecError('Expected number of shards not created')

    if config.test_ops.get('delete_bucket_object', False):
        if config.test_ops.get('enable_version', False):
            for name, path in objects_created_list:
                resuables.delete_version_object(bucket, name, path, rgw_conn, user_info)
        else:
            resuables.delete_objects(bucket)
        resuables.delete_bucket(bucket)


if __name__ == '__main__':

    test_info = AddTestInfo('RGW Dynamic Resharding test')
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


