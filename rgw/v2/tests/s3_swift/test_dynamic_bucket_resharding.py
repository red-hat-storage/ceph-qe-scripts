import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser, RGWService
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import random, time
import resuables
import threading
import json

TEST_DATA_PATH = None


def create_bucket_with_versioning(rgw_conn, user_info, bucket_name):
    # create buckets
    bucket = resuables.create_bucket(bucket_name, rgw_conn, user_info)
    bucket_versioning = s3lib.resource_op({'obj': rgw_conn,
                                           'resource': 'BucketVersioning',
                                           'args': [bucket.name]})
    # checking the versioning status
    version_status = s3lib.resource_op({'obj': bucket_versioning,
                                        'resource': 'status',
                                        'args': None
                                        })
    if version_status is None:
        log.info('bucket versioning still not enabled')
    # enabling bucket versioning
    version_enable_status = s3lib.resource_op({'obj': bucket_versioning,
                                               'resource': 'enable',
                                               'args': None})
    response = HttpResponseParser(version_enable_status)
    if response.status_code == 200:
        log.info('version enabled')
    else:
        raise TestExecError("version enable failed")
    return bucket


def upload_objects(user_info, bucket, config):
    log.info('s3 objects to create: %s' % config.objects_count)
    for oc, size in config.mapped_sizes.items():
        config.obj_size = size
        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
        resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info)


def test_exec(config):
    test_info = AddTestInfo('RGW Dynamic Resharding test')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    try:
        test_info.started_info()
        log.info('starting IO')
        config.max_objects_per_shard = 10
        config.no_of_shards = 10
        config.user_count = 1
        user_info = s3lib.create_users(config.user_count)
        user_info = user_info[0]
        auth = Auth(user_info)
        rgw_conn = auth.do_auth()
        config.bucket_count = 1
        log.info('no of buckets to create: %s' % config.bucket_count)
        bucket_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=1)
        bucket = create_bucket_with_versioning(rgw_conn, user_info, bucket_name)
        upload_objects(user_info, bucket, config)
        log.info('sharding configuration will be added now.')
	num_shards_expected = config.objects_count / config.max_objects_per_shard
        if config.sharding_type == 'online':
            log.info('sharding type is online')
            # for online,
            # the number of shards  should be greater than   [ (no of objects)/(max objects per shard) ]
            # example: objects = 500 ; max object per shard = 10
            # then no of shards should be at least 50 or more
            time.sleep(15)
            log.info('making changes to ceph.conf')
            ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_max_objs_per_shard, config.max_objects_per_shard)
            ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_dynamic_resharding,
                                       True)
            num_shards_expected = config.objects_count / config.max_objects_per_shard
            log.info('num_shards_expected: %s' % num_shards_expected)
            log.info('trying to restart services ')
            srv_restarted = rgw_service.restart()
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info('RGW service restarted')
        if config.sharding_type == 'offline':
            log.info('sharding type is offline')
            # for offline.
            # the number of shards will be the value set in the command.
            time.sleep(15)
            log.info('in offline sharding')
            cmd_exec = utils.exec_shell_cmd('radosgw-admin bucket reshard --bucket=%s --num-shards=%s '
                                            '--yes-i-really-mean-it'
                                            % (bucket.name, config.no_of_shards))
            if cmd_exec is False:
                raise TestExecError("offline resharding command execution failed")
        # upload_objects(user_info, bucket, config)
        log.info('s3 objects to create: %s' % config.objects_count)
        for oc, size in config.mapped_sizes.items():
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(bucket.name, config.objects_count + oc)
            resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info)
        time.sleep(300)
        log.info('verification starts')
        op = utils.exec_shell_cmd("radosgw-admin metadata get bucket:%s" % bucket.name)
        json_doc = json.loads(op)
        bucket_id = json_doc['data']['bucket']['bucket_id']
        op2 = utils.exec_shell_cmd("radosgw-admin metadata get bucket.instance:%s:%s" % (bucket.name, bucket_id))
        json_doc2 = json.loads((op2))
        num_shards_created = json_doc2['data']['bucket_info']['num_shards']
        log.info('no_of_shards_created: %s' % num_shards_created)
	#global num_shards_expected
	#num_shards_expected = config.objects_count / config.max_objects_per_shard
        log.info('no_of_shards_expected: %s' % num_shards_expected)
        if config.sharding_type == 'offline':
            if num_shards_expected != num_shards_created:
                raise TestExecError("expected number of shards not created")
            log.info('Expected number of shards created')
        if config.sharding_type == 'online':
            log.info('for online, '
                     'number of shards created should be greater than or equal to number of  expected shards')
            if int(num_shards_created) >= int(num_shards_expected):
                log.info('Expected number of shards created')
            else:
                raise TestExecError('Expected number of shards not created')

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
    if config.mapped_sizes is None:
        config.mapped_sizes = utils.make_mapped_sizes(config)
    test_exec(config)
