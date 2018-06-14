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
from v2.lib.s3.read_io_info import ReadIOInfo

TEST_DATA_PATH = None


def create_bucket_with_versioning(rgw_conn, user_info,  config):

    # create buckets

    log.info('no of buckets to create: %s' % config.bucket_count)

    buckets = []

    for bc in range(config.bucket_count):

        bucket_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=bc)
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

        buckets.append(bucket)

    return buckets


def upload_objects(user_info, buckets, config):

    for bucket in buckets:

        log.info('s3 objects to create: %s' % config.objects_count)

        for oc in range(config.objects_count):
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

        config.user_count = 1

        user_info = s3lib.create_users(config.user_count)
        user_info = user_info[0]

        auth = Auth(user_info)
        rgw_conn = auth.do_auth()

        buckets = create_bucket_with_versioning(rgw_conn, user_info, config)

        upload_objects(user_info, buckets, config)

        log.info('sharding configuration will be added now.')

        if config.sharding_type == 'online':

            time.sleep(15)

            log.info('making changes to ceph.conf')

            ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_override_bucket_index_max_shards, config.max_shards)

            ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_dynamic_resharding,
                                       True)

            log.info('trying to restart services ')

            srv_restarted = rgw_service.restart()

            time.sleep(10)

            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info('RGW service restarted')

        if config.sharding_type == 'offline':

            time.sleep(15) # waiting so that user gets created.

            log.info('in offline sharding')

            for bucket in buckets:

                cmd_exec = utils.exec_shell_cmd('radosgw-admin bucket reshard --bucket=%s --num-shards=%s'
                                                %(bucket.name, config.max_shards))

                if cmd_exec is False:
                    raise TestExecError("offline resharding command execution failed")

        upload_objects(user_info, buckets, config)

        # verification

        time.sleep(20)

        read_io = ReadIOInfo()
        read_io.yaml_fname = 'io_info.yaml'
        read_io.verify_io()

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

    with open(yaml_file, 'r') as f:
        doc = yaml.load(f)
    config.bucket_count = doc['config']['bucket_count']
    config.objects_count = doc['config']['objects_count']
    config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                 'max': doc['config']['objects_size_range']['max']}

    config.max_shards = doc['config']['max_shards']

    config.sharding_type = doc['config']['sharding_type']

    log.info('bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             'sharding_type: %s\n'
             % (config.bucket_count, config.objects_count, config.objects_size_range,
                config.sharding_type))

    test_exec(config)