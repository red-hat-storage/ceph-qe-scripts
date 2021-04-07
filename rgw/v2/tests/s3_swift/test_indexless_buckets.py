"""  
    test_indexless_buckets.py - Test s3 operations on indexless buckets

    Usage: test_indexless_buckets.py -c <input_yaml>
    
    <input_yaml>:
        test_indexless_buckets_s3.yaml
"""

=======
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.utils as utils
from v2.utils.log import configure_logging
from v2.utils.utils import RGWService
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.admin import UserMgmt
import time
import json
from v2.tests.s3_swift import reusable
import logging

log = logging.getLogger()

TEST_DATA_PATH = None


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    rgw_service = RGWService()

    log.info('adding indexless placement to placement target of default zonegroup')
    zonegroup_set = utils.exec_shell_cmd('radosgw-admin zonegroup placement add --rgw-zonegroup="default" --placement-id="indexless-placement"')
    
    log.info('adding indexless placement to placement pool of default zone')
    zone_set = utils.exec_shell_cmd('radosgw-admin zone placement add --rgw-zone="default" --placement-id="indexless-placement" --data-pool="default.rgw.buckets.data" --index-pool="default.rgw.buckets.index" --data_extra_pool="default.rgw.buckets.non-ec" --placement-index-type="indexless"')
    
    log.info ('making indexless-placement as default')
    indexless_default=utils.exec_shell_cmd('radosgw-admin zonegroup placement default --placement-id="indexless-placement"')
    
    log.info('restart the rgw daemons')
    restart_service = rgw_service.restart()
    if restart_service is False:
        raise TestExecError("RGW service restart failed")

    # perform s3 operations
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssl=config.ssl)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{'signature_version': 's3v4'})
        else:
            rgw_conn = auth.do_auth()

        if config.test_ops['create_bucket'] is True:
            log.info('no of buckets to create: %s' % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=bc)
                log.info('creating bucket with name: %s' % bucket_name_to_create)
                bucket = reusable.create_bucket(bucket_name_to_create, rgw_conn, each_user)
                if config.test_ops['create_object'] is True:
                    # uploading data
                    log.info('s3 objects to create: %s' % config.objects_count)
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                        log.info('s3 object name: %s' % s3_object_name)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info('s3 object path: %s' % s3_object_path)
                        log.info('upload type: normal')
                        reusable.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, each_user)

        #verify the bucket created has index_type = Indexless
        log.info('verify the bucket created has index_type as Indexless')
        bucket_stats=utils.exec_shell_cmd("radosgw-admin bucket stats --bucket %s" % bucket_name_to_create)
        bucket_stats_json = json.loads(bucket_stats)
        bkt_index_type = bucket_stats_json['index_type']
        if bkt_index_type == 'Indexless':
            log.info(f'index_type is Indexless for bucket %s' %bucket_name_to_create)
        else:
            raise TestExecError(" index_type is not Indexless as expected")

        #delete bucket and objects
        if config.test_ops['delete_bucket'] is True:
            log.info('Deleting buckets and objects')
            reusable.delete_bucket(bucket)

    
    # reverting to default placement group
    log.info('revert changes to zone, zonegroup and default placement target')
    zone_set = utils.exec_shell_cmd('radosgw-admin zone placement rm --rgw-zone="default" --placement-id="indexless-placement" ')
    zonegroup_set = utils.exec_shell_cmd('radosgw-admin zonegroup placement rm --rgw-zonegroup="default" --placement-id="indexless-placement"')
    default_placement = utils.exec_shell_cmd('radosgw-admin zonegroup placement default --placement-id="default-placement"')

    log.info('restart the rgw daemons')
    restart_service = rgw_service.restart()
    if restart_service is False:
        raise TestExecError("RGW service restart failed")
    
    # check for any crashes during the execution
    crash_info=reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

if __name__ == '__main__':

    test_info = AddTestInfo('Test indexless buckets')
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = 'test_data'
        ceph_conf = CephConfOp()
        rgw_service = RGWService()
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
<<<<<<< HEAD
=======

>>>>>>> 964eb83... Add test on indexless(blind) buckets
