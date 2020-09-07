"""
Test bucket lifecycle for object expiration:
Script tests the s3 object(both versioned and non-versioned) expiration rules based on:
a) Prefix filters 
b) ANDing of Prefix and TAG filters

Usage: test_bucket_lifecycle_object_expiration.py -c configs/<input-yaml>
where : <input-yaml> are test_lc_date.yaml, test_lc_multiple_rule_prefix_current_days.yaml, test_lc_rule_delete_marker.yaml, test_lc_rule_prefix_and_tag.yaml and test_lc_rule_prefix_non_current_days.yaml

Operation:

-Create a user and a bucket
-Enable versioning on the bucket as per config in the input-yaml file.
-Put objects (object count and size taken from input-yaml)
-Enable Lifecycle(lc) rule on the bucket based on the rule created as per the input-yaml
-Validate the lc rule via lifecycle_validation()
-Remove the user at successful completion.

"""

# test s3 bucket_lifecycle: object expiration operations
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser, RGWService
import traceback
import argparse
import yaml
import json
import random, time
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure, BucketIoInfo
from v2.tests.s3_swift import resuables
from v2.lib.s3 import lifecycle as lc
from v2.lib.s3 import lifecycle_validation as lc_ops

TEST_DATA_PATH = None


def test_exec(config):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()
    config.rgw_lc_debug_interval = 30
    config.rgw_lc_max_worker = 10
    log.info('making changes to ceph.conf')
    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_lc_debug_interval, str(config.rgw_lc_debug_interval))
    ceph_version = utils.exec_shell_cmd("ceph version")
    op = ceph_version.split()
    for i in op:
        if i == 'nautilus':
                ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_lc_max_worker, str(config.rgw_lc_max_worker))
    log.info('trying to restart services')
    srv_restarted = rgw_service.restart()
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info('RGW service restarted')
    
    # create user
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = Auth(user_info, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    rgw_conn2 = auth.do_auth_using_client()
    log.info('no of buckets to create: %s' % config.bucket_count)
    bucket_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=1)
    obj_list = []
    obj_tag = 'suffix1=WMV1'
    bucket = resuables.create_bucket(bucket_name, rgw_conn, user_info)
    prefix = list(map(lambda x: x,
                      [rule['Filter'].get('Prefix') or
                       rule['Filter']['And'].get('Prefix')
                       for rule in config.lifecycle_ops]))
    prefix = prefix if prefix else ['dummy1']
    if config.test_ops['enable_versioning'] is True:
        resuables.enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info)
        if config.test_ops['create_object'] is True:
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                key = prefix.pop()
                prefix.insert(0, key)
                s3_object_name = key + '.' + bucket.name + '.' + str(oc)
                obj_list.append(s3_object_name)
                if config.test_ops['version_count'] > 0:
                    for vc in range(config.test_ops['version_count']):
                        log.info('version count for %s is %s' % (s3_object_name, str(vc)))
                        log.info('modifying data: %s' % s3_object_name)
                        resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info,
                                                append_data=True,
                                                append_msg='hello object for version: %s\n' % str(vc))
                else:
                    log.info('s3 objects to create: %s' % config.objects_count)
                    resuables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info)

        life_cycle_rule = {"Rules": config.lifecycle_ops}
        resuables.put_get_bucket_lifecycle_test(bucket, rgw_conn, rgw_conn2, life_cycle_rule, config)
        lc_ops.validate_prefix_rule(bucket, config)
        if config.test_ops['delete_marker'] is True:
            life_cycle_rule_new = {"Rules": config.delete_marker_ops}
            resuables.put_get_bucket_lifecycle_test(bucket, rgw_conn, rgw_conn2, life_cycle_rule_new, config)
    if config.test_ops['enable_versioning'] is False:
        if config.test_ops['create_object'] is True:
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                key = prefix.pop()
                prefix.insert(0, key)
                s3_object_name = key + '.' + bucket.name + '.' + str(oc)
                obj_list.append(s3_object_name)
                resuables.upload_object_with_tagging(s3_object_name, bucket, TEST_DATA_PATH, config, user_info, obj_tag)
        life_cycle_rule = {"Rules": config.lifecycle_ops}
        resuables.put_get_bucket_lifecycle_test(bucket, rgw_conn, rgw_conn2, life_cycle_rule, config)
        lc_ops.validate_and_rule(bucket, config) 
    resuables.remove_user(user_info)


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
        args = parser.parse_args()
        yaml_file = args.config
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


