"""
# test storage policy for s3 and swift interfaces

Usage : test_storage_policy.py -c configs/input-yaml
where input-yaml is test_storage_policy_s3.yaml and test_storage_policy_swift.yaml

Operation:
- Create a pool '.rgw.buckets.special'
- Create a realm
- Modify default zonegroup to be added in the realm
- Modify zonegroup and zone and add a special-placement rule under default-placemnt as mentioned in the 'special_placement_info' in the script.
- Create user, bucket and objects after modifying the default-placement hence verifying the storage policy.

"""
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3_swift_lib
from v2.lib.swift.auth import Auth
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

    # create pool
    pool_name = '.rgw.buckets.special'
    pg_num = '8'
    pgp_num = '8'
    pool_create = 'sudo ceph osd pool create "%s" %s %s replicated' % (pool_name, pg_num, pgp_num)
    pool_create_exec = utils.exec_shell_cmd(pool_create)
    if pool_create_exec is False:
        raise TestExecError("Pool creation failed")
    # create realm
    realm_name = 'buz-tickets'
    log.info('creating realm name')
    realm_create = 'sudo radosgw-admin realm create --rgw-realm=%s' % realm_name
    realm_create_exec = utils.exec_shell_cmd(realm_create)
    if realm_create_exec is False:
        raise TestExecError("cmd execution failed")
    # sample output of create realm
    """
    {
        "id": "0956b174-fe14-4f97-8b50-bb7ec5e1cf62",
        "name": "buz-tickets",
        "current_period": "1950b710-3e63-4c41-a19e-46a715000980",
        "epoch": 1
    }
    """
    log.info('modify zonegroup ')
    modify = 'sudo radosgw-admin zonegroup modify --rgw-zonegroup=default --rgw-realm=%s --master' % realm_name
    modify_exec = utils.exec_shell_cmd(modify)
    if modify_exec is False:
        raise TestExecError("cmd execution failed")
    # get the zonegroup
    zonegroup_file = 'zonegroup.json'
    get_zonegroup = 'sudo radosgw-admin zonegroup --rgw-zonegroup=default get > %s' % zonegroup_file
    get_zonegroup_exec = utils.exec_shell_cmd(get_zonegroup)
    if get_zonegroup_exec is False:
        raise TestExecError("cmd execution failed")
    add_to_placement_targets = {
        "name": "special-placement",
        "tags": []
    }
    fp = open(zonegroup_file, 'r')
    zonegroup_txt = fp.read()
    fp.close()
    log.info('got zonegroup info: \n%s' % zonegroup_txt)
    zonegroup = json.loads(zonegroup_txt)
    log.info('adding placement targets')
    zonegroup['placement_targets'].append(add_to_placement_targets)
    with open(zonegroup_file, 'w') as fp:
        json.dump(zonegroup, fp)
    zonegroup_set = 'sudo radosgw-admin zonegroup set < %s' % zonegroup_file
    zonegroup_set_exec = utils.exec_shell_cmd(zonegroup_set)
    if zonegroup_set_exec is False:
        raise TestExecError("cmd execution failed")
    log.info('zone group update completed')
    log.info('getting zone file')
    # get zone
    log.info('getting zone info')
    zone_file = 'zone.json'
    get_zone = 'sudo radosgw-admin zone --rgw-zone=default  get > zone.json'
    get_zone_exec = utils.exec_shell_cmd(get_zone)
    if get_zone_exec is False:
        raise TestExecError("cmd execution failed")
    fp = open(zone_file, 'r')
    zone_info = fp.read()
    fp.close()
    log.info('zone_info :\n%s' % zone_info)
    zone_info_cleaned = json.loads(zone_info)
    special_placement_info = {
        "key": "special-placement",
        "val": {
            "index_pool": ".rgw.buckets.index",
            "data_pool": ".rgw.buckets.special",
            "data_extra_pool": ".rgw.buckets.extra"
        }
    }
    log.info('adding  special placement info')
    zone_info_cleaned['placement_pools'].append(special_placement_info)
    with open(zone_file, 'w+') as fp:
        json.dump(zone_info_cleaned, fp)
    zone_file_set = 'sudo radosgw-admin zone set < %s' % zone_file
    zone_file_set_exec = utils.exec_shell_cmd(zone_file_set)
    if zone_file_set_exec is False:
        raise TestExecError("cmd execution failed")
    log.info('zone info updated ')
    zone_group_update_set = 'radosgw-admin period update --commit'
    zone_group_update_set_exec = utils.exec_shell_cmd(zone_group_update_set)
    log.info(zone_group_update_set_exec)
    restarted = rgw_service.restart()
    if restarted is False:
        raise TestExecError("service restart failed")
    if config.rgw_client == 'rgw':
        log.info('client type is rgw')
        rgw_user_info = s3_swift_lib.create_users(1)
        auth = Auth(rgw_user_info)
        rgw_conn = auth.do_auth()
        # create bucket
        bucket_name = utils.gen_bucket_name_from_userid(rgw_user_info['user_id'], 0)
        bucket = reusable.create_bucket(bucket_name, rgw_conn, rgw_user_info)
        # create object
        s3_object_name = utils.gen_s3_object_name(bucket_name, 0)
        reusable.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, rgw_user_info)
    if config.rgw_client == 'swift':
        log.info('client type is swift')
        user_names = ['tuffy', 'scooby', 'max']
        tenant = 'tenant'
        umgmt = UserMgmt()
        umgmt.create_tenant_user(tenant_name=tenant, user_id=user_names[0],
                                 displayname=user_names[0])
        user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_names[0])
        auth = Auth(user_info)
        rgw = auth.do_auth()
        container_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=0)
        container = s3_swift_lib.resource_op({'obj': rgw,
                                              'resource': 'put_container',
                                              'args': [container_name]})
        if container is False:
            raise TestExecError("Resource execution failed: container creation faield")

        swift_object_name = utils.gen_s3_object_name('%s.container.%s' % (user_names[0], 0), 0)
        log.info('object name: %s' % swift_object_name)
        object_path = os.path.join(TEST_DATA_PATH, swift_object_name)
        log.info('object path: %s' % object_path)
        object_size = utils.get_file_size(config.objects_size_range['min'],config.objects_size_range['max'])
        data_info = manage_data.io_generator(object_path, object_size)
        # upload object
        if data_info is False:
            TestExecError("data creation failed")
        log.info('uploading object: %s' % object_path)
        with open(object_path, 'r') as fp:
            rgw.put_object(container_name, swift_object_name,
                           contents=fp.read(),
                           content_type='text/plain')


if __name__ == '__main__':

    test_info = AddTestInfo('storage_policy test')
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

        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)

        test_info.name = 'storage_policy for %s' % config.rgw_client
        test_info.started_info()

        config.objects_size_range = doc['config']['objects_size_range']
        config.rgw_client = doc['rgw_client']

        test_exec(config)
        test_info.success_status('test passed')
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)
