"""
test_swift_bulk_delete - Test swift bulk delete operation on cluster

Usage: test_swift_bulk_delete.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_swift_bulk_delete.yaml

Operation:
    Create swift user
    Create a single container
    Upload 1000 objects in container
    Delete all objects from container
    Delete container
"""

# test swift bulk delete
import os, sys
import requests

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.utils.utils as utils
from v2.utils.log import configure_logging
import traceback
import argparse
import yaml
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser, RGWService
import json
import v2.lib.resource_op as swiftlib
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
import v2.lib.manage_data as manage_data
from v2.lib.admin import UserMgmt
import logging, time

log = logging.getLogger()


TEST_DATA_PATH = None


# create user
# create subuser
# create container
# upload object
def fill_container(rgw, container_name, user_id, oc, cc, size):
    swift_object_name = utils.gen_s3_object_name('%s.container.%s' % (user_id, cc), oc)
    log.info('object name: %s' % swift_object_name)
    object_path = os.path.join(TEST_DATA_PATH, swift_object_name)
    log.info('object path: %s' % object_path)
    data_info = manage_data.io_generator(object_path, size)
    # upload object
    if data_info is False:
        raise TestExecError("data creation failed")
    log.info('uploading object: %s' % object_path)
    with open(object_path, 'r') as fp:
        rgw.put_object(container_name, swift_object_name,
                       contents=fp.read(),
                       content_type='text/plain')
    return swift_object_name
def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    rgw_service = RGWService()
    # preparing data
    user_names = ['tuffy', 'scooby', 'max']
    tenant = 'tenant'
    tenant_user_info = umgmt.create_tenant_user(tenant_name=tenant, user_id=user_names[0],
                                                displayname=user_names[0])
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_names[0])
    auth = Auth(user_info)
    rgw = auth.do_auth()

    container_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=cc)
    container = swiftlib.resource_op({'obj': rgw,
                                      'resource': 'put_container',
                                      'args': [container_name]})
    if container is False:
        raise TestExecError("Resource execution failed: container creation faield")
    for oc, size in list(config.mapped_sizes.items()):
        # upload objects to the container
        swift_object_name = fill_container(rgw, container_name, user_names[0], oc, cc, size)
        # delete all uploaded objects
        log.info('deleting all swift objects')
    # delete container
    auth_response = rgw.get_auth()
    token = auth_response[1]
    # test.txt file should contain container_name
    with open("test.txt", "w") as f:
        f.write(container_name)
    ip_and_port = rgw.authurl.split('/')[2]
    url = 'http://{}/swift/v1/?bulk-delete'.format(ip_and_port)
    test_file = open("test.txt", "r")
    headers = {"Accept": "application/json", "Content-Type": "text/plain",
               "X-Auth-Token": token}
    response = requests.delete(url, headers=headers,
                               files={"form_field_name": test_file})
    if response.status_code == 200:
        print('Bulk delete succeeded')
    else:
        print('Bulk delete failed with status code: %d' response.status_code)
    log.info('deleting swift container')
    rgw.delete_container(container_name)

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
