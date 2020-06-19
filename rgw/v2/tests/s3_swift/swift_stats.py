import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.utils.log as log
import v2.utils.utils as utils
import traceback
import argparse
import yaml
import json
import v2.lib.resource_op as swiftlib
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.swift.auth import Auth
import v2.lib.manage_data as manage_data
from v2.lib.admin import UserMgmt

def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()

    # preparing data
    user_names = ['tuffy', 'scooby', 'max']
    tenant = 'tenant'
    tenant_user_info = umgmt.create_tenant_user(tenant_name=tenant, user_id=user_names[0],
                                                displayname=user_names[0])
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_names[0])
    cmd = 'radosgw-admin quota enable --quota-scope=user --uid={uid} --tenant={tenant}'.format(
        uid=user_names[0], tenant=tenant)
    enable_user_quota = utils.exec_shell_cmd(cmd)
    cmd = 'radosgw-admin quota set --quota-scope=user --uid={uid} --tenant={tenant} --max_buckets=2000'.format(
        uid=user_names[0], tenant=tenant)
    max_bucket = utils.exec_shell_cmd(cmd)
    auth = Auth(user_info)
    rgw = auth.do_auth()
    for cc in range(config.container_count):
        container_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=cc)
        container = swiftlib.resource_op({'obj': rgw,
                                          'resource': 'put_container',
                                          'args': [container_name]})
        if container is False:
            raise TestExecError("Resource execution failed: container creation faield")

    host, ip = utils.get_hostname_ip()
    port = utils.get_radosgw_port_no()
    hostname = str(ip) + ":" + str(port)
    cmd = 'swift -A http://{hostname}/auth/1.0 -U \'{uid}\' -K \'{key}\' stat'.format(
        hostname=hostname, uid=user_info['user_id'], key=user_info['key'])
    swift_cmd = utils.exec_shell_cmd(cmd)
    swift_cmd=swift_cmd.replace(" ", "")
    swift_cmd=swift_cmd.replace("\n", ":")
    li=list(swift_cmd.split(":"))
    res_dct = {li[i]: li[i + 1] for i in range(0, len(li)-1, 2)}

    if (int(res_dct['Containers']) == config.container_count):
        cmd = 'radosgw-admin user rm --uid={uid} --tenant={tenant} --purge-data'.format(
            uid=user_names[0], tenant=tenant)
        delete_user_bucket = utils.exec_shell_cmd(cmd)
        test_info.success_status('test passed')
        sys.exit(0)
    else:
        cmd = 'radosgw-admin user rm --uid={uid} --tenant={tenant} --purge-data'.format(
            uid=user_names[0], tenant=tenant)
        delete_user_bucket = utils.exec_shell_cmd(cmd)
        test_info.failed_status('test failed')
        sys.exit(1)

if __name__ == '__main__':

    test_info = AddTestInfo('swift stats')

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

        test_exec(config)
        test_info.success_status('test passed')
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)