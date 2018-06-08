# test basic creation of buckets with objects
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
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.swift.auth import Auth
import v2.lib.manage_data as manage_data


TEST_DATA_PATH = None

# create user
# create subuser
# gen secret-key
# create container
# upload object


def test_exec(config):
    test_info = AddTestInfo('test swift user key gen')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:
        test_info.started_info()

        # preparing data

        user_names = ['tuffy', 'scooby', 'max']
        tenant1 = 'tenant'

        cmd = 'radosgw-admin user create --uid=%s --display-name="%s" --tenant=%s' %(user_names[0], user_names[0], tenant1)
        out = utils.exec_shell_cmd(cmd)

        if out is False:
            raise TestExecError("RGW User creation error")

        log.info('output :%s' % out)
        v1_as_json = json.loads(out)
        log.info('creted user_id: %s' % v1_as_json['user_id'])

        cmd2 = 'radosgw-admin subuser create --uid=%s$%s --subuser=%s:swift --tenant=%s --access=full' % (tenant1, user_names[0], user_names[0], tenant1)
        out2 = utils.exec_shell_cmd(cmd2)

        if out2 is False:
            raise TestExecError("sub-user creation error")

        v2_as_json = json.loads(out2)
        log.info('created subuser: %s' % v2_as_json['subusers'][0]['id'])

        cmd3 = 'radosgw-admin key create --subuser=%s:swift --uid=%s$%s --tenant=%s --key-type=swift --gen-secret' %(user_names[0], user_names[0], tenant1, tenant1)
        out3 = utils.exec_shell_cmd(cmd3)

        if out3 is False:
            raise TestExecError("secret_key gen error")

        v3_as_json = json.loads(out3)
        log.info('created subuser: %s\nsecret_key generated: %s' % (v3_as_json['swift_keys'][0]['user'],v3_as_json['swift_keys'][0]['secret_key']) )

        user_info = {'user_id':v3_as_json['swift_keys'][0]['user'],
                     'key': v3_as_json['swift_keys'][0]['secret_key']}

        auth = Auth(user_info)

        rgw = auth.do_auth()

        for cc in range(config.container_count):

            container_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=cc)

            container = swiftlib.resource_op({'obj': rgw,
                                              'resource': 'put_container',
                                              'args': [container_name]})

            if container is False:
                raise TestExecError("Resource execution failed: container creation faield")

            for oc in range(config.objects_count):

                swift_object_name = utils.gen_s3_object_name('%s.container.%s' %(user_names[0], cc), oc)

                log.info('object name: %s' % swift_object_name)

                object_path = os.path.join(TEST_DATA_PATH, swift_object_name)

                log.info('object path: %s' % object_path)

                object_size = utils.get_file_size(config.objects_size_range['min'],
                                                     config.objects_size_range['max'])

                data_info = manage_data.io_generator(object_path, object_size)

                if data_info is False:
                    TestExecError("data creation failed")

                log.info('uploading object: %s' % object_path)

                with open(object_path, 'r') as fp:
                    rgw.put_object(container_name, swift_object_name,
                                    contents=fp.read(),
                                    content_type='text/plain')

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

    config.container_count = doc['config']['container_count']
    config.objects_count = doc['config']['objects_count']
    config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                 'max': doc['config']['objects_size_range']['max']}

    log.info('bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (config.container_count, config.objects_count, config.objects_size_range))

    test_exec(config)