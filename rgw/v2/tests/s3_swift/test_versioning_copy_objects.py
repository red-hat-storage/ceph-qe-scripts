# Test Desc:  test of version copy objects to different buckets
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure,  BucketIoInfo, KeyIoInfo
import random
from v2.tests.s3_swift import resuables

TEST_DATA_PATH = None


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_bucket_io_info = BucketIoInfo()
    write_key_io_info = KeyIoInfo()

    version_count = 3
    # create user
    s3_user = s3lib.create_users(1)[0]
    # authenticate
    auth = Auth(s3_user, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    b1_name = 'bucky.1e'  # bucket 1
    b1_k1_name = b1_name + ".key.1"  # key1
    b1_k2_name = b1_name + ".key.2"  # key2
    b2_name = 'bucky.2e'  # bucket 2
    b2_k1_name = b2_name + ".key.1"  # key1
    b2_k2_name = b2_name + ".key.2"  # key2
    b1 = resuables.create_bucket(b1_name, rgw_conn, s3_user)
    b2 = resuables.create_bucket(b2_name, rgw_conn, s3_user)
    # enable versioning on b1
    resuables.enable_versioning(b1, rgw_conn, s3_user, write_bucket_io_info)
    # upload object to version enabled bucket b1
    obj_sizes = list(config.mapped_sizes.values())
    config.obj_size = obj_sizes[0]
    for vc in range(version_count):
        resuables.upload_object(b1_k1_name, b1, TEST_DATA_PATH, config, s3_user, append_data=True,
                                append_msg='hello vc count: %s' % str(vc))
    # upload object to non version bucket b2
    config.obj_size = obj_sizes[1]
    resuables.upload_object(b2_k1_name, b2, TEST_DATA_PATH, config, s3_user)
    # copy b2_k1 to b1 and check if version id is created, expectation: version id should be created
    # copy b1_k1 to b2 and check if version id is created, expectation: version id should not be present
    b1_k2 = s3lib.resource_op({'obj': rgw_conn,
                               'resource': 'Object',
                               'args': [b1.name, b1_k2_name]})
    b2_k2 = s3lib.resource_op({'obj': rgw_conn,
                               'resource': 'Object',
                               'args': [b2.name, b2_k2_name]})
    log.info('copy from b2_k1 key to b1_k2 key to bucket 1 -> version enabled bucket')
    copy_response = b1_k2.copy_from(CopySource={'Bucket': b2.name,
                                                'Key': b2_k1_name, })
    log.info('copy_response: %s' % copy_response)
    if copy_response is None:
        raise TestExecError("copy object failed")
    log.info('checking if copies object has version id created')
    b1_k2_version_id = b1_k2.version_id
    log.info('version id: %s' % b1_k2_version_id)
    if b1_k2_version_id is None:
        raise TestExecError('Version ID not created for the copied object on to the versioned enabled bucket')
    else:
        log.info('Version ID created for the copied object on to the versioned bucket')
    all_objects_in_b1 = b1.objects.all()
    log.info('all objects in bucket 1')
    for obj in all_objects_in_b1:
        log.info('object_name: %s' % obj.key)
        versions = b1.object_versions.filter(Prefix=obj.key)
        log.info('displaying all versions of the object')
        for version in versions:
            log.info(
                'key_name: %s --> version_id: %s' % (version.object_key, version.version_id))
    log.info('-------------------------------------------')
    log.info('copy from b1_k1 key to b2_k2 to bucket 2 -> non version bucket')
    copy_response = b2_k2.copy_from(CopySource={'Bucket': b1.name,
                                                'Key': b1_k1_name, })
    log.info('copy_response: %s' % copy_response)
    if copy_response is None:
        raise TestExecError("copy object failed")
    log.info('checking if copies object has version id created')
    b2_k2_version_id = b2_k2.version_id
    log.info('version id: %s' % b2_k2_version_id)
    if b2_k2_version_id is None:
        log.info('Version ID not created for the copied object on to the non versioned bucket')
    else:
        raise TestExecError('Version ID created for the copied object on to the non versioned bucket')
    all_objects_in_b2 = b2.objects.all()
    log.info('all objects in bucket 2')
    for obj in all_objects_in_b2:
        log.info('object_name: %s' % obj.key)
        versions = b2.object_versions.filter(Prefix=obj.key)
        log.info('displaying all versions of the object')
        for version in versions:
            log.info(
                'key_name: %s --> version_id: %s' % (version.object_key, version.version_id))


if __name__ == '__main__':

    test_info = AddTestInfo('test versioning with objects')
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
        config.objects_count = 2
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

