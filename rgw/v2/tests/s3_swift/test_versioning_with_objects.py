# test basic creation of buckets with objects
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
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import random

TEST_DATA_PATH = None


def test_exec(config):

    test_info = AddTestInfo('test versioning with objects')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:

        test_info.started_info()

        # create user

        all_users_info = s3lib.create_users(config.user_count)

        for each_user in all_users_info:

            # authenticate

            auth = Auth(each_user)
            rgw_conn = auth.do_auth()

            s3_object_names = []

            # create buckets

            log.info('no of buckets to create: %s' % config.bucket_count)

            for bc in range(config.bucket_count):

                bucket_name_to_create = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=bc)

                log.info('creating bucket with name: %s' % bucket_name_to_create)

                # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)

                bucket = s3lib.resource_op({'obj': rgw_conn,
                                            'resource': 'Bucket',
                                            'args': [bucket_name_to_create]})

                # created = s3_ops.resource_op(bucket, 'create', None, **{'access_key': each_user['access_key']})

                created = s3lib.resource_op({'obj': bucket,
                                             'resource': 'create',
                                             'args': None,
                                             'extra_info': {'access_key': each_user['access_key']}})

                if created is False:
                    raise TestExecError("Resource execution failed: bucket creation faield")

                if created is not None:

                    response = HttpResponseParser(created)

                    if response.status_code == 200:
                       log.info('bucket created')

                    else:
                        raise TestExecError("bucket creation failed")

                else:
                    raise TestExecError("bucket creation failed")

                # getting bucket version object

                if config.test_ops['enable_version'] is True:

                    log.info('bucket versionig test on bucket: %s' % bucket.name)

                    # bucket_versioning = s3_ops.resource_op(rgw_conn, 'BucketVersioning', bucket.name)

                    bucket_versioning = s3lib.resource_op({'obj': rgw_conn,
                                                           'resource': 'BucketVersioning',
                                                           'args': [bucket.name]})

                    # checking the versioning status

                    # version_status = s3_ops.resource_op(bucket_versioning, 'status')

                    version_status = s3lib.resource_op({'obj': bucket_versioning,
                                                        'resource': 'status',
                                                        'args': None
                                                        })

                    if version_status is None:

                       log.info('bucket versioning still not enabled')

                    # enabling bucket versioning

                    # version_enable_status = s3_ops.resource_op(bucket_versioning, 'enable')

                    version_enable_status = s3lib.resource_op({'obj': bucket_versioning,
                                                               'resource': 'enable',
                                                               'args': None})

                    response = HttpResponseParser(version_enable_status)

                    if response.status_code == 200:
                        log.info('version enabled')

                    else:
                        raise TestExecError("version enable failed")

                    if config.objects_count > 0:



                        log.info('s3 objects to create: %s' % config.objects_count)

                        for oc in range(config.objects_count):

                            # versioning upload

                            s3_object_name = utils.gen_s3_object_name(bucket_name_to_create,str(oc))

                            s3_object_names.append(s3_object_name)

                            log.info('s3 object name: %s' % s3_object_name)

                            log.info('versioning count: %s' % config.version_count)

                            s3_object_size = utils.get_file_size(config.objects_size_range['min'],
                                                                 config.objects_size_range['max'])

                            s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, str(oc))

                            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)

                            original_data_info = manage_data.io_generator(s3_object_path, s3_object_size)

                            if original_data_info is False:
                                TestExecError("data creation failed")

                            for vc in range(config.version_count):

                                log.info('version count for %s is %s' % (s3_object_name, str(vc)))

                                log.info('modifying data: %s' % s3_object_name)

                                modified_data_info = manage_data.io_generator(s3_object_path, s3_object_size, data='append',
                                                                     **{'message': '\nhello object for version: %s\n' % str(vc)})

                                if modified_data_info is False:
                                    TestExecError("data modification failed")

                                log.info('uploading s3 object: %s' % s3_object_path)

                                upload_info = dict({'access_key': each_user['access_key']}, **modified_data_info)

                                object_uploaded_status = s3lib.resource_op({'obj': bucket,
                                                                            'resource': 'upload_file',
                                                                            'args': [modified_data_info['name'], s3_object_name],
                                                                            'extra_info': upload_info})

                                if object_uploaded_status is False:
                                    raise TestExecError("Resource execution failed: object upload failed")

                                if object_uploaded_status is None:
                                    log.info('object uploaded')

                            log.info('all versions for the object: %s\n' % s3_object_name)

                            versions = bucket.object_versions.filter(Prefix=s3_object_name)

                            for version in versions:
                                log.info('key_name: %s --> version_id: %s' %(version.object_key, version.version_id))

                            if config.test_ops['copy_to_version'] is True:

                                # reverting object to one of the versions ( randomly chosen )

                                version_id_to_copy = random.choice([v.version_id for v in versions])

                                log.info('version_id_to_copy: %s' % version_id_to_copy)

                                s3_obj = rgw_conn.Object(bucket.name, s3_object_name)

                                log.info('current version_id: %s' % s3_obj.version_id)

                                copy_response = s3_obj.copy_from(CopySource={'Bucket': bucket.name,
                                                                             'Key': s3_object_name,
                                                                             'VersionId': version_id_to_copy})

                                log.info('copy_response: %s' % copy_response)

                                if copy_response is None:
                                    raise TestExecError("copy object from version id failed")

                                # current_version_id = copy_response['VersionID']

                                log.info('current_version_id: %s' % s3_obj.version_id )

                                # delete the version_id_to_copy object

                                s3_obj.delete(VersionId=version_id_to_copy)

                                log.info('all versions for the object after the copy operation: %s\n' % s3_object_name)

                                for version in versions:
                                    log.info('key_name: %s --> version_id: %s' % (version.object_key, version.version_id))

                                # log.info('downloading current s3object: %s' % s3_object_name)

                                # s3_obj.download_file(s3_object_name + ".download")

                            if config.test_ops['delete_object_versions'] is True:

                                log.info('deleting s3_obj keys and its versions')

                                s3_obj = s3lib.resource_op({'obj': rgw_conn,
                                                            'resource': 'Object',
                                                            'args': [bucket.name, s3_object_name]})

                                log.info('deleting versions for s3 obj: %s' % s3_object_name)

                                for version in versions:

                                    log.info('trying to delete obj version: %s' % version.version_id)

                                    del_obj_version = s3lib.resource_op({'obj': s3_obj,
                                                                         'resource': 'delete',
                                                                         'kwargs': dict(VersionId=version.version_id)})

                                    log.info('response:\n%s' % del_obj_version)

                                    if del_obj_version is not None:

                                        response = HttpResponseParser(del_obj_version)

                                        if response.status_code == 204:
                                            log.info('version deleted ')

                                        else:
                                            raise TestExecError("version  deletion failed")

                                    else:
                                        raise TestExecError("version deletion failed")

                    if config.test_ops['suspend_version'] is True:

                        # suspend_version_status = s3_ops.resource_op(bucket_versioning, 'suspend')
                        suspend_version_status = s3lib.resource_op({'obj': bucket_versioning,
                                                                    'resource': 'suspend',
                                                                    'args': None})

                        response = HttpResponseParser(suspend_version_status)

                        if response.status_code == 200:
                            log.info('versioning suspended')

                        else:
                            raise TestExecError("version suspend failed")

                if config.test_ops['upload_after_suspend'] is True:


                    log.info('trying to upload after suspending versioning on bucket')

                    for s3_object_name in s3_object_names:

                        # non versioning upload

                        log.info('s3 object name: %s' % s3_object_name)

                        s3_object_size = utils.get_file_size(config.objects_size_range['min'],
                                                             config.objects_size_range['max'])

                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)

                        non_version_data_info = manage_data.io_generator(s3_object_path, s3_object_size, op="append",
                                                                    **{'message': '\nhello object for non version\n'})

                        if non_version_data_info is False:
                            TestExecError("data creation failed")

                        log.info('uploading s3 object: %s' % s3_object_path)

                        upload_info = dict({'access_key': each_user['access_key']}, **non_version_data_info)

                        object_uploaded_status = s3lib.resource_op({'obj': bucket,
                                                                    'resource': 'upload_file',
                                                                    'args': [non_version_data_info['name'],
                                                                             s3_object_name],
                                                                    'extra_info': upload_info})

                        if object_uploaded_status is False:
                            raise TestExecError("Resource execution failed: object upload failed")

                        if object_uploaded_status is None:
                            log.info('object uploaded')

                        s3_object_download_path = os.path.join(TEST_DATA_PATH, s3_object_name+".download")

                        object_downloaded_status = s3lib.resource_op({'obj': bucket,
                                                                      'resource': 'download_file',
                                                                      'args': [s3_object_name,
                                                                               s3_object_download_path],
                                                                      })

                        if object_downloaded_status is False:
                            raise TestExecError("Resource execution failed: object download failed")

                        if object_downloaded_status is None:
                            log.info('object downloaded')

                        # checking md5 of the downloaded file

                        s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)

                        log.info('s3_object_downloaded_md5: %s' % s3_object_downloaded_md5)
                        log.info('s3_object_uploaded_md5: %s' % non_version_data_info['md5'])


        test_info.success_status('test passed')

        sys.exit(0)

    except Exception,e:
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
    config.shards = None
    config.max_objects = None
    if yaml_file is None:
        config.user_count = 2
        config.bucket_count = 10
        config.objects_count = 2
        config.objects_size_range = {'min': 10, 'max': 50}

    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.user_count = doc['config']['user_count']
        config.bucket_count = doc['config']['bucket_count']
        config.objects_count = doc['config']['objects_count']
        config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                     'max': doc['config']['objects_size_range']['max']}

        config.test_ops = doc['config']['test_ops']
        config.version_count = doc['config']['version_count']

    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (config.user_count, config.bucket_count, config.objects_count, config.objects_size_range))

    log.info('test_ops: %s' % config.test_ops)

    test_exec(config)




