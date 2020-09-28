# test basic creation of buckets with objects
import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.utils.log import configure_logging
import v2.utils.utils as utils
from v2.tests.nfs_ganesha.initialize import PrepNFSGanesha
import traceback
import logging
import argparse
import yaml
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure, AddUserInfo
import time
import v2.tests.s3_swift.reusable as s3_reusables
from v2.tests.nfs_ganesha.verify_on_nfs import ReadIOInfoOnNFS
import v2.lib.resource_op as s3lib
from v2.utils.utils import HttpResponseParser

TEST_DATA_PATH = None
SLEEP_TIME = 60  # seconds
log = logging.getLogger()

def test_exec(rgw_user_info_file, config):

    test_info = AddTestInfo('Test Basic IO on S3')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_user_info = AddUserInfo()

    try:
        test_info.started_info()
        with open(rgw_user_info_yaml, 'r') as f:
            rgw_user_info = yaml.safe_load(f)
        mount_point = rgw_user_info['nfs_mnt_point']
        nfs_ganesha = PrepNFSGanesha(rgw_user_info_file=rgw_user_info_file)
        mounted = nfs_ganesha.initialize(write_io_info=False)
        if mounted is False:
            raise TestExecError("mount failed")
        if nfs_ganesha.rgw_user_info['nfs_version'] == 4 and \
                nfs_ganesha.rgw_user_info['Pseudo'] is not None:
            log.info('nfs version: 4')
            log.info('adding Pseudo path to writable mount point')
            mount_point = os.path.join(mount_point,nfs_ganesha.rgw_user_info['Pseudo'])
            log.info('writable mount point with Pseudo: %s' % mount_point)
        log.info('authenticating rgw user')

        # authenticate
        auth = Auth(rgw_user_info)
        rgw_conn = auth.do_auth()
        # add user_info io_info yaml file
        user_info_add = basic_io_structure.user(**rgw_user_info)
        write_user_info.add_user_info(user_info_add)
        if config.io_op_config.get('create', None) is True:
            # create buckets
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(rgw_user_info['user_id'], rand_no=bc)
                bucket = s3_reusables.create_bucket(bucket_name_to_create, rgw_conn, rgw_user_info)
                # uploading data
                log.info('s3 objects to create: %s' % config.objects_count)
                for oc in range(config.objects_count):
                    s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                    config.obj_size = utils.get_file_size(config.objects_size_range.get('min'),
                                                          config.objects_size_range.get('max'))
                    s3_reusables.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, rgw_user_info)
            log.info('verification Starts on NFS mount after %s seconds' % SLEEP_TIME)
            time.sleep(SLEEP_TIME)
            read_io_info_on_nfs = ReadIOInfoOnNFS(mount_point)
            read_io_info_on_nfs.yaml_fname = 'io_info.yaml'
            read_io_info_on_nfs.initialize_verify_io()
            read_io_info_on_nfs.verify_if_basedir_created()
            read_io_info_on_nfs.verify_if_files_created()
            log.info('verification complete, data intact')
            created_buckets = read_io_info_on_nfs.base_dirs
            created_objects = read_io_info_on_nfs.files
            if config.io_op_config.get('delete', None) is True:
                log.info('delete operation starts')
                for bucket_name in created_buckets:
                    bucket = s3lib.resource_op({'obj': rgw_conn,
                                                'resource': 'Bucket',
                                                'args': [os.path.basename(bucket_name)]}) # buckets are base dirs in NFS
                    objects = s3lib.resource_op({'obj': bucket,
                                                 'resource': 'objects',
                                                 'args': None})
                    log.info('deleting all objects in bucket')
                    objects_deleted = s3lib.resource_op({'obj': objects,
                                                         'resource': 'delete',
                                                         'args': None})
                    log.info('objects_deleted: %s' % objects_deleted)
                    if objects_deleted is False:
                        raise TestExecError('Resource execution failed: Object deletion failed')
                    if objects_deleted is not None:
                        response = HttpResponseParser(objects_deleted[0])
                        if response.status_code == 200:
                            log.info('objects deleted ')
                        else:
                            raise TestExecError("objects deletion failed")
                    else:
                        raise TestExecError("objects deletion failed")
                    log.info('deleting bucket: %s' % bucket.name)
                    bucket_deleted_status = s3lib.resource_op({'obj': bucket,
                                                               'resource': 'delete',
                                                               'args': None})
                    log.info('bucket_deleted_status: %s' % bucket_deleted_status)
                    if bucket_deleted_status is not None:
                        response = HttpResponseParser(bucket_deleted_status)
                        if response.status_code == 204:
                            log.info('bucket deleted ')
                        else:
                            raise TestExecError("bucket deletion failed")
                    else:
                        raise TestExecError("bucket deletion failed")

                log.info('verification on NFS will start after %s seconds for delete operation' % SLEEP_TIME)
                time.sleep(200)

                for basedir in created_buckets:
                    exists = os.path.exists(basedir)
                    log.info('exists status: %s' % exists)
                    if exists is True:
                        raise TestExecError("Basedir or Basedir: %s not deleted on NFS" % basedir)
                log.info('basedirs deleted')
                for each_file in created_objects:
                    log.info('verifying existence for: %s' % each_file['file'])
                    exists = os.path.exists(each_file['file'])
                    if exists:
                        raise TestExecError("files not created")
                    log.info('file deleted')
                log.info('verification of files complete, files exists and data intact')

            if config.io_op_config.get('move', None) is True:
                log.info('move operation starts')
                for each_file in created_objects:
                    # in s3 move operation is achieved by copying the same object with the new name and
                    #  deleting the old object
                    log.info('move operation for :%s' % each_file['file'])
                    new_obj_name = os.path.basename(each_file['file']) + ".moved"
                    log.info('new file name: %s' % new_obj_name)
                    new_object = s3lib.resource_op({'obj': rgw_conn,
                                                'resource': 'Object',
                                                'args': [each_file['bucket'], new_obj_name],
                                                })
                    new_object.copy_from(CopySource='%s/%s' %(each_file['bucket'],
                                                             os.path.basename(each_file['file']))) # old object name
                    old_object = s3lib.resource_op({'obj': rgw_conn,
                                                    'resource': 'Object',
                                                    'args': [each_file['bucket'], os.path.basename(each_file['file'])],
                                                    })
                    old_object.delete()
                    each_file['file'] = os.path.abspath(os.path.join(mount_point, each_file['bucket'],new_obj_name))
                log.info('verification on NFS for move operation will start after %s seconds' % SLEEP_TIME)
                time.sleep(SLEEP_TIME)
                read_io_info_on_nfs.verify_if_files_created()
                log.info('move completed, data intact')

        test_info.success_status('test passed')
        sys.exit(0)

    except Exception as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)

    except TestExecError as e:
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
    parser = argparse.ArgumentParser(description='NFS-Ganesha-RGW Automation')
    parser.add_argument('-r', dest="rgw_user_info",
                        help='RGW user info')
    parser.add_argument('-c', dest="test_config",
                        help='Test Configuration')
    parser.add_argument('-log_level', dest='log_level',
                        help='Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]',
                        default='info')
    args = parser.parse_args()

    rgw_user_info_yaml = args.rgw_user_info
    test_config_yaml = args.test_config
    log_f_name = os.path.basename(os.path.splitext(test_config_yaml)[0])
    configure_logging(f_name=log_f_name,
                      set_level=args.log_level.upper())
    config = Config(test_config_yaml)
    config.read()
    test_exec(rgw_user_info_yaml, config)
