import os, sys, glob

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v2.lib.resource_op as s3lib
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
from v2.lib.exceptions import TestExecError
import v2.lib.manage_data as manage_data
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure, BucketIoInfo, KeyIoInfo

io_info_initialize = IOInfoInitialize()
basic_io_structure = BasicIOInfoStructure()
write_bucket_io_info = BucketIoInfo()
write_key_io_info = KeyIoInfo()


def create_bucket(bucket_name, rgw, user_info):
    log.info('creating bucket with name: %s' % bucket_name)
    # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)
    bucket = s3lib.resource_op({'obj': rgw,
                                'resource': 'Bucket',
                                'args': [bucket_name]})
    created = s3lib.resource_op({'obj': bucket,
                                 'resource': 'create',
                                 'args': None,
                                 'extra_info': {'access_key': user_info['access_key']}})
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
    return bucket


def upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info, append_data=False, append_msg=None):
    log.info('s3 object name: %s' % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info('s3 object path: %s' % s3_object_path)
    s3_object_size = config.obj_size
    if append_data is True:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size, op='append',
                                             **{'message': '\n%s' % append_msg})
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    log.info('uploading s3 object: %s' % s3_object_path)
    upload_info = dict({'access_key': user_info['access_key']}, **data_info)
    s3_obj = s3lib.resource_op({'obj': bucket,
                                'resource': 'Object',
                                'args': [s3_object_name],
                                })
    object_uploaded_status = s3lib.resource_op({'obj': s3_obj,
                                                'resource': 'upload_file',
                                                'args': [s3_object_path],
                                                'extra_info': upload_info})
    if object_uploaded_status is False:
        raise TestExecError("Resource execution failed: object upload failed")
    if object_uploaded_status is None:
        log.info('object uploaded')


def upload_mutipart_object(s3_object_name, bucket, TEST_DATA_PATH, config, user_info, append_data=False,
                            append_msg=None):
    log.info('s3 object name: %s' % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info('s3 object path: %s' % s3_object_path)
    s3_object_size = config.obj_size
    split_size = config.split_size if hasattr(config, 'split_size') else 5
    log.info('split size: %s' % split_size)
    if append_data is True:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size, op='append',
                                             **{'message': '\n%s' % append_msg})
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    mp_dir = os.path.join(TEST_DATA_PATH, s3_object_name + '.mp.parts')
    log.info('mp part dir: %s' % mp_dir)
    log.info('making multipart object part dir')
    mkdir = utils.exec_shell_cmd('sudo mkdir %s' % mp_dir)
    if mkdir is False:
        raise TestExecError('mkdir failed creating mp_dir_name')
    utils.split_file(s3_object_path, split_size, mp_dir+"/")
    parts_list = sorted(glob.glob(mp_dir + '/' + '*'))
    log.info('parts_list: %s' % parts_list)
    log.info('uploading s3 object: %s' % s3_object_path)
    upload_info = dict({'access_key': user_info['access_key'], 'upload_type': 'multipart'}, **data_info)
    s3_obj = s3lib.resource_op({'obj': bucket,
                                'resource': 'Object',
                                'args': [s3_object_name],
                                })
    log.info('initiating multipart upload')
    mpu = s3lib.resource_op({'obj': s3_obj,
                             'resource': 'initiate_multipart_upload',
                             'args': None,
                             'extra_info': upload_info})
    part_number = 1
    parts_info = {'Parts': []}
    log.info('no of parts: %s' % len(parts_list))
    for each_part in parts_list:
        log.info('trying to upload part: %s' % each_part)
        part = mpu.Part(part_number)
        # part_upload_response = part.upload(Body=open(each_part))
        part_upload_response = s3lib.resource_op({'obj': part,
                                                  'resource': 'upload',
                                                  'kwargs': dict(Body=open(each_part))})
        if part_upload_response is not False:
            response = HttpResponseParser(part_upload_response)
            if response.status_code == 200:
                log.info('part uploaded')
                if config.local_file_delete is True:
                    log.info('deleting local file part')
                    utils.exec_shell_cmd('sudo rm -rf %s' % each_part)
            else:
                raise TestExecError("part uploading failed")
        part_info = {'PartNumber': part_number, 'ETag': part_upload_response['ETag']}
        parts_info['Parts'].append(part_info)
        if each_part != parts_list[-1]:
            # increase the part number only if the current part is not the last part
            part_number += 1
        log.info('curr part_number: %s' % part_number)
    # log.info('parts_info so far: %s'% parts_info)
    if len(parts_list) == part_number:
        log.info('all parts upload completed')
        mpu.complete(MultipartUpload=parts_info)
        log.info('multipart upload complete for key: %s' % s3_object_name)


def enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info):
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
        write_bucket_io_info.add_versioning_status(user_info['access_key'], bucket.name,
                                                   'enabled')
    else:
        raise TestExecError("version enable failed")


def rename_user(old_username, new_username, tenant=False):
    """"""
    if tenant:
        cmd = 'radosgw-admin user rename --uid=%s --new-uid=%s --tenant=%s' % (
            old_username, new_username, tenant)
    else:
        cmd = 'radosgw-admin user rename --uid=%s --new-uid=%s' % (
            old_username, new_username)
    out = utils.exec_shell_cmd(cmd)
    log.info('Renamed user %s to %s' % (old_username, new_username))
    return out


def rename_bucket(old_bucket, new_bucket, userid, tenant=False):
    """"""
    if tenant:
        cmd = 'radosgw-admin bucket link --bucket=%s --bucket-new-name=%s --uid=%s --tenant=%s' % (
            str(tenant) + '/' + old_bucket, str(tenant) + '/' + new_bucket, userid, tenant)
    else:
        cmd = 'radosgw-admin bucket link --bucket=%s --bucket-new-name=%s --uid=%s' % ('/' + old_bucket,
                                                                                       new_bucket, userid)
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW Bucket rename error")
    return out


def unlink_bucket(curr_uid, bucket, tenant=False):
    """"""
    if tenant:
        cmd = 'radosgw-admin bucket unlink --bucket=%s --uid=%s --tenant=%s' % (bucket, curr_uid,
                                                                                tenant)
    else:
        cmd = 'radosgw-admin bucket unlink --bucket=%s --uid=%s' % (bucket, curr_uid)
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW Bucket unlink error")
    return out


def link_chown_to_tenanted(new_uid, bucket, tenant):
    """"""
    cmd = 'radosgw-admin bucket link --bucket=%s --uid=%s --tenant=%s' % (
        '/' + bucket, new_uid, tenant)
    out1 = utils.exec_shell_cmd(cmd)
    if out1 is False:
        raise TestExecError("RGW Bucket link error")
    log.info('output :%s' % out1)
    cmd1 = 'radosgw-admin bucket chown --bucket=%s --uid=%s --tenant=%s' % (bucket, new_uid,
                                                                            tenant)
    out2 = utils.exec_shell_cmd(cmd1)
    if out2 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info('output :%s' % out2)
    return


def link_chown_to_nontenanted(new_uid, bucket, tenant):
    """"""
    cmd2 = 'radosgw-admin bucket link --bucket=%s --uid=%s' % (
        tenant + '/' + bucket, new_uid)
    out3 = utils.exec_shell_cmd(cmd2)
    if out3 is False:
        raise TestExecError("RGW Bucket link error")
    log.info('output :%s' % out3)
    cmd3 = 'radosgw-admin bucket chown --bucket=%s --uid=%s' % (bucket, new_uid)
    out4 = utils.exec_shell_cmd(cmd3)
    if out4 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info('output :%s' % out4)
    return
