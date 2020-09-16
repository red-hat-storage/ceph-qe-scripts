import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import socket
from v2.utils.utils import FileOps
from v2.utils import utils
import boto3
from v2.lib.exceptions import TestExecError
import logging

log = logging.getLogger()


IO_INFO_FNAME = 'io_info.yaml'


def verify_key(each_key, bucket):
    log.info('verifying data for key: %s' % os.path.basename(each_key['name']))
    key_from_s3 = bucket.Object(os.path.basename(each_key['name']))
    log.info('verifying size')
    log.info('size from yaml: %s' % each_key['size'])
    log.info('size from s3: %s' % key_from_s3.content_length)
    if int(each_key['size']) != int(key_from_s3.content_length):
        raise TestExecError("Size not matched")
    log.info('verifying md5')
    log.info('md5_local: %s' % each_key['md5_local'])
    key_from_s3.download_file('download.temp')
    downloaded_md5 = utils.get_md5('download.temp')
    log.info('md5_from_s3: %s' % downloaded_md5)
    if each_key['md5_local'] != downloaded_md5:
        raise TestExecError("Md5 not matched")
    utils.exec_shell_cmd('sudo rm -rf download.temp')
    log.info('verification complete for the key: %s' % key_from_s3.key)


def verify_key_with_version(each_key, bucket):
    log.info('verifying data for key: %s' % os.path.basename(each_key['name']))
    key_from_s3 = bucket.Object(os.path.basename(each_key['name']))
    no_of_versions = len(each_key['versioning_info'])
    log.info('no of versions: %s' % no_of_versions)
    for each_version in each_key['versioning_info']:
        log.info('version_id: %s' % each_version['version_id'])
        key_from_s3_with_version = key_from_s3.get(VersionId=each_version['version_id'])
        log.info('verifying size')
        log.info('size from yaml: %s' % each_version['size'])
        log.info('size from s3 %s' % key_from_s3_with_version['ContentLength'])
        if int(each_version['size'] != int(key_from_s3_with_version['ContentLength'])):
            raise TestExecError('Size not matched')
        log.info('verifying md5')
        log.info('md5_local: %s' % each_version['md5_local'])
        key_from_s3.download_file('download.temp',
                                  ExtraArgs={'VersionId': each_version['version_id']})
        downloaded_md5 = utils.get_md5('download.temp')
        log.info('md5_from_s3: %s' % downloaded_md5)
        if each_version['md5_local'] != downloaded_md5:
            raise TestExecError("Md5 not matched")
        utils.exec_shell_cmd('sudo rm -rf download.temp')
        log.info('verification complete for the key: %s ---> version_id: %s' %
                 (key_from_s3.key, each_version['version_id']))


class ReadIOInfo(object):
    def __init__(self, yaml_fname=IO_INFO_FNAME):
        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type='yaml')

    def verify_io(self):
        log.info('***************Starting Verification*****************')
        data = self.file_op.get_data()
        users = data['users']
        for each_user in users:
            log.info('verifying data for the user: \n')
            log.info('user_id: %s' % each_user['user_id'])
            log.info('access_key: %s' % each_user['access_key'])
            log.info('secret_key: %s' % each_user['secret_key'])
            conn = boto3.resource('s3',
                                  aws_access_key_id=each_user['access_key'],
                                  aws_secret_access_key=each_user['secret_key'],
                                  endpoint_url='http://%s:%s' % (
                                  socket.gethostbyname(socket.gethostname()), int(utils.get_radosgw_port_no())),
                                  use_ssl=False)
            for each_bucket in each_user['bucket']:
                log.info('verifying data for bucket: %s' % each_bucket['name'])
                bucket_from_s3 = conn.Bucket(each_bucket['name'])
                curr_versioning_status = each_bucket['curr_versioning_status']
                log.info('curr_versioning_status: %s' % curr_versioning_status)
                if not each_bucket['keys']:
                    log.info('keys are not created')
                else:
                    no_of_keys = len(each_bucket['keys'])
                    log.info('no_of_keys: %s' % no_of_keys)
                    for each_key in each_bucket['keys']:
                        versioned_keys = len(each_key['versioning_info'])
                        log.info('versioned_keys: %s' % versioned_keys)
                        if not each_key['versioning_info']:
                            log.info('not versioned key')
                            verify_key(each_key, bucket_from_s3)
                        else:
                            log.info('versioned key')
                            verify_key_with_version(each_key, bucket_from_s3)
        log.info('verification of data completed')


if __name__ == '__main__':
    read_io_info = ReadIOInfo()
    read_io_info.verify_io()
