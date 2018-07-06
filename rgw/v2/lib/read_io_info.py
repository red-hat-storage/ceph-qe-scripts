import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import socket
from v2.utils import log
from v2.utils.utils import FileOps
from v2.utils import utils
import boto3
from v2.lib.exceptions import TestExecError

IO_INFO_FNAME = 'io_info.yaml'


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
                                 endpoint_url='http://%s:%s' % (socket.gethostname(), int(utils.get_radosgw_port_no())),
                                 use_ssl=False)

            for each_bucket in each_user['bucket']:

                log.info('verifying data for bucket: %s' % each_bucket['name'])

                bucket_from_s3 = conn.Bucket(each_bucket['name'])

                if not each_bucket['keys']:

                    log.info('keys are not created')

                else:

                    for each_key in each_bucket['keys']:

                        log.info('verifying data for key: %s' % os.path.basename(each_key['name']))

                        key_from_s3 = bucket_from_s3.Object(os.path.basename(each_key['name']))

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

        log.info('verification of data completed')

if __name__ == '__main__':

    read_io_info = ReadIOInfo()

    read_io_info.verify_io()