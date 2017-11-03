import os
import sys
import boto.exception as exception
import socket
import boto.s3.connection
from boto.s3.key import Key
sys.path.append(os.path.abspath(os.path.join(__file__, "../..")))
import utils.log as log
from utils.utils import FileOps
import utils.utils as utils

IO_INFO_FNAME = 'io_info.yaml'


class ReadIOInfo(object):
    def __init__(self, yaml_fname=IO_INFO_FNAME):

        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type='yaml')

    def verify_io(self):

        data = self.file_op.get_data()

        users = data['users']

        try:

            for each_user in users:

                log.info('verifying data for the user: \n')
                log.info('user_id: %s' % each_user['user_id'])
                log.info('access_key: %s' % each_user['access_key'])
                log.info('secret_key: %s' % each_user['secret_key'])

                conn = boto.connect_s3(
                        aws_access_key_id=each_user['access_key'],
                        aws_secret_access_key=each_user['secret_key'],
                        host=socket.gethostname(),
                        port=int(utils.get_radosgw_port_no()),
                        is_secure=False,
                        calling_format=boto.s3.connection.OrdinaryCallingFormat()
                    )

                for each_bucket in each_user['bucket']:

                    log.info('verifying data for bucket: %s' % each_bucket['name'])

                    bucket_from_s3 = conn.get_bucket(each_bucket['name'])

                    if not each_bucket['keys']:

                        log.info('keys are not created')

                    else:

                        for each_key in each_bucket['keys']:

                            log.info('verifying data for key: %s' % each_key['name'])

                            if each_key['test_op_code'] == 'create':

                                key_from_s3 = bucket_from_s3.get_key(each_key['name'])

                                log.info('verifying size')

                                log.info('size from yaml: %s' % each_key['size'])
                                log.info('size from s3: %s' % key_from_s3.size)

                                if int(each_key['size']) != int(key_from_s3.size):
                                    raise Exception, "Size not matched"

                                log.info('verifying md5')

                                log.info('md5_on_s3_from yaml: %s' % each_key['md5_on_s3'])
                                log.info('md5_on_s3: %s' % key_from_s3.etag.replace('"', ''))

                                if each_key['md5_on_s3'] != key_from_s3.etag.replace('"', ''):
                                    raise Exception, "Md5 not matched"

                                log.info('verification complete for the key: %s' % key_from_s3.name)

                            if each_key['test_op_code'] == 'delete':

                                key_from_s3 = bucket_from_s3.get_key(each_key['name'])

                                if key_from_s3 is None:
                                    log.info('key deleted')

                                if  key_from_s3 is not None:
                                    log.info('key exists')
                                    raise Exception, "Key is not deleted"

            log.info('verification of data completed, data intact')

        except Exception, e :
            log.error(e)
            log.error('verification failed')
            exit(1)


if __name__ == '__main__':

    read_io_info = ReadIOInfo()

    read_io_info.verify_io()