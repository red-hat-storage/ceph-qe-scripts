import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import socket
import v2.utils.log as log
from v2.utils.utils import FileOps
import v2.utils.utils as utils
import boto3
from v2.lib.s3.auth import Auth
from v2.lib.exceptions import TestExecError

IO_INFO_FNAME = 'io_info.yaml'


class ReadIOInfoOnS3(object):
    def __init__(self, yaml_fname=IO_INFO_FNAME):
        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type='yaml')
        self.rgw_conn = None
        self.rgw_conn2 = None
        self.buckets = []
        self.objects = []
        self.io = None

    def initialize_verify_io(self):
        log.info('***************Starting Verification*****************')
        data = self.file_op.get_data()
        rgw_user_info = data['users'][0]
        log.info('verifying data for the user: \n')
        auth = Auth(rgw_user_info)
        self.rgw_conn = auth.do_auth()
        self.rgw_conn2 = auth.do_auth_using_client()
        self.io = rgw_user_info['io']

        for each_io in self.io:
            if each_io['s3_convention'] == 'bucket':
                self.buckets.append(each_io['name'])
            if each_io['s3_convention'] == 'object':
                temp = {'name': each_io['name'],
                        'md5': each_io['md5'],
                        'bucket': each_io['bucket'],
                        'type': each_io['type']}
                self.objects.append(temp)

        log.info('buckets:\n%s' % self.buckets)
        for object in self.objects:
            log.info('object: %s' % object)
        log.info('verification of buckets starting')

    def verify_if_bucket_created(self):
        # getting list of buckets of rgw user
        buckets_from_s3 = self.rgw_conn2.list_buckets()
        print(buckets_from_s3)
        buckets_info = buckets_from_s3['Buckets']
        bucket_names_from_s3 = [x['Name'] for x in buckets_info]
        log.info('bucket names from s3: %s' % bucket_names_from_s3)
        log.info('bucket names from yaml: %s' % self.buckets)
        comp_val = set(self.buckets) == set(bucket_names_from_s3)
        return comp_val

    def verify_if_objects_created(self):
        log.info('verification of s3 objects')
        for each_key in self.objects:
            log.info('verifying data for key: %s' % os.path.basename(each_key['name']))
            log.info('bucket: %s' % each_key['bucket'])
            key_from_s3 = self.rgw_conn.Object(each_key['bucket'],os.path.basename(each_key['name']))
            log.info('got key name from s3: %s' % key_from_s3.key)

            if each_key['type'] == 'file':
                log.info('verifying md5')
                log.info('md5_local: %s' % each_key['md5'])
                key_from_s3.download_file('download.temp')
                downloaded_md5 = utils.get_md5('download.temp')
                log.info('md5_from_s3: %s' % downloaded_md5)
                if each_key['md5'] != downloaded_md5:
                    raise TestExecError("md5 not matched")
                utils.exec_shell_cmd('sudo rm -rf download.temp')


if __name__ == '__main__':
    read_io_info = ReadIOInfoOnS3()
    read_io_info.initialize_verify_io()
