import os
import sys
import logging

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import socket
from v2.utils.utils import FileOps
import v2.utils.utils as utils
import boto3
from v2.lib.s3.auth import Auth
from v2.lib.exceptions import TestExecError

IO_INFO_FNAME = 'io_info.yaml'
log = logging.getLogger()


class ReadIOInfoOnNFS(object):

    def __init__(self, mount_point, yaml_fname=IO_INFO_FNAME, ):
        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type='yaml')
        self.mount_point = mount_point
        self.base_dirs = []
        self.files = []

    def initialize_verify_io(self):
        log.info('***************Starting Verification*****************')
        data = self.file_op.get_data()
        user_info = data['users'][0]

        for each_bucket in user_info['bucket']:
            path = os.path.join(self.mount_point, os.path.basename(each_bucket['name']))
            base_dir_full_path = os.path.abspath(path)
            self.base_dirs.append(base_dir_full_path)
            if not each_bucket['keys']:
                log.info('keys are not created')
            else:
                for each_key in each_bucket['keys']:
                    path = os.path.join(self.mount_point,
                                        os.path.basename(each_bucket['name']),
                                        os.path.basename(each_key['name']))
                    files_full_path = os.path.abspath(path)
                    temp = {'file': files_full_path, 'md5': each_key['md5_local'],
                            'bucket': each_bucket['name']}
                    self.files.append(temp)
        log.info('basedirs:\n%s' % self.base_dirs)
        log.info('files:\n%s' % self.files)

    def verify_if_basedir_created(self):
        # verify basedir and files created
        log.info('verifying basedir')
        for basedir in self.base_dirs:
            log.info('verifying existence for: %s' % basedir)
            created = os.path.exists(basedir)
            if not created:
                raise TestExecError("basedir not exists")
            log.info('basedir created')
        log.info('basedir verification complete, basedirs exists')

    def verify_if_files_created(self):
        if not self.files:
            log.info('no files are created')
        else:
            log.info('verifying files')
            for each_file in self.files:
                log.info('verifying existence for: %s' % each_file['file'])
                created = os.path.exists(each_file['file'])
                if not created:
                    raise TestExecError("files not created")
                log.info('file created')
                md5 = utils.get_md5(each_file['file'])
                log.info('md5 on nfs mount point: %s' % md5)
                log.info('md5 on rgw_client: %s' % each_file['md5'])
                if md5 != each_file['md5']:
                    raise TestExecError("md5 not matched")
                log.info('md5 matched')
            log.info('verification of files complete, files exists and data intact')
