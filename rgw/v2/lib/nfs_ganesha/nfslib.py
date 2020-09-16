import os, sys
import logging
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.lib.nfs_ganesha.write_io_info import IOInfo
import v2.utils.utils as utils
import v2.lib.manage_data as manage_date

log = logging.getLogger()

dir_info = {'basedir': 0,
            'files': 10,
            'subdir': 20
            }

NFS_CONVENTIONS = {'basedir': 'bucket',
                   'file': 'object',
                   'subdir': 'object'}


class DoIO(object):

    def __init__(self, rgw_user_info, mnt_pont):

        self.rgw_user_info = rgw_user_info
        self.mnt_point = mnt_pont

    def write(self, io_type, fname, size=0):

        # io_type should be: basedir | subdir | file

        log.info('io_type: %s' % io_type)
        log.info('fname: %s' % fname)
        log.info('size: %s' % size)

        s3_conv = NFS_CONVENTIONS.get(io_type)
        ioinfo = IOInfo()

        path = os.path.abspath(self.mnt_point)
        full_path = os.path.join(path, fname)
        log.info('abs_path: %s' % full_path)
        try:

            if io_type == 'basedir' or io_type == 'subdir':

                log.info('creating dir, type: %s' % io_type)

                os.makedirs(full_path)

                io_info = {'name': os.path.basename(fname),
                           'type': 'dir',
                           's3_convention': s3_conv,
                           'bucket': 'self' if s3_conv == 'bucket' else fname.split('/')[0],
                           'md5': None
                           }

                log.info('io_info: %s' % io_info)

                ioinfo.add_io_info(self.rgw_user_info['access_key'], io_info)

            if io_type == 'file':

                log.info('io_type is file: %s' % io_type)

                log.info('creating file with size: %s' % size)

                finfo = manage_date.io_generator(full_path, size)

                io_info = {'name': os.path.basename(fname),
                           'type': 'file',
                           's3_convention': s3_conv,
                           'bucket': fname.split('/')[0],
                           'md5': finfo['md5']}

                log.info('io_info: %s' % io_info)

                ioinfo.add_io_info(self.rgw_user_info['access_key'], io_info)

        except (Exception) as e:
            log.error('Write IO Execution failed')
            log.error(e)
            return False

    def delete(self):

        pass

    def modify(self):

        pass


class Config(object):
    def __init__(self):
        pass
