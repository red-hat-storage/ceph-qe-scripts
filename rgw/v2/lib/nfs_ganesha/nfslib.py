import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
from v2.lib.nfs_ganesha.write_io_info import IOInfo
import v2.utils.utils as utils
import v2.lib.manage_data as manage_date


dir_info = {'basedir': 0,
            'files': 10,
            'subdir': 20
            }

NFS_CONVENTIONS = {'basedir': 'bucket',
                   'file': 'object',
                   'subdir': 'object'}


class DoIO(object):

    def __init__(self, rgw_user_info):

        self.rgw_user_info = rgw_user_info

    def write(self, io_type, path, size=0):

        # io_type should be: basedir | subdir | file

        # path should be given from mount point

        log.info('io_type: %s' % io_type)
        log.info('path: %s' % path)
        log.info('size: %s' % size)

        s3_conv = NFS_CONVENTIONS.get(io_type)
        ioinfo = IOInfo()

        try:

            if io_type == 'basedir' or io_type == 'subdir':
                full_path = os.path.abspath(path)

                log.info('abs_path: %s' % full_path)
                log.info('creating dir, type: %s' % io_type)

                os.makedirs(full_path)

                io_info = {'name': os.path.basename(path),
                           'type': 'dir',
                           's3_convention': s3_conv,
                           'bucket': 'self' if s3_conv == 'bucket' else path.split('/')[1],
                           'md5': None
                           }

                log.info('io_info: %s' % io_info)

                ioinfo.add_io_info(self.rgw_user_info['access_key'], io_info)

            if io_type == 'file':

                log.info('io_type is file: %s' % io_type)

                log.info('creating file with size: %s' % size)

                finfo = manage_date.io_generator(path, size)

                io_info = {'name': os.path.basename(path),
                           'type': 'file',
                           's3_convention': s3_conv,
                           'bucket': path.split('/')[1],
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
