import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
from initialize import PrepNFSGanesha
import time
from v2.lib.s3.auth import Auth
import v2.utils.log as log
from v2.lib.exceptions import TestExecError
from v2.lib.nfs_ganesha.nfslib import DoIO
import v2.utils.utils as utils
from v2.utils.test_desc import AddTestInfo
from v2.lib.nfs_ganesha.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import traceback


def test(config):
    test_info = AddTestInfo('NFS Basic Ops')

    log.info('io_config: %s\n' % config['test_io_config'])
    log.info('rgw_user_info_file\n: %s' % config['rgw_user_info_file'])

    io_config = config['test_io_config']

    log.info('initiating nfs ganesha')

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:

        test_info.started_info()

        nfs_ganesha = PrepNFSGanesha(rgw_user_info_file=config['rgw_user_info_file'])

        mounted = nfs_ganesha.initialize()

        if mounted is False:
            raise TestExecError("mount failed")

        log.info('authenticating rgw user')

        auth = Auth(nfs_ganesha.rgw_user_info)
        rgw_conn = auth.do_auth()

        # auth = rgw_conn.do_auth()

        mnt_point = nfs_ganesha.rgw_user_info['nfs_mnt_point']

        do_io = DoIO(nfs_ganesha.rgw_user_info)

        # base dir creation

        for bc in range(io_config['basedir_count']):

            basedir_name_to_create = utils.gen_bucket_name_from_userid(nfs_ganesha.rgw_user_info['user_id'], rand_no=bc)
            log.info('creating basedir with name: %s' % basedir_name_to_create)

            write = do_io.write('basedir', os.path.join(mnt_point, basedir_name_to_create))

            if write is False:
                raise TestExecError("write failed on mount point")

            if io_config['subdir_count'] != 0:

                for sd in range(io_config['basedir_count']):

                    subdir_name_to_create = utils.gen_bucket_name_from_userid(basedir_name_to_create + ".subdir",
                                                                              rand_no=sd)

                    log.info('creating subdir with name: %s' % subdir_name_to_create)

                    write = do_io.write('subdir',
                                        os.path.join(mnt_point, basedir_name_to_create, subdir_name_to_create))

                    if write is False:
                        raise TestExecError("write failed on mount point")

            if io_config['file_count'] != 0:

                for fc in range(io_config['file_count']):
                    file_name_to_create = utils.gen_bucket_name_from_userid(basedir_name_to_create + ".file",
                                                                            rand_no=fc)

                    log.info('creating file with name: %s' % file_name_to_create)

                    write = do_io.write('file', os.path.join(mnt_point, basedir_name_to_create, file_name_to_create))

                    if write is False:
                        raise TestExecError("write failed on mount point")

        test_info.success_status("test success")

    except Exception, e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        return 1

    except TestExecError, e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        return 1


if __name__ == '__main__':
    config = {}

    parser = argparse.ArgumentParser(description='NFS Ganesha Automation')

    test_info = AddTestInfo('nfs ganesha basic IO test and verification on rgw')

    parser.add_argument('-c', dest="config",
                        help='RGW Test yaml configuration')

    args = parser.parse_args()

    config['rgw_user_info_file'] = args.config

    config['test_io_config'] = {'basedir_count': 2,
                                'subdir_count': 1,
                                'file_count': 2}

    test(config)
