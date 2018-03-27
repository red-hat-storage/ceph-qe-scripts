import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import v1.lib.s3.rgw as rgw
from initialize import PrepNFSGanesha
import time
import v1.utils.log as log
from v1.lib.s3.rgw import ObjectOps, Authenticate
from v1.utils.test_desc import AddTestInfo
from v1.lib.nfs_ganesha.manage_data import BaseDir, SubdirAndObjects
from v1.lib.io_info import AddIOInfo


def test(yaml_file_path):

    ganesha_test_config = {'mount_point': 'ganesha-mount',
                           'rgw_user_info': yaml_file_path}

    log.info('ganesha_test_config :%s\n' % ganesha_test_config)

    io_config = {'base_dir_count': 2,
                 'sub_dir_count': 2,
                 'Files': {'files_in_dir': 2, 'size': 10}}

    add_io_info = AddIOInfo()
    add_io_info.initialize()

    log.info('io_config: %s\n' % io_config)

    log.info('initiating nfs ganesha')

    nfs_ganesha = PrepNFSGanesha(mount_point=ganesha_test_config['mount_point'],
                                 yaml_fname=ganesha_test_config['rgw_user_info'])

    nfs_ganesha.initialize()

    log.info('authenticating rgw user')

    rgw_auth = Authenticate(user_id=nfs_ganesha.user_id,
                            access_key=nfs_ganesha.access_key,
                            secret_key=nfs_ganesha.secret_key)

    auth = rgw_auth.do_auth()

    log.info('begin IO')

    bdir = BaseDir(int(io_config['base_dir_count']), rgw_auth.json_file_upload,
                   ganesha_test_config['mount_point'],
                   auth['conn'])

    bdirs = bdir.create(uname=str(rgw_auth.user_id))

    subdir = SubdirAndObjects(bdirs, io_config, rgw_auth.json_file_upload, auth['conn'])
    subdir.create()

    op_status = subdir.operation_on_nfs(ganesha_test_config['mount_point'], op_code='move')

    verification = {'key': True,
                    'move': True}

    for ops in op_status:

        if not ops['op_code_status']:
            verification['move'] = False
            break

        else:
            log.info('verification starts')

            log.info('key verifcation starts on s3')
            kstatus = subdir.verify_s3()
            log.info('key verificaion complete: \n%s' % kstatus)

            for ks in kstatus:

                if ks['type'] == 'file':
                    if ks['exists']:
                        verification['key'] = True
                    else:
                        verification['key'] = False

    return verification

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NFS Ganesha Automation')

    test_info = AddTestInfo('Move Object on NFS and verify from s3')

    parser.add_argument('-c', dest="config",
                        help='RGW Test yaml configuration')

    args = parser.parse_args()

    yaml_file = args.config

    verified = test(yaml_file_path=yaml_file)
    log.info('verified status: %s' % verified)
    if not verified['move'] or not verified['key']:
        test_info.failed_status('test failed')
        exit(1)

    else:
        test_info.success_status('test passed')

    test_info.completed_info()




