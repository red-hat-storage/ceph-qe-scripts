import logging
import v1.utils.utils as utils
import os
from v1.utils.utils import FileOps

log = logging.getLogger()


def get_ganesha_config(user_id, access_key, secret_key, rgw_hostname, nfs_version):

    ganesha_conf = '''
                EXPORT
                {
                        Export_ID=77;
                        Path = "/";
                        Pseudo = "/";
                        Access_Type = RW;
                        SecType = "sys";
                        NFS_Protocols = %s;
                        Transport_Protocols = TCP;
                        FSAL {
                                Name = RGW;
                                User_Id = %s;
                                Access_Key_Id ="%s";
                                Secret_Access_Key = "%s";
                        }
                }
                NFSV4 {
                    Allow_Numeric_Owners = true;
                    Only_Numeric_Owners = true;
                }
                Cache_Inode {
                    Dir_Max = 10000;
                }
                RGW {
                    name = "client.rgw.%s";
                    ceph_conf = "/etc/ceph/ceph.conf";
                    init_args = "-d --debug-rgw=16";
                }
        ''' % (nfs_version,user_id,
               access_key,
               secret_key,
               rgw_hostname)

    return ganesha_conf


class GaneshaConfig(object):

    def __init__(self, rgw_user_info):

        self.conf_path = '/etc/ganesha'
        self.fname = 'ganesha.conf'
        self.nfS_version = rgw_user_info['nfs_version']

        self.user_id = rgw_user_info['user_id']
        self.access_key = rgw_user_info['access_key']
        self.secret_key = rgw_user_info['secret_key']
        self.rgw_hostname = rgw_user_info['rgw_hostname']

    def backup(self, uname):

        """
        backup existing config  
        """

        original_fname = os.path.join(self.conf_path, self.fname)
        log.info('original file name: %s' % original_fname)

        backup_fname = os.path.join(str(self.conf_path), str(self.fname) + '.%s' % uname + '.bkp')

        log.info('backup file name: %s' % backup_fname)

        cmd = 'sudo mv %s %s' % (original_fname, backup_fname)

        utils.exec_shell_cmd(cmd)

    def create(self):

        conf_fname = os.path.join(self.conf_path, self.fname)

        ganesha_config = get_ganesha_config(access_key=self.access_key, secret_key=self.secret_key,
                                            user_id=self.user_id, rgw_hostname=self.rgw_hostname, nfs_version=self.nfS_version)

        create_conf = FileOps(filename=conf_fname, type='txt')

        create_conf.add_data(ganesha_config)
