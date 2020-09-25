import logging
import v1.utils.utils as utils
import os
from v1.utils.utils import FileOps

log = logging.getLogger()


def get_ganesha_config(user_id, access_key, secret_key, rgw_hostname, nfs_version):
    """
        This function is to get the ganesha configuration 

        Parameters:
            user_id(char): uid of the user
            access_key(char):
            secret_key(char):
            rgw_hostname(char): name of the rgw host running ganesha
            nfs_version(char): version of nfs 
    
        Returns:
            ganesha_conf: returns the ganesha configuration
    """
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
    """
    This class has functions 
        1. create ganesha configuration
        2. To backup existing ganesha configuration
    """

    def __init__(self, rgw_user_info):
        """
        Initializes the variables
        
        Parameter:
            rgw_user_info:
        
        Returns:

        """
        self.conf_path = '/etc/ganesha'
        self.fname = 'ganesha.conf'
        self.nfS_version = rgw_user_info['nfs_version']

        self.user_id = rgw_user_info['user_id']
        self.access_key = rgw_user_info['access_key']
        self.secret_key = rgw_user_info['secret_key']
        self.rgw_hostname = rgw_user_info['rgw_hostname']

    def backup(self, uname):

        """
            This function is to backup existing ganesha config with the user name provided 
    
            Parameters:
                uname(char): user name provided to backup the ganesha config file.
            
            Returns:

        """

        original_fname = os.path.join(self.conf_path, self.fname)
        log.info('original file name: %s' % original_fname)

        backup_fname = os.path.join(str(self.conf_path), str(self.fname) + '.%s' % uname + '.bkp')

        log.info('backup file name: %s' % backup_fname)

        cmd = 'sudo mv %s %s' % (original_fname, backup_fname)

        utils.exec_shell_cmd(cmd)

    def create(self):
        """
            This function is to create a ganesha configuration
            
        """
        conf_fname = os.path.join(self.conf_path, self.fname)

        ganesha_config = get_ganesha_config(access_key=self.access_key, secret_key=self.secret_key,
                                            user_id=self.user_id, rgw_hostname=self.rgw_hostname, nfs_version=self.nfS_version)

        create_conf = FileOps(filename=conf_fname, type='txt')

        create_conf.add_data(ganesha_config)
