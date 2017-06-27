import utils.log as log
import utils.utils as utils
import os
import socket
from lib.nfs_ganesha.manage_conf import GaneshaConfig
from lib.nfs_ganesha.manage_services import ManageNFSServices
import lib.s3.rgw as rgw
import yaml


class RGWUserConfigOps(object):

    def __init__(self, yaml_fname):

        self.fname = yaml_fname

        self.user_id = None
        self.access_key = None
        self.secret_key = None

        self.rgw_hostname = None

        self.ganesha_config_exists = False
        self.already_mounted = False

    def read_config(self):

        yaml_file = os.path.abspath(self.fname)

        with open(yaml_file, 'r') as f:
            rgw_user_details = yaml.load(f)

        log.info('got configuration: %s' % rgw_user_details)

        self.user_id = rgw_user_details['user_id']
        self.access_key = rgw_user_details['access_key']
        self.secret_key = rgw_user_details['secret_key']

        self.rgw_hostname = rgw_user_details['rgw_hostname']

        self.ganesha_config_exists = rgw_user_details['ganesha_config_exists']
        self.already_mounted = rgw_user_details['already_mounted']

        return rgw_user_details

    def update_config(self):

        rgw_user_details_structure = dict(user_id=self.user_id,
                                          access_key=self.access_key,
                                          secret_key=self.secret_key,
                                          rgw_hostname=self.rgw_hostname,
                                          ganesha_config_exists=self.ganesha_config_exists,
                                          already_mounted=self.already_mounted
                                          )

        with open(self.fname, 'w') as fp:
            yaml.dump(rgw_user_details_structure, fp, default_flow_style=False)


class PrepNFSGanesha(RGWUserConfigOps):

    def __init__(self, mount_point, yaml_fname='yaml/rgw_user.yaml'):

        super(PrepNFSGanesha, self).__init__(yaml_fname)

        self.mount_point = mount_point

        self.rgw_user_config = {}

        self.nfs_service = ManageNFSServices()

    def create_rgw_user(self):

        log.info('creating rgw user')

        rgw_user = rgw.create_users(1)[0]

        self.user_id = rgw_user['user_id']
        self.access_key = rgw_user['access_key']
        self.secret_key = rgw_user['secret_key']

        self.rgw_hostname = socket.gethostname()
        self.ganesha_config_exists = False
        self.already_mounted = False

    def create_ganesha_config(self):

        log.info('creating ganesha config')

        self.nfs_service.ganesha_stop()

        nfs_ganesha_config = GaneshaConfig(self.user_id, self.access_key, self.secret_key, self.rgw_hostname)
        nfs_ganesha_config.backup(uname='default')
        nfs_ganesha_config.create()

        self.nfs_service.ganesha_start()

        self.ganesha_config_exists = True

    def do_mount(self):

        log.info('mounting on a dir: %s' % self.mount_point)

        self.nfs_service.ganesha_restart()

        if not os.path.exists(self.mount_point):
            os.makedirs(self.mount_point)

        mnt_cmd = 'sudo mount -v -t nfs -o nfsvers=4,sync,rw,noauto,soft,proto=tcp %s:/  %s' % \
                  (self.rgw_hostname, self.mount_point)

        log.info('mnt_dird_info: %s' % mnt_cmd)

        mounted = utils.exec_shell_cmd(mnt_cmd)
        return mounted

    def do_un_mount(self):

        log.info('un_mounting dir: %s' % self.mount_point)

        un_mount_cmd = 'sudo umount %s' % self.mount_point

        un_mounted = utils.exec_shell_cmd(un_mount_cmd)

        if un_mounted[0]:
            self.already_mounted = False

        self.update_config()

        self.read_config()

        return un_mounted

    def initialize(self):

        log.info('initializing NFS Ganesha')

        self.read_config()

        if self.user_id is None:

            log.info('rgw user does not exists')

            self.create_rgw_user()

            self.update_config()

            self.read_config()

        if not self.ganesha_config_exists:

            log.info('ganesha config does not exists')

            self.create_ganesha_config()

            self.update_config()

            self.read_config()

        if not self.already_mounted:

            log.info('mount needed')

            self.do_mount()

            self.already_mounted = True

            self.update_config()

            self.read_config()

