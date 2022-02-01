import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))

import socket

# from v2.lib.io_info import AddIOInfo
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
import yaml
from v2.lib.exceptions import NFSGaneshaMountError
from v2.lib.nfs_ganesha.manage_conf import GaneshaConfig
from v2.lib.nfs_ganesha.manage_services import ManageNFSServices
from v2.lib.nfs_ganesha.write_io_info import AddUserInfo, BasicIOInfoStructure

log = logging.getLogger()


class RGWUserConfigOps(object):
    def __init__(self, rgw_user_info_file):
        self.fname = rgw_user_info_file
        self.rgw_user_info = None

    def read_config(self):
        yaml_file = os.path.abspath(self.fname)
        with open(yaml_file, "r") as f:
            self.rgw_user_info = yaml.safe_load(f)
        log.info("got configuration: %s" % self.rgw_user_info)
        return self.rgw_user_info

    def update_config(self):
        rgw_user_details_structure = dict(
            user_id=self.rgw_user_info["user_id"],
            access_key=self.rgw_user_info["access_key"],
            secret_key=self.rgw_user_info["secret_key"],
            rgw_hostname=self.rgw_user_info["rgw_hostname"],
            ganesha_config_exists=self.rgw_user_info["ganesha_config_exists"],
            already_mounted=self.rgw_user_info["already_mounted"],
            nfs_version=self.rgw_user_info["nfs_version"],
            nfs_mnt_point=self.rgw_user_info["nfs_mnt_point"],
            Pseudo=self.rgw_user_info["Pseudo"],
        )
        with open(self.fname, "w") as fp:
            yaml.dump(rgw_user_details_structure, fp, default_flow_style=False)


class PrepNFSGanesha(RGWUserConfigOps):
    def __init__(self, rgw_user_info_file="config/rgw_user.yaml"):
        super(PrepNFSGanesha, self).__init__(rgw_user_info_file)
        self.rgw_user_config = {}
        self.nfs_service = ManageNFSServices()

    def create_rgw_user(self):
        log.info("creating rgw user")
        rgw_user = s3lib.create_users(1)[0]
        self.rgw_user_info["user_id"] = rgw_user["user_id"]
        self.rgw_user_info["access_key"] = rgw_user["access_key"]
        self.rgw_user_info["secret_key"] = rgw_user["secret_key"]
        self.rgw_user_info["rgw_hostname"] = socket.gethostname()
        self.rgw_user_info["ganesha_config_exists"] = False
        self.rgw_user_info["already_mounted"] = False

    def create_ganesha_config(self):
        log.info("creating ganesha config")
        self.nfs_service.ganesha_stop()
        nfs_ganesha_config = GaneshaConfig(self.rgw_user_info)
        nfs_ganesha_config.backup(uname="default")
        nfs_ganesha_config.create()
        self.nfs_service.ganesha_start()
        self.rgw_user_info["ganesha_config_exists"] = True

    def do_mount(self):
        log.info("mounting on a dir: %s" % self.rgw_user_info["nfs_mnt_point"])
        self.nfs_service.ganesha_restart()
        if not os.path.exists(self.rgw_user_info["nfs_mnt_point"]):
            os.makedirs(self.rgw_user_info["nfs_mnt_point"])
        mnt_cmd = (
            "sudo mount -v -t nfs -o nfsvers=%s,sync,rw,noauto,soft,proto=tcp %s:/  %s"
            % (
                self.rgw_user_info["nfs_version"],
                self.rgw_user_info["rgw_hostname"],
                self.rgw_user_info["nfs_mnt_point"],
            )
        )
        log.info("mnt_command: %s" % mnt_cmd)
        mounted = utils.exec_shell_cmd(mnt_cmd)
        return mounted

    def do_un_mount(self):
        log.info("un_mounting dir: %s" % self.rgw_user_info["nfs_mnt_point"])
        un_mount_cmd = "sudo umount %s" % self.rgw_user_info["nfs_mnt_point"]
        un_mounted = utils.exec_shell_cmd(un_mount_cmd)
        if un_mounted:
            self.already_mounted = False
        self.update_config()
        self.read_config()
        return un_mounted

    def initialize(self, write_io_info=True):
        write_user_info = AddUserInfo()
        basic_io_structure = BasicIOInfoStructure()
        log.info("initializing NFS Ganesha")
        self.read_config()
        if self.rgw_user_info["user_id"] is None:
            log.info("rgw user does not exists")
            self.create_rgw_user()
            self.update_config()
            self.read_config()

        if write_io_info is True:
            log.info("user_id already exists, logging in for io_info")
            user_info = basic_io_structure.user(
                **{
                    "user_id": self.rgw_user_info["user_id"],
                    "access_key": self.rgw_user_info["access_key"],
                    "secret_key": self.rgw_user_info["secret_key"],
                }
            )
            write_user_info.add_user_info(user_info)
        if not self.rgw_user_info["ganesha_config_exists"]:
            log.info("ganesha config does not exists")
            self.create_ganesha_config()
            self.update_config()
            self.read_config()

        if not os.path.exists(self.rgw_user_info["nfs_mnt_point"]):
            os.makedirs(self.rgw_user_info["nfs_mnt_point"])

        if not self.rgw_user_info["already_mounted"]:
            try:
                log.info("mount needed")
                mounted = self.do_mount()
                if mounted is False:
                    raise NFSGaneshaMountError("mount failed")
                self.rgw_user_info["already_mounted"] = True
                self.update_config()
                self.read_config()
            except NFSGaneshaMountError as e:
                log.error("mount failed")
                log.error(e)
                return False

        return True
