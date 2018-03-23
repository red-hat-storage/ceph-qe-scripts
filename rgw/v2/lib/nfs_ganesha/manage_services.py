import v2.utils.log as log
import v2.utils.utils as utils
import os
from v1.utils.utils import FileOps
import socket
from v1.lib.process_manage import Process


class ManageNFSServices(object):

    def __init__(self):

        pass

    def ganesha_start(self):

        log.info('starting nfs-ganesha services')

        cmd = 'sudo systemctl enable nfs-ganesha '
        utils.exec_shell_cmd(cmd)

        cmd = 'sudo systemctl start nfs-ganesha '
        utils.exec_shell_cmd(cmd)

    def ganesha_stop(self):

        log.info('stopping ganesha services via systemctl')
        cmd = 'sudo systemctl stop nfs-ganesha'
        utils.exec_shell_cmd(cmd)

    def ganesha_restart(self):

        log.info('restarting ganesha services')

        log.info('restarting services using systemctl')

        cmd = 'sudo systemctl restart nfs-ganesha'
        utils.exec_shell_cmd(cmd)

    def kernel_stop(self):

        log.info('stopping nfs kernel services')

        cmd = 'systemctl stop nfs-server.service'
        utils.exec_shell_cmd(cmd)

        cmd = 'systemctl disable nfs-server.service'
        utils.exec_shell_cmd(cmd)





