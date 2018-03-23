import v1.utils.log as log
import v1.utils.utils as utils
import os
from v1.utils.utils import FileOps
import socket
from v1.lib.process_manage import Process


class ManageNFSServices(object):

    def __init__(self):

        pass

    def ganesha_start(self):

        log.info('starting nfs-ganesha services')

        # cmd = 'sudo /usr/bin/ganesha.nfsd -f /etc/ganesha/ganesha.conf'
        # utils.exec_shell_cmd(cmd)

        cmd = 'sudo systemctl enable nfs-ganesha '
        utils.exec_shell_cmd(cmd)

        cmd = 'sudo systemctl start nfs-ganesha '
        utils.exec_shell_cmd(cmd)

    def ganesha_stop(self):

        log.info('stopping ganesha services via systemctl')

        # for now there is no way to stop ganesha services, only option is to kill the process


        # p = Process(name='ganesha')
        # p.find()
        #
        # if p.process is None:
        #     log.info('process nor running')
        # else:
        #     p.process.kill()
        #

        cmd = 'sudo systemctl stop nfs-ganesha'
        utils.exec_shell_cmd(cmd)

    def ganesha_restart(self):

        log.info('restarting ganesha services')

        # self.ganesha_stop()
        # self.ganesha_start()

        log.info('restarting services using systemctl')

        cmd = 'sudo systemctl restart nfs-ganesha'
        utils.exec_shell_cmd(cmd)

    def kernel_stop(self):

        log.info('stopping nfs kernel services')

        cmd = 'systemctl stop nfs-server.service'
        utils.exec_shell_cmd(cmd)

        cmd = 'systemctl disable nfs-server.service'
        utils.exec_shell_cmd(cmd)





