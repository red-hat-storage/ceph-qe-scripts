import logging
import v2.utils.utils as utils
import os
from v2.utils.utils import FileOps
import socket
import time

log = logging.getLogger()

class ManageNFSServices(object):
    """
        This class is to manage NFS services. The functions are
        1. ganesha_start() : Start the ganesha service
        2. ganesha_stop() : Stop the ganesha service
        3. ganesha_restart() : Restart the ganesha service
        4. kernel_stop(): Stop NFS  kernel services
    """
    def __init__(self):
        
        pass

    def ganesha_start(self):
        """
        This function is to start the nfs-ganesha service

        """
        log.info('starting nfs-ganesha services')

        cmd = 'sudo systemctl enable nfs-ganesha '
        utils.exec_shell_cmd(cmd)

        cmd = 'sudo systemctl start nfs-ganesha '
        utils.exec_shell_cmd(cmd)

        time.sleep(10)

    def ganesha_stop(self):
        """
            This function is to stop the nfs-ganesha service
        """
        log.info('stopping ganesha services via systemctl')
        cmd = 'sudo systemctl stop nfs-ganesha'
        utils.exec_shell_cmd(cmd)
        time.sleep(10)

    def ganesha_restart(self):
        """
             This function is to restart the nfs-ganesha service
        """
        log.info('restarting ganesha services')

        log.info('restarting services using systemctl')

        cmd = 'sudo systemctl restart nfs-ganesha'
        utils.exec_shell_cmd(cmd)

        time.sleep(10)

    def kernel_stop(self):
        """
            This function is to stop the nfs kernel service
        """
        log.info('stopping nfs kernel services')

        cmd = 'systemctl stop nfs-server.service'
        utils.exec_shell_cmd(cmd)

        cmd = 'systemctl disable nfs-server.service'
        utils.exec_shell_cmd(cmd)

        time.sleep(10)







