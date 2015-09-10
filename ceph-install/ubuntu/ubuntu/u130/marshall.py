from src.prereq.prerequisite import Prerequisites
from utils.utils import Machines, create_ceph_dir, change_dir, ceph_deploy, SSH, change_perms
from src.install.install import Install
import os
import utils.log as log


class MakeMachine(object):

    def get_osds(self):

        # example
        
        osd1 = Machines('x.x.x.63', 'hostname063')
        osd2 = Machines('x.x.x.64', 'hostname064')

        return osd1, osd2

    def get_mons(self):

        # example

        mon1 = Machines('x.x.x.63', 'hostname063')
        mon2 = Machines('x.x.x.64', 'hostname064')

        return mon1,mon2

    def get_admin(self):

        # example

        admin_node = Machines('x.x.x.14', 'hostname014')
        return admin_node


class Marshall(object):

    def __init__(self):
        machines = MakeMachine()
        self.osdL = machines.get_osds()
        self.monL = machines.get_mons()
        self.admin_nodes = machines.get_admin()
        self.username = 'username'  # uesername from inktank
        self.password = 'password'  # password from inktank

        self.run_prerequites = True  # True or False

        self.cdn_enabled = True   # True or False
        self.iso_enabled = False   # True or False

    def set(self):

        log.info('Machines Using:')
        log.info('admin: %s, %s' % (self.admin_nodes.ip, self.admin_nodes.hostname ))

        log.info('mons:')
        for each_mon in self.monL:
            log.info('mon: %s, %s'  %(each_mon.ip, each_mon.hostname))

        log.info('osds: ')
        for each_osd in self.osdL:
            log.info('osds: %s, %s' % (each_osd.ip, each_osd.hostname))

        log.info('Configuration: ')
        log.info('username: %s' % self.username)
        log.info('password: %s' % self.password)
        log.info('CDN Enabled: %s' % self.cdn_enabled)
        log.info('ISO Enabled: %s' % self.iso_enabled )

        self.install_ceph = Install(self.username,self.password,
                                    self.admin_nodes, self.monL, self.osdL,
                                    self.cdn_enabled, self.iso_enabled)

    def execute(self):

        try:
                log.debug('executing ssh commands')

                ssh = SSH(self.admin_nodes, self.monL, self.osdL)
                ssh.execute()
                create_ceph_dir()
                os.system('sudo chmod 777 ceph-config')
                change_dir()
                os.system('touch ceph.log')
                os.system('sudo chmod 777 ceph.log')

                self.set()

                if self.run_prerequites:
                    log.info('running prerequistes')
                    self.prereq = Prerequisites(self.admin_nodes, self.monL, self.osdL)
                    self.prereq.execute()

                self.install_ceph.execute()

        except Exception, e:
            log.error(e)

if __name__ == "__main__":

    log.info('starting message')
    #marshall = Marshall()
    #marshall.execute()
