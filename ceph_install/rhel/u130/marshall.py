from src.prereq.prerequisite import Prerequisites
from utils.utils import Machines, create_ceph_dir, change_dir, ceph_deploy, SSH, change_perms
from src.install.install import Install
import os
import utils.log as log


class MakeMachine(object):

    def get_osds(self):

        # example

        osd1 = Machines('10.8.128.16', 'magna016')
        osd2 = Machines('10.8.128.19', 'magna019')
        osd3 = Machines('10.8.128.21', 'magna021')

        return osd1, osd2, osd3

    def get_mons(self):

        # example
        mon = []
        mon.append(Machines('10.8.128.15', 'magna015'))

        return mon

    def get_admin(self):

        # example

        admin_node = Machines('10.8.128.12', 'magna012')
        return admin_node


class Marshall(object):

    def __init__(self):
        machines = MakeMachine()
        self.osdL = machines.get_osds()
        self.monL = machines.get_mons()
        self.admin_nodes = machines.get_admin()
        self.username = 'username'  # uesername from inktank
        self.password = 'password'  # password from inktank

        self.creds = {'qa_username': 'qa@redhat.com',   # repace the dictionary values with proper credentials
                            'qa_password': 'QMdMJ8jvSWUwB6WZ',
                            'pool_id' : '8a85f9823e3d5e43013e3ddd4e2a0977'}
        self.iso_link = "https://access.cdn.redhat.com//content/origin/files/sha256/c8/c8e209111ce01955d216ab8e817f32b6a2afd35733d68170e1034411c8440cb3/rhceph-1.3.1-rhel-7-x86_64-dvd.iso?_auth_=1450274672_f430967f03a79addd94634096198d600" #Provide ISO link from cdn.access.redhat.com


        self.run_prerequites = True  # True or False

        self.cdn_enabled = True   # True or False
        self.iso_enabled = False   # True or False


        self.repo = {'mon': "rhel-7-server-rhceph-1.3-mon-rpms",
                     'osd': "rhel-7-server-rhceph-1.3-osd-rpms"

                     }

        self.admin_repo = {'installer' : "rhel-7-server-rhceph-1.3-installer-rpms",
                           'calamari' : "rhel-7-server-rhceph-1.3-calamari-rpms",
                           'tools' : "rhel-7-server-rhceph-1.3-tools-rpms"}

        self.pool_id = None


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
                                    self.cdn_enabled, self.iso_enabled, self.iso_link, self.pool_id, self.admin_repo, self.repo)

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
                    print 'pre -req enabled'
                    self.prereq = Prerequisites(self.admin_nodes, self.monL, self.osdL, self.creds)
                    self.prereq.execute()

                self.install_ceph.execute()

        except Exception, e:
            log.error(e)

if __name__ == "__main__":

    log.info('starting message')
    marshall = Marshall()
    marshall.execute()
