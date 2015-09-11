import os
import subprocess

def create_ceph_dir():
    os.system('cd ~')
    os.system('sudo mkdir ceph-config')

def change_dir():
    os.system('cd ~')
    os.chdir('ceph-config')

def ceph_deploy(commandslist):
    subprocess.call(commandslist, cwd='ceph-config')

class Machines(object):
    def __init__(self, ip, hostname):
        self.ip = ip
        self.hostname = hostname

    def ip(self):
        return self.ip

    def hostname(self):
        return self.hostname


class SSH(object):

    def __init__(self, admin_node, mons, osds):
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

    def ssh_execute(self, hostname):

        #self.ssh_cmd = 'ssh %s' %hostname  + ' ' + 'passwd'
        self.ssh_copy_id = 'ssh-copy-id %s ' %hostname

        #os.system(self.ssh_cmd)
        os.system(self.ssh_copy_id)

    def execute(self):

        self.ssh_execute(self.admin_node.hostname)

        for each_mon in self.mons:
            self.ssh_execute(each_mon.hostname)

        for each_osd in self.osds:
            self.ssh_execute(each_osd.hostname)



def change_perms(filename):
    os.system('sudo chmod 777 %s' %filename)