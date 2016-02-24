# input:  OSP Server hostname
import subprocess
import argparse
import socket
import logging
import sys
# step 2


logging.basicConfig(format='%(asctime)s : %(levelname)s: %(message)s',
                    datefmt='[%m/%d/%Y - %I:%M:%S %p]',
                    filename='conf_admin.log',level=logging.DEBUG)

class Bcolors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def onscreen(text):
    print "\033[1;36m*%s*\033[1;m" % text


class ConfigureOSPClients(object):
    def __init__(self, ceph_install ,osp_hostname, volumes_pool, images_pool, backups_pool, vms_pools):
        self.osp_hostname = osp_hostname
        self.volumes_p = volumes_pool
        self.images_p = images_pool
        self.backups_p = backups_pool
        self.vms_p = vms_pools
        self.ceph_install = ceph_install.lower()

        self.all_pools = []

        self.all_pools.append(self.volumes_p)
        self.all_pools.append(self.images_p)
        self.all_pools.append(self.backups_p)
        self.all_pools.append(self.vms_p)

        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        # self.exec_cmd = lambda cmd: cmd

    def install_ceph_clients(self):

        try:


            # create pools
            for each_pool in self.all_pools:
                create_pool_cmd = 'sudo ceph osd pool create %s 128' % each_pool
                print create_pool_cmd
                logging.info(create_pool_cmd)
                self.exec_cmd(create_pool_cmd)

            # enable ceph cline in osp node
            enable_tools = "ssh %s " % self.osp_hostname + " 'sudo subscription-manager repos --enable=rhel-7-server-rhceph-1.3-tools-rpms' "
            logging.info(enable_tools)
            self.exec_cmd(enable_tools)

            if self.ceph_install == "y":

                logging.info('ceph installation required')

                logging.info('removing old python rbd')
                remove_python_rbd = "ssh %s 'sudo yum remove python-rbd -y' " % self.osp_hostname
                logging.info(remove_python_rbd)
                self.exec_cmd(remove_python_rbd)

                install_python_rbd = "ssh %s 'sudo yum install python-rbd -y' " % self.osp_hostname
                logging.info(install_python_rbd)
                self.exec_cmd(install_python_rbd)

                install_ceph = "ssh %s 'sudo yum install ceph-common -y' " % self.osp_hostname
                logging.info(install_ceph)
                self.exec_cmd(install_ceph)

                mkdir_ceph = "ssh %s " % self.osp_hostname + "'sudo mkdir -p /etc/ceph '"
                logging.info(mkdir_ceph)
                self.exec_cmd(mkdir_ceph)

                scp_conf_file_cmd = 'scp /etc/ceph/ceph.conf %s:' % self.osp_hostname
                logging.info(scp_conf_file_cmd)
                self.exec_cmd(scp_conf_file_cmd)

                copy_conf_file_cmd = "ssh %s " % self.osp_hostname + 'sudo cp ceph.conf /etc/ceph/'
                #copy_conf_file_cmd = 'ssh %s ' % self.osp_hostname + " 'sudo tee /etc/ceph/ceph.conf </etc/ceph/ceph.conf' "
                logging.info(copy_conf_file_cmd)
                self.exec_cmd(copy_conf_file_cmd)

            elif self.ceph_install == 'n':
                logging.info('skipping ceph installation')
                pass

            return True, 0

        except subprocess.CalledProcessError as e:
            error = Bcolors.FAIL + Bcolors.BOLD + e.output + str(e.returncode) + Bcolors.ENDC
            print error
            logging.error(error)
            return False, e.returncode

    def client_authx(self):

        try:

            ceph_auth_pool1 = "ceph auth get-or-create client.cinder mon 'allow r' " \
                              "osd 'allow class-read object_prefix rbd_children, allow rwx pool=%s, " \
                              "allow rwx pool=%s, allow rwx pool=%s' " %(self.volumes_p, self.vms_p, self.images_p)

            logging.info(ceph_auth_pool1)
            self.exec_cmd(ceph_auth_pool1)

            ceph_auth_pool2 = "ceph auth get-or-create client.glance mon " \
                              "'allow r' osd 'allow class-read object_prefix rbd_children, allow rwx pool=%s, allow rwx pool=%s'" % (self.images_p, self.vms_p)

            logging.info(ceph_auth_pool2)
            self.exec_cmd(ceph_auth_pool2)

            ceph_auth_pool3 = "ceph auth get-or-create client.cinder-backup mon " \
                              "'allow r' osd 'allow class-read object_prefix rbd_children, allow rwx pool=%s' " % str(self.backups_p)

            logging.info(ceph_auth_pool3)
            self.exec_cmd(ceph_auth_pool3)

            # adding the client keyring
            create_glance_keyring = "ceph auth get-or-create client.glance | " \
                                    "ssh %s 'sudo tee /etc/ceph/ceph.client.glance.keyring ' " %(self.osp_hostname)
            logging.info(create_glance_keyring)
            self.exec_cmd(create_glance_keyring)

            change_glance_keyring_perms = "ssh %s 'sudo chown glance:glance /etc/ceph/ceph.client.glance.keyring' " % self.osp_hostname
            logging.info(change_glance_keyring_perms)
            self.exec_cmd(change_glance_keyring_perms)

            create_cinder_keyring = "ceph auth get-or-create client.cinder |" \
                                    " ssh %s ' sudo tee /etc/ceph/ceph.client.cinder.keyring ' " % self.osp_hostname
            logging.info(create_cinder_keyring)
            self.exec_cmd(create_cinder_keyring)

            change_cinder_keyring = "ssh %s ' sudo chown cinder:cinder /etc/ceph/ceph.client.cinder.keyring ' " % self.osp_hostname
            logging.info(change_cinder_keyring)
            self.exec_cmd(change_cinder_keyring)

            create_cinder_backup = "ceph auth get-or-create client.cinder-backup | " \
                                   "ssh %s ' sudo tee /etc/ceph/ceph.client.cinder-backup.keyring' " % self.osp_hostname
            logging.info(create_cinder_backup)
            self.exec_cmd(create_cinder_backup)

            change_cinder_backup = "ssh %s ' sudo chown cinder:cinder /etc/ceph/ceph.client.cinder-backup.keyring ' " % self.osp_hostname
            logging.info(change_cinder_backup)
            self.exec_cmd(change_cinder_backup)

            create_nova_compute_keyring = "ceph auth get-or-create client.cinder | " \
                                          "ssh %s ' sudo tee /etc/ceph/ceph.client.cinder.keyring ' " % self.osp_hostname
            logging.info(create_nova_compute_keyring)
            self.exec_cmd(create_nova_compute_keyring)

            copy_nova_keyring = "ceph auth get-key client.cinder | ssh %s 'tee /tmp/client.cinder.key ' " % self.osp_hostname
            logging.info(copy_nova_keyring)
            self.exec_cmd(copy_nova_keyring)

            return True, 0

        except subprocess.CalledProcessError as e:
            error = Bcolors.FAIL + Bcolors.BOLD + e.output + str(e.returncode) + Bcolors.ENDC
            print error
            logging.error(error)
            return False, e.returncode


if __name__ == '__main__':

    onscreen('Admin Configuration Started')
    logging.info('Admin Configuration completed')

    parser = argparse.ArgumentParser(description='Configure OSP Admin')

    parser.add_argument('-ospn', "--osp_node", dest = "ospn", default=socket.gethostname(), help= 'Give the OSP hostname, shortname[hostname -s]')
    parser.add_argument('-vp', '--volumes_pool', dest='vp', help= 'Enter pool name for volumes')
    parser.add_argument('-ip', '--images_pool', dest='ip', help='Enter pool name for images')
    parser.add_argument('-bp', '--backup_pool', dest='bp', help= 'Enter pool name for backup')
    parser.add_argument('-vmp', '--vms_pool', dest='vmp', help='Enter pool name for vms')
    parser.add_argument('-ci', '--ceph_install', dest='ci', default= 'n',  help='Enter n or y, "n" - for skip and "y" - install')



    args = parser.parse_args()

    logging.info('recieved args: \n'
                  'ceph installation : %s\n'
                 'osp_hostanme : %s\n'
                 'volumes_pool : %s \n'
                 'images pool : %s \n'
                 'backup_pool : %s \n'
                 'vms_pool : %s' % (args.ci, args.ospn, args.vp, args.ip, args.bp, args.vmp))

    try:
        configure = ConfigureOSPClients(args.ci, args.ospn, args.vp, args.ip, args.bp, args.vmp)
        installed,ret_code = configure.install_ceph_clients()

        assert installed, ret_code

        configured, err_code = configure.client_authx()

        assert configure, err_code
        logging.info('Admin Configuration completed')
        onscreen('Admin Configuration completed')

    except AssertionError, e:
        logging.error(e)
        logging.error('Admin Confiuguration failed')
        onscreen('Admin Configuration failed')
        sys.exit(1)




