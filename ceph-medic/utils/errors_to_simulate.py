import subprocess
import ConfigParser
import socket
from StringIO import StringIO
import paramiko
import log
import string
import random

class ErrorSimulation(object):


    def __init__(self, cluster_name):

        self.cluster_name = cluster_name


    def ecom1_err(self):

        try:

            conf_file = self.cluster_name + ".conf"

            bkp_conf_file_name = conf_file + ".bkp"

            op = subprocess.call(['mv', '/etc/ceph/%s' % (conf_file), '/etc/ceph/%s' % (bkp_conf_file_name)])

            if op == 0:
                log.info('Conf file has been renamed')

        except (subprocess.CalledProcessError, IOError) as e:

            log.error(e)

    def ecom2_err(self):
        try:
            op = subprocess.call(['mv','/usr/bin/ceph', '/usr/bin/ceph1'])
            if op == 0:

                log.info("ceph executable has been renamed")

        except (subprocess.CalledProcessError, IOError) as e:

            log.error(e)

    def ecom3_err(self):

        try:
            op = subprocess.call(['mv', '/var/lib/ceph', '/var/lib/ceph1'])
            if op == 0:
                log.info('/var/lib/ceph has been renamed')

        except (subprocess.CalledProcessError, IOError) as e:

            log.error(e)

    def ecom4_err(self):
        try:
            op=subprocess.call(['chown', 'root:root', '/var/lib/ceph'])

            if op == 0:
                log.info('Ownership is changed')

        except (subprocess.CalledProcessError, IOError) as e:

            log.error(e)

    def ecom5_err(self):

        try:
            conf_file = self.cluster_name + ".conf"

            ceph_fsid_1 = subprocess.check_output(['ceph', 'fsid']).strip('\n')

            with open('/etc/ceph/%s' % (conf_file), 'r') as file:
                filedata = file.read()

            # Replace the target string
            filedata = filedata.replace(ceph_fsid_1, 'random_val')

            # Write the file out again
            with open('/etc/ceph/%s' % (conf_file), 'w') as file:
                file.write(filedata)

            log.info('fsid has been changed')

        except Exception as e:
            log.error(e)


    def wmon1_warning(self):

        try:

            op = subprocess.call(['mkdir', '/var/lib/ceph/mon/fakemondir'])

            if op == 0:
                log.info("Fake MON dir has been created")

        except (subprocess.CalledProcessError, IOError) as e:

            log.error(e)




    def emon1_err(self):
        try:
            def id_generator(size=50, chars=string.ascii_uppercase + string.digits + '=='):
                return ''.join(random.choice(chars) for _ in range(size))

            hostname = socket.gethostname()

            parser = ConfigParser.SafeConfigParser()

            path_keyring = '/var/lib/ceph/mon/ceph-%s/keyring' % (hostname)

            keyring_file_copy = '/var/lib/ceph/mon/ceph-%s/keyring1' % (hostname)

            subprocess.call(['cp',path_keyring,keyring_file_copy])

            conf_file_modified = StringIO('\n'.join(line.strip() for line in open(path_keyring)))

            parser.readfp(conf_file_modified)

            original_key = parser.get('mon.', 'key')

            log.info("Original key %s" % (original_key))

            parser.set('mon.', 'key', id_generator())

            log.info('Modified key %s'%(id_generator()))

            with open(path_keyring, "w+") as configfile:
                parser.write(configfile)

            log.info('Keyring has been modified')




        except Exception as  e:

            log.error(e)


    def wosd1_warning(self):

        try:
            osd_names = subprocess.Popen(("ceph osd tree | grep host | awk '{print $4}'"), shell=True, stdout=subprocess.PIPE,stderr=None)

            output_osd, error = osd_names.communicate()
            get_osd = output_osd.split()

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(get_osd[0])
            stdin, stdout, stderr = ssh.exec_command("cd /var/lib/ceph/osd/* ;touch ceph_fsid1 ; ls ceph_fsid1 ")
            if stdout.channel.recv_exit_status() == 0:
                log.info("Fake fsid file is created")


        except Exception as  e:

            log.error(e)
