import logging
import socket
import subprocess

import ConfigParser
import log
import paramiko
from StringIO import StringIO


class ErrorToRevert(object):
    def __init__(self, cluster_name):
        self.cluster_name = cluster_name

    def ecom1_err_revert(self):
        try:
            conf_file = self.cluster_name + ".conf"

            bkp_conf_file_name = conf_file + ".bkp"

            op = subprocess.call(
                [
                    "mv",
                    "/etc/ceph/%s" % (bkp_conf_file_name),
                    "/etc/ceph/%s" % (conf_file),
                ]
            )

            if op == 0:
                log.info("%s has been renamed to %s" % (bkp_conf_file_name, conf_file))

        except (subprocess.CalledProcessError, IOError), e:
            log.error(e)

    def ecom2_err_revert(self):

        try:
            op = subprocess.call(["mv", "/usr/bin/ceph1", "/usr/bin/ceph"])

            if op == 0:
                log.info("Renamed ceph executable has been reverted")

        except Exception, e:

            log.error(e)

    def ecom3_err_revert(self):

        try:
            op = subprocess.call(["mv", "/var/lib/ceph1", "/var/lib/ceph"])

            if op == 0:
                log.info("Rename of /var/lib/ceph1 directory has been reverted")

        except Exception, e:

            log.error(e)

    def ecom4_err_revert(self):

        try:
            op = subprocess.call(["chown", "ceph:ceph", "/var/lib/ceph"])
            if op == 0:
                log.info("Ownership of /var/lib/ceph is reverted to original")

        except Exception, e:

            log.error(e)

    def ecom5_err_revert(self):

        try:
            conf_file = self.cluster_name + ".conf"

            ceph_fsid_1 = subprocess.check_output(["ceph", "fsid"]).strip("\n")

            with open("/etc/ceph/%s" % (conf_file), "r"), file:
                filedata = file.read()

            filedata = filedata.replace("random_val", ceph_fsid_1)
            with open("/etc/ceph/%s" % (conf_file), "w"), file:
                file.write(filedata)

            ceph_fsid_2 = subprocess.check_output(["ceph", "fsid"]).strip("\n")

            if ceph_fsid_1 == ceph_fsid_2:
                log.info("modified fsid is replaced with original fsid")

        except Exception, e:

            log.error(e)

    def wmon1_revert(self):
        try:
            op = subprocess.call(["rmdir", "/var/lib/ceph/mon/fakemondir"])
            if op == 0:
                log.info("FakeMonDir has been removed")

        except Exception, e:

            log.error(e)

    def emon1_err_revert(self):
        try:

            hostname = socket.gethostname()

            parser = ConfigParser.SafeConfigParser()
            path_keyring = "/var/lib/ceph/mon/ceph-%s/keyring" % (hostname)

            keyring_file_copy = "/var/lib/ceph/mon/ceph-%s/keyring1" % (hostname)

            op_1 = subprocess.call(["rm", "-rf", path_keyring])

            op_2 = subprocess.call(["mv", keyring_file_copy, path_keyring])

            conf_file = StringIO("\n".join(line.strip() for line in open(path_keyring)))

            parser.readfp(conf_file)

            original_key = parser.get("mon.", "key")

            if op_1 == 0 and op_2 == 0:

                log.info("Keyring has been restored")
                log.info("Original key %s" % (original_key))

        except Exception, e:
            log.error(e)

    def wosd1_revert(self):
        try:
            osd_names = subprocess.Popen(
                ("ceph osd tree | grep host | awk '{print $4}'"),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=None,
            )

            output_osd, error = osd_names.communicate()
            get_osd = output_osd.split()

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(get_osd[0])
            stdin, stdout, stderr = ssh.exec_command(
                "cd /var/lib/ceph/osd/* ;sudo rm ceph_fsid1"
            )
            if stdout.channel.recv_exit_status() == 0:
                log.info("Fake fsid file is deleted")

        except Exception, e:

            log.error(e)
