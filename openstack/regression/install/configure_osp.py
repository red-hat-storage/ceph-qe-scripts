import argparse
import logging
import subprocess
import sys
from subprocess import PIPE, Popen

import ConfigParser

# use sudo to run this file

logging.basicConfig(
    format="%(asctime)s : %(levelname)s: %(message)s",
    datefmt="[%m/%d/%Y - %I:%M:%S %p]",
    filename="co.log",
    level=logging.DEBUG,
)


def onscreen(text):
    print "\033[1;36m*%s*\033[1;m" % text


class Bcolors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def log_msgs(msgs):
    logging.info(msgs)
    print msgs


def log_errors(msgs):
    logging.error(msgs)
    print msgs


def uuid_gen():
    cmd = "uuidgen"
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    return out.rstrip()


class ConfigureGlance(object):
    def __init__(self, images_pool):
        self.images_pool = images_pool

    def do_config(self):

        log_msgs("configuring glance")
        # Read the glance-api.conf file
        cfg = ConfigParser.ConfigParser()
        cfg.read("/etc/glance/glance-api.conf")

        # Add the following lines to section "glance_store". This configures glance to use ceph as backend driver
        cfg.set("glance_store", "stores", "glance.store.rbd.Store,")
        cfg.set("glance_store", "rbd_store_user", "glance")
        cfg.set("glance_store", "default_store", "rbd")
        cfg.set("glance_store", "rbd_store_pool", "%s" % self.images_pool)
        cfg.set("glance_store", "rbd_store_chunk_size", "8")
        cfg.set("glance_store", "rbd_store_ceph_conf", "/etc/ceph/ceph.conf")

        # Add the following lines to enable glance to use ceph copy-on-write cloning of images
        cfg.set("", "show_image_direct_url", "True")
        cfg.set("", "enable_v2_api", "True")

        # Write to the  config file and close
        with open("/etc/glance/glance-api.conf", "w") as configfile:
            cfg.write(configfile)
        configfile.close()


class ConfigureNova(object):
    def __init__(self, vms_pool, uuid):
        self.vms_pool = vms_pool
        self.uuid = uuid

    def do_config(self):
        # Read the nova config file

        log_msgs("configuring nova")
        cfg = ConfigParser.ConfigParser()
        cfg.read("/etc/nova/nova.conf")

        # Add the following lines to section "libvirt". This configures nova to use ceph as backend driver
        cfg.set("libvirt", "images_type", "rbd")
        cfg.set("libvirt", "images_rbd_pool", "%s" % self.vms_pool)
        cfg.set("libvirt", "images_rbd_ceph_conf", "/etc/ceph/ceph.conf")
        cfg.set("libvirt", "rbd_user", "cinder")
        cfg.set("libvirt", "rbd_secret_uuid", "%s" % self.uuid)  # stdin uuid
        cfg.set("libvirt", "disk_cachemodes", '"network=writeback"')
        cfg.set("libvirt", "inject_password", "false")
        cfg.set("libvirt", "inject_key", "false")
        cfg.set("libvirt", "inject_partition", "-2")
        cfg.set(
            "libvirt",
            "live_migration_flag",
            "VIR_MIGRATE_UNDEFINE_SOURCE,VIR_MIGRATE_PEER2PEER,VIR_MIGRATE_LIVE,VIR_MIGRATE_PERSIST_DEST",
        )

        # Write to the config file and close.
        with open("/etc/nova/nova.conf", "w") as configfile:
            cfg.write(configfile)
        configfile.close()


class ConfigureCinder(object):
    def __init__(self, volume_pool, backiup_pool, uuid):
        self.volumes_pool = volume_pool
        self.backup_pool = backiup_pool

        self.uuid = uuid

    def do_config(self):
        log_msgs("configuring cinder")
        # Read the cinder config file
        config = ConfigParser.ConfigParser()
        config.read("/etc/cinder/cinder.conf")

        # Add the following lines to configure cinder to use ceph as backend driver
        config.set("DEFAULT", "enabled_backends", "rbd")
        config.set("DEFAULT", "glance_api_version", "2")

        config.add_section("rbd")
        config.set("rbd", "volume_driver", "cinder.volume.drivers.rbd.RBDDriver")
        config.set("rbd", "rbd_pool", "%s" % self.volumes_pool)  # stdin pool
        config.set("rbd", "rbd_ceph_conf", " /etc/ceph/ceph.conf")
        config.set("rbd", "rbd_flatten_volume_from_snapshot", "false")
        config.set("rbd", "rbd_max_clone_depth", "5")
        config.set("rbd", "rbd_store_chunk_size", "4")
        config.set("rbd", "rados_connect_timeout", "-1")
        config.set("rbd", "rbd_user", "cinder")
        config.set("rbd", "rbd_secret_uuid", "%s" % self.uuid)  # stdin uuid

        config.set("DEFAULT", "backup_driver", "cinder.backup.drivers.ceph")
        config.set("DEFAULT", "backup_ceph_conf", "/etc/ceph/ceph.conf")
        config.set("DEFAULT", "backup_ceph_user", "cinder-backup")
        config.set("DEFAULT", "backup_ceph_chunk_size", "134217728")
        config.set("DEFAULT", "backup_ceph_pool", "%s" % self.backup_pool)
        config.set("DEFAULT", "backup_ceph_stripe_unit", "0")
        config.set("DEFAULT", "backup_ceph_stripe_count", "0")
        config.set("DEFAULT", "restore_discard_excess_bytes", "true")

        # Write to the config file and close
        with open("/etc/cinder/cinder.conf", "w") as configfile:
            config.write(configfile)
        configfile.close()


def restart_services():
    try:

        log_msgs("starting services")
        exec_cmd = lambda cmd: subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT
        )

        exec_cmd("sudo service openstack-glance-api restart")
        exec_cmd("sudo service openstack-nova-compute restart")
        exec_cmd("sudo service openstack-cinder-volume restart")
        exec_cmd("sudo service openstack-cinder-backup restart")

        log_msgs("services started")
        return True, 0

    except subprocess.CalledProcessError as e:
        log_msgs("starting services failed")
        error = (
            Bcolors.FAIL + Bcolors.BOLD + e.output + str(e.returncode) + Bcolors.ENDC
        )
        print error
        log_errors(error)
        return False, e.returncode


class ConfigureOSP(object):
    def __init__(self, volumes_pool, images_pool, backup_pool, vm_pool, uuid):
        self.cinder_config = ConfigureCinder(volumes_pool, backup_pool, uuid)
        self.nova_config = ConfigureNova(vm_pool, uuid)
        self.glance_config = ConfigureGlance(images_pool)
        self.uuid = uuid

        self.exec_cmd = lambda cmd: subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT
        )

    def secret_xml_define(self):

        try:
            secret_xml = (
                "cat >   secret.xml <<EOF\n<secret ephemeral='no' private='no'>\n<uuid>%s</uuid>"
                "\n<usage type='ceph'>\n<name>client.cinder secret</name>\n</usage>\n</secret>\nEOF"
                % self.uuid
            )

            logging.debug(secret_xml)
            self.exec_cmd(secret_xml)

            cmd = "sudo virsh secret-define --file secret.xml"
            logging.debug(cmd)
            self.exec_cmd(cmd)

            cmd1 = (
                "sudo virsh secret-set-value --secret %s "
                "--base64 $(cat /tmp/client.cinder.key) && rm /tmp/client.cinder.key && rm secret.xml"
                % self.uuid
            )

            logging.debug(cmd1)
            self.exec_cmd(cmd1)

            return True, 0

        except subprocess.CalledProcessError as e:
            error = (
                Bcolors.FAIL
                + Bcolors.BOLD
                + e.output
                + str(e.returncode)
                + Bcolors.ENDC
            )
            print error
            log_errors(error)
            return False, e.returncode

    def do_config(self):

        try:
            self.cinder_config.do_config()
            self.nova_config.do_config()
            self.glance_config.do_config()

            return True, 0

        except Exception, e:
            log_errors("error in configuring")
            log_errors(e)
            return False, 1


if __name__ == "__main__":

    onscreen("Configuration started")

    parser = argparse.ArgumentParser(description="Configure OSP")

    parser.add_argument(
        "-vp", "--volumes_pool", dest="vp", help="Enter pool name for volumes"
    )
    parser.add_argument(
        "-ip", "--images_pool", dest="ip", help="Enter pool name for images"
    )
    parser.add_argument(
        "-bp", "--backup_pool", dest="bp", help="Enter pool name for backup"
    )
    parser.add_argument(
        "-vmp", "--vms_pool", dest="vmp", help="Enter pool name for vms"
    )

    args = parser.parse_args()

    try:

        uuid = uuid_gen()

        log_msgs("uuid generated: %s" % uuid)

        osp_configure = ConfigureOSP(args.vp, args.ip, args.bp, args.vmp, uuid)

        xml_status, ret_code = osp_configure.secret_xml_define()

        assert xml_status, str(ret_code) + "\nsecret xml config failed "

        status = osp_configure.do_config()

        assert status[0], "Configuration Failed"

        restart_serv, ret_code = restart_services()

        assert restart_serv, str(ret_code) + "\nrestarting Services failed "

        onscreen("Configuration Completed")

    except AssertionError, e:
        log_errors(e)
        sys.exit(1)
