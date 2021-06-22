import os

import utils.log as log


class PrepareISO(object):
    def __init__(self, iso_link, gpg_signing_on):
        self.iso_link = iso_link
        self.gpg_signing_on = gpg_signing_on

        self.iso_name = "rhceph.iso"

    def download_iso(self):

        log.info("downloading ceph iso")

        log.debug(self.iso_link)

        os.system("sudo wget " + self.iso_link)
        filename = self.iso_link.split("/")[-1]

        # renaming the ISO
        print "checking the dir contenst********************************************"
        os.system("pwd")
        os.system("ls -l")
        os.system(" sudo mv %s %s" % (filename, self.iso_name))
        # mouting iso

        log.info("mounting ceph iso")

        mount_cmd = "sudo mount " + self.iso_name + " /mnt"

        log.debug(mount_cmd)

        os.system(mount_cmd)

    def ice_setup(self):

        # extracting ICE setup

        log.info("Installing ICE setup")

        extract_cmd = "sudo yum install /mnt/Installer/ice_setup-*.rpm -y"

        log.debug(extract_cmd)

        os.system(extract_cmd)

        # run ice setup

        if self.gpg_signing_on:
            run_ice_setup = "sudo ice_setup -d /mnt --no-gpg"
        else:
            run_ice_setup = "sudo ice_setup -d /mnt"

        log.info("running ice setup")
        log.debug(run_ice_setup)

        os.system(run_ice_setup)

        os.system("sudo calamari-ctl initialize")


class ISOInstall(object):
    def __init__(
        self, username, password, admin_node, mons, osds, iso_link, gpg_signing_on
    ):

        self.username = username
        self.passowrd = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds
        self.iso_link = iso_link
        self.mon_hostnames = []
        self.gpg_signing_on = gpg_signing_on

        for each_mon in self.mons:
            self.mon_hostnames.append(str(each_mon.hostname))

        self.osd_hostnames = []

        for each_osd in self.osds:
            self.osd_hostnames.append(str(each_osd.hostname))

    def create_cluster(self):

        log.info('creating cluster, running "ceph-deploy new" ')

        self.create_cliuster_cmd = "ceph-deploy new %s" % (" ".join(self.mon_hostnames))

        log.debug(self.create_cliuster_cmd)
        os.system(self.create_cliuster_cmd)

    def install_ceph(self):

        # log.debug('ceph install admin node ')

        # self.install_in_admin_node = 'ceph-deploy install --no-adjust-repos --cli %s' % self.admin_node.hostname
        # log.debug(self.install_in_admin_node)
        # os.system(self.install_in_admin_node)

        log.debug("ceph install in MON nodes")
        self.install_repo_in_mon_nodes = (
            "ceph-deploy install --repo --release=ceph-mon %s"
            % (" ".join(self.mon_hostnames))
        )
        self.install_in_mon_nodes = "ceph-deploy install --mon  %s" % (
            " ".join(self.mon_hostnames)
        )
        log.debug(self.install_repo_in_mon_nodes)
        log.debug(self.install_in_mon_nodes)
        os.system(self.install_repo_in_mon_nodes)
        os.system(self.install_in_mon_nodes)

        log.debug("ceph install in OSD nodes")
        self.install_repo_in_osd_nodes = (
            "ceph-deploy install --repo --release=ceph-osd %s"
            % (" ".join(self.osd_hostnames))
        )
        self.install_in_osd_nodes = "ceph-deploy install --osd   %s" % (
            " ".join(self.osd_hostnames)
        )
        log.debug(self.install_repo_in_osd_nodes)
        log.debug(self.install_in_osd_nodes)
        os.system(self.install_repo_in_osd_nodes)
        os.system(self.install_in_osd_nodes)

    def execute(self):
        prepare_iso = PrepareISO(self.iso_link, self.gpg_signing_on)

        prepare_iso.download_iso()
        prepare_iso.ice_setup()
        self.create_cluster()
        self.install_ceph()
