import os

# import ubuntu.u130.log as log
import utils.log as log


class PrepareISO(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password

        # ftp://partners.redhat.com/33a20d04c450dcece12644c03c609f1d/rhceph-1.2.3-2-ubuntu-x86_64-rh.iso

        self.iso = "ceph-1.3-ubuntu-x86_64-dvd.iso"

        self.download_link = (
            "http://download.eng.bos.redhat.com/rcm-guest/ceph-drops/test-sign/%s"
            % (self.iso)
        )

    def download_iso(self):

        log.info("downloading ceph iso")

        log.debug(self.download_link)

        os.system("sudo wget " + self.download_link)

        # mouting iso

        log.info("mounting ceph iso")

        mount_cmd = "sudo mount " + self.iso + " /mnt"

        log.debug(mount_cmd)

        os.system(mount_cmd)

    def ice_setup(self):

        # extracting ICE setup

        log.info("extracting ICE setup")

        extract_cmd = "sudo dpkg -i /mnt/ice-*.deb"

        log.debug(extract_cmd)

        os.system(extract_cmd)

        # run ice setup

        run_ice_setup = "sudo ice_setup -d /mnt"
        log.info("running ice setup")
        log.debug(run_ice_setup)

        os.system(run_ice_setup)

        os.system("sudo calamari-ctl initialize")


class ISOInstall(object):
    def __init__(self, username, password, admin_node, mons, osds):

        self.username = username
        self.passowrd = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

        self.mon_hostnames = []

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
        self.install_repo_in_mon_nodes = "ceph-deploy repo ceph-mon %s" % (
            " ".join(self.mon_hostnames)
        )
        self.install_in_mon_nodes = (
            "ceph-deploy install --no-adjust-repos --mon  %s"
            % (" ".join(self.mon_hostnames))
        )
        log.debug(self.install_repo_in_mon_nodes)
        log.debug(self.install_in_mon_nodes)
        os.system(self.install_repo_in_mon_nodes)
        os.system(self.install_in_mon_nodes)

        log.debug("ceph install in OSD nodes")
        self.install_repo_in_osd_nodes = "ceph-deploy repo ceph-osd %s" % (
            " ".join(self.osd_hostnames)
        )
        self.install_in_osd_nodes = (
            "ceph-deploy install --no-adjust-repos --osd  %s"
            % (" ".join(self.osd_hostnames))
        )
        log.debug(self.install_repo_in_osd_nodes)
        log.debug(self.install_in_osd_nodes)
        os.system(self.install_repo_in_osd_nodes)
        os.system(self.install_in_osd_nodes)

    def execute(self):
        prepare_iso = PrepareISO(self.username, self.passowrd)

        prepare_iso.download_iso()
        prepare_iso.ice_setup()
        self.create_cluster()
        self.install_ceph()
