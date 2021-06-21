import os

import utils.log as log


class PrepareCeph(object):
    def __init__(self, admin_node, mons, osds):

        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

        self.mon_hostnames = []

        for each in self.mons:
            self.mon_hostnames.append(str(each.hostname))

        self.osd_hostnames = []

        for each in self.osds:
            self.osd_hostnames.append(str(each.hostname))

    def add_initial_mons(self):

        log.info("adding inital mons and connecting to calamari")

        self.add_initial_mons_cmd = "ceph-deploy mon create-initial"
        self.connect_mon_calamari = "ceph-deploy calamari connect --master %s %s" % (
            self.admin_node.ip,
            " ".join(self.mon_hostnames),
        )

        log.debug(self.add_initial_mons_cmd)
        os.system(self.add_initial_mons_cmd)

        log.debug(self.connect_mon_calamari)
        os.system(self.connect_mon_calamari)

    def make_calamari_admin_node(self):

        log.info("making admin calamari node")

        log.debug("installing cli")
        self.cli_install = "ceph-deploy install --cli %s" % (self.admin_node.hostname)
        log.debug(self.cli_install)

        log.debug("installing ceph-deploy admin")
        self.make_admin_node = "ceph-deploy admin %s" % (self.admin_node.hostname)
        log.debug(self.make_admin_node)
        os.system(self.cli_install)
        os.system(self.make_admin_node)

    def check_quorum_status(self):

        log.info("cheking quorum status")

        self.check_quorum = "sudo ceph quorum_status --format json-pretty"

        log.debug(self.check_quorum)
        os.system(self.check_quorum)

        log.info("set permission on admin.keyring")
        self.set_perm = "sudo chmod +r /etc/ceph/ceph.client.admin.keyring"
        log.debug(self.set_perm)
        os.system(self.set_perm)

    def adjust_crush_tunables(self):
        log.info("Adjust Crush Tunables")
        self.adjust_crush = "ceph osd crush tunables optimal"
        log.debug(self.adjust_crush)
        os.system(self.adjust_crush)

    def add_osds(self):

        log.info("adding osds")

        hostname_with_disk = []

        for each in self.osds:
            hostname_with_disk.append(
                each.hostname
                + ":/dev/sdb"
                + "  "
                + each.hostname
                + ":/dev/sdc"
                + "  "
                + each.hostname
                + ":/dev/sdd"
            )

        self.disk_zap_cmd = "ceph-deploy disk zap %s" % (" ".join(hostname_with_disk))
        log.debug("disk zap cmd: %s" % self.disk_zap_cmd)

        self.osd_prepare = "ceph-deploy osd prepare %s" % (" ".join(hostname_with_disk))
        log.debug("osd prepare %s" % self.osd_prepare)

        self.osd_activate = "ceph-deploy osd activate %s" % (
            " ".join(hostname_with_disk)
        )
        log.debug("osd activate:  %s" % self.osd_activate)

        self.connect_osd_calamari = "ceph-deploy calamari connect --master %s %s" % (
            self.admin_node.ip,
            " ".join(self.osd_hostnames),
        )

        os.system(self.disk_zap_cmd)
        os.system(self.osd_prepare)
        # os.system(self.osd_activate)

        log.debug("ceph osd calamari connect")
        log.debug(self.connect_osd_calamari)
        os.system(self.connect_osd_calamari)

    def create_pool(self):

        log.info("creating pool")

        self.create_pool_cmd = (
            "sudo ceph osd pool create mypool 512 512 replicated replicated_ruleset"
        )

        log.debug(self.create_pool_cmd)
        os.system(self.create_pool_cmd)

    def execute(self):

        log.info("preparing ceph---------------------------------")
        log.info("current working directory %s" % os.system("pwd"))

        self.add_initial_mons()
        self.make_calamari_admin_node()
        self.check_quorum_status()
        self.add_osds()
        self.create_pool()
