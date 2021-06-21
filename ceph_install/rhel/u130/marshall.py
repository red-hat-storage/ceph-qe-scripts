import os

import utils.log as log
import yaml
from src.install.install import Install
from src.prereq.prerequisite import Prerequisites
from utils.utils import (
    SSH,
    Machines,
    ceph_deploy,
    change_dir,
    change_perms,
    create_ceph_dir,
)


def make_machines(machines):

    machine_list = machines.split(" ")
    print machine_list

    machines = []
    for each_machine in machine_list:
        temp = each_machine.split("-")
        machines.append(Machines(temp[0], temp[1]))

    return machines


class Marshall(object):
    def __init__(self, doc):

        t1 = doc["machine"]["osd"]
        self.osdL = make_machines(t1)

        t2 = doc["machine"]["mon"]
        self.monL = make_machines(t2)

        t3 = doc["machine"]["admin"]
        self.admin_nodes = make_machines(t3)
        self.admin_nodes = self.admin_nodes[0]

        self.username = doc["ceph_config"][
            "cdn_live_username"
        ]  # uesername from inktank
        self.password = doc["ceph_config"]["cdn_live_username"]  # password from inktank

        self.creds = {
            "qa_username": doc["ceph_config"]["cdn_live_username"],
            "qa_password": doc["ceph_config"]["cdn_live_password"],
            "pool_id": doc["ceph_config"]["rhel_pool_id"],
        }

        self.iso_link = doc["ceph_config"]["iso"]

        self.run_prerequites = True  # True or False

        self.cdn_enabled = doc["ceph_config"]["cdn_enabled"]  # True or False
        self.iso_enabled = doc["ceph_config"]["iso_enabled"]  # True or False

        self.repo = {"mon": doc["repos"]["mon"], "osd": doc["repos"]["osd"]}

        self.admin_repo = {
            "installer": doc["repos"]["admin"]["installer"],
            "calamari": doc["repos"]["admin"]["calamari"],
            "tools": doc["repos"]["admin"]["tools"],
        }

        self.pool_id = doc["ceph_config"]["rhel_pool_id"]

        self.gpg_signing_on = doc["ceph_config"]["gpg_signing_on"]

    def set(self):

        log.info("Machines Using:")
        log.info("admin: %s, %s" % (self.admin_nodes.ip, self.admin_nodes.hostname))

        log.info("mons:")
        for each_mon in self.monL:
            log.info("mon: %s, %s" % (each_mon.ip, each_mon.hostname))

        log.info("osds: ")
        for each_osd in self.osdL:
            log.info("osds: %s, %s" % (each_osd.ip, each_osd.hostname))

        log.info("Configuration: ")
        log.info("username: %s" % self.username)
        log.info("password: %s" % self.password)
        log.info("CDN Enabled: %s" % self.cdn_enabled)
        log.info("ISO Enabled: %s" % self.iso_enabled)

        self.install_ceph = Install(
            self.username,
            self.password,
            self.admin_nodes,
            self.monL,
            self.osdL,
            self.cdn_enabled,
            self.iso_enabled,
            self.iso_link,
            self.pool_id,
            self.admin_repo,
            self.repo,
            self.gpg_signing_on,
        )

    def execute(self):
        try:
            log.debug("executing ssh commands")

            ssh = SSH(self.admin_nodes, self.monL, self.osdL)
            ssh.execute()
            create_ceph_dir()
            os.system("sudo chmod 777 ceph-config")
            change_dir()
            os.system("touch ceph.log")
            os.system("sudo chmod 777 ceph.log")

            self.set()

            if self.run_prerequites:
                log.info("running prerequistes")
                print "pre -req enabled"
                self.prereq = Prerequisites(
                    self.admin_nodes, self.monL, self.osdL, self.creds
                )
                self.prereq.execute()

            self.install_ceph.execute()

        except Exception, e:
            log.error(e)


if __name__ == "__main__":

    log.info("starting message")

    with open("config.yaml", "r") as f:
        doc = yaml.load(f)

    marshall = Marshall(doc)
    marshall.execute()
