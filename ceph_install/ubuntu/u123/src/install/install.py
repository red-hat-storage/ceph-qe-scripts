import utils.log as log
from CDN_install import CDNInstall
from ISO_install import ISOInstall
from prepare_ceph import PrepareCeph


class Install(object):
    def __init__(
        self,
        username,
        password,
        admin_node,
        mons,
        osds,
        cdn_install_enabled,
        iso_install_enabled,
    ):
        self.username = username
        self.password = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

        self.cdn_install_enabled = cdn_install_enabled
        self.iso_install_enabled = iso_install_enabled

    def execute(self):

        if self.cdn_install_enabled:

            log.info("cdn enabled")

            cdn_install = CDNInstall(
                self.username,
                self.password,
                self.admin_node,
                self.mons,
                self.osds,
                True,
            )
            cdn_install.execute()

        if self.iso_install_enabled:

            log.info("ISO enabled")

            iso_install = ISOInstall(
                self.username, self.password, self.admin_node, self.mons, self.osds
            )
            iso_install.execute()

        prepare_ceph = PrepareCeph(self.admin_node, self.mons, self.osds)
        prepare_ceph.execute()
