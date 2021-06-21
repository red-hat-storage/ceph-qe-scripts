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
        iso_link,
        pool_id,
        admin_repo,
        repos,
        gpg_signing_on,
    ):
        self.username = username
        self.password = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds
        self.iso_link = iso_link

        self.pool_id = pool_id

        self.admin_repo = admin_repo
        self.repos = repos

        self.cdn_install_enabled = cdn_install_enabled
        self.iso_install_enabled = iso_install_enabled

        self.gpg_signing_on = gpg_signing_on

    def execute(self):

        if self.cdn_install_enabled:

            log.info("cdn enabled")

            # cdn_install = CDNInstall(self.username, self.password, self.admin_node, self.mons, self.osds, True)
            # cdn_install.execute()

            cdn_install = CDNInstall(
                self.username,
                self.password,
                self.admin_node,
                self.mons,
                self.osds,
                self.pool_id,
                self.admin_repo,
                self.repos,
            )
            cdn_install.execute()

        if self.iso_install_enabled:

            log.info("ISO enabled")

            iso_install = ISOInstall(
                self.username,
                self.password,
                self.admin_node,
                self.mons,
                self.osds,
                self.iso_link,
                self.gpg_signing_on,
            )
            iso_install.execute()

            # else code for ISO install pending

        prepare_ceph = PrepareCeph(self.admin_node, self.mons, self.osds)
        prepare_ceph.execute()
