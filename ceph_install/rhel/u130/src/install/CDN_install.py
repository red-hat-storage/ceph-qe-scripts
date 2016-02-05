import utils.log as log
import os


class AdminRepos(object):
    def __init__(self, cdn_username, cdn_password, pool_id, admin_repo, host):
        self.cdn_username = cdn_username
        self.cdn_password = cdn_password
        self.pool_id = pool_id
        self.installer_repo = admin_repo['installer']
        self.calamari_repo = admin_repo['calamari']
        self.tools_repo = admin_repo['tools']
        self.host = host
        self.ssh = 'ssh %s ' % host.hostname

    def enable_admin_repo(self):
        log.info('Enabling Installer, Calamari and Tools Repo on Admin Node')
        print 'Enabling Installer, Calamari and Tools Repo on Admin Node'
        self.repo = " 'sudo subscription-manager repos --enable=%s --enable=%s --enable=%s' " % (
            self.installer_repo, self.calamari_repo, self.tools_repo)
        self.yum_update = " 'sudo yum update -y' "
        self.install_on_admin = " 'sudo yum install ceph-deploy calamari-server calamari-clients -y' "
        self.calamari_initialize = " 'sudo calamari-ctl initialize' "

        return self.repo, self.yum_update, self.install_on_admin, self.calamari_initialize

    def execute(self):
        print "Enabling Installer, Calamari and Tools Repo on Admin Node"
        print "Installing ceph deploy, calamari-server and calamari clients"

        commands = self.enable_admin_repo()
        for command in commands:
            command = self.ssh + command

            log.info("Enabling Installer, Calamari and Tools Repo on Admin Node")
            log.debug(command)
            os.system(command)


class MonRepos(object):
    def __init__(self, cdn_username, cdn_password, pool_id, host, mon_repo):
        self.cdn_username = cdn_username
        self.cdn_password = cdn_password
        self.pool_id = pool_id
        self.mon_repo = mon_repo
        self.host = host

        self.ssh = 'ssh %s ' % host.hostname

    def enable_mon_repo(self):
        log.info('Enabling Mon Repo on Mon Node')
        print 'Enabling Mon Repo on Mon Node'
        self.repo = " 'sudo subscription-manager repos --enable=%s ' " % (self.mon_repo)
        self.yum_update = " 'sudo yum update -y' "

        return self.repo, self.yum_update

    def execute(self):
        print "Enabling Mon Repo on Mon Node"

        commands = self.enable_mon_repo()
        for command in commands:
            command = self.ssh + command

            log.info("Enabling Mon Repo on Osd Node")
            log.debug(command)
            os.system(command)


class OsdRepos(object):
    def __init__(self, cdn_username, cdn_password, pool_id, host, osd_repo):
        self.cdn_username = cdn_username
        self.cdn_password = cdn_password
        self.pool_id = pool_id
        self.osd_repo = osd_repo
        self.host = host
        self.ssh = 'ssh %s ' % host.hostname

    def enable_osd_repo(self):
        log.info('Enabling OSD Repo on OSD Node')
        print 'Enabling OSD Repo on OSD Node'
        self.repo = " 'sudo subscription-manager repos --enable=%s ' " % (self.osd_repo)
        self.yum_update = " 'sudo yum update -y' "

        return self.repo, self.yum_update

    def execute(self):
        print "Enabling Osd Repo on Osd Node"

        commands = self.enable_osd_repo()
        for command in commands:
            command = self.ssh + command

            log.info("Enabling Osd Repo on Osd Node")
            log.debug(command)
            os.system(command)


class CDNInstall(object):
    def __init__(self, username, password, admin_node, mons,  osds, pool_id, admin_repos,  repos):

        self.username = username
        self.passowrd = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds
        self.mon_hostnames = []

        self.admin_repo = admin_repos
        self.pool_id = pool_id
        for each_mon in self.mons:
            self.mon_hostnames.append(str(each_mon.hostname))

        self.osd_repo = repos['osd']
        self.mon_repo = repos['mon']

        self.osd_hostnames = []
        for each_osd in self.osds:
            self.osd_hostnames.append(str(each_osd.hostname))

    def create_cluster(self):
        log.info('creating cluster, running "ceph-deploy new" ')
        self.create_cliuster_cmd = 'ceph-deploy new %s' % (' '.join(self.mon_hostnames))
        log.debug(self.create_cliuster_cmd)
        os.system(self.create_cliuster_cmd)

    def install_ceph(self):

        log.debug('ceph install in MON nodes')
        self.install_in_mon_nodes = 'ceph-deploy install --mon  %s' % (' '.join(self.mon_hostnames))
        log.debug(self.install_in_mon_nodes)
        os.system(self.install_in_mon_nodes)

        log.debug('ceph install in OSD nodes')
        self.install_in_osd_nodes = 'ceph-deploy install --osd   %s' % (' '.join(self.osd_hostnames))
        log.debug(self.install_in_osd_nodes)
        os.system(self.install_in_osd_nodes)

    def install_cli(self):

        log.info('installing cli on Admin')
        self.install_cli_cmd = 'ceph-deploy install --cli %s' % (self.admin_node.hostname)
        self.make_admin = 'ceph-deploy admin %s' % (self.admin_node.hostname)
        log.debug(self.install_cli_cmd)
        log.debug(self.make_admin)
        os.system(self.install_cli_cmd)
        os.system(self.make_admin)

    def execute(self):


        admin_mon_repo = AdminRepos(self.username, self.passowrd, self.pool_id, self.admin_repo , self.admin_node)
        admin_mon_repo.execute()

        for each_mon in self.mons:
            enable_mon_repo = MonRepos(self.username, self.passowrd, self.pool_id, each_mon,self.mon_repo)
            enable_mon_repo.execute()


        for each_osd in self.osds:
            enabl_osd_repos = OsdRepos(self.username, self.passowrd, self.pool_id, each_osd, self.osd_repo )
            enabl_osd_repos.execute()


        log.info('installing ceph from CDN')

        self.create_cluster()
        self.install_ceph()
        self.install_cli()
