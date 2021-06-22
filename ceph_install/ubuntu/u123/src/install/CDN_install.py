import os

import utils.log as log


class CalamariToolsRepo(object):
    def __init__(self, repo_username, repo_password, admin_node):
        self.admin_node = admin_node
        self.username = repo_username
        self.password = repo_password

        self.repo = None
        self.get_release_key = None
        self.apt_update = "sudo apt-get update -y"
        self.install_cephdeploy = None
        self.calamari_repo = None
        self.tools_repo = None

    def set_repo(self):

        log.info("Calamari: setting repo ")

        print "setting repo"
        self.repo = (
            "sudo bash -c 'umask 0077; echo deb https://%s:%s@download.inktank.com/enterprise-testing/Ceph-1.3-Ubuntu-14.04-20150813.t.0/repos/debian/Installer "
            "$(lsb_release -sc) main | tee /etc/apt/sources.list.d/rhcs-installer-1.3.list' "
            % (self.username, self.password)
        )

        self.get_release_key = "sudo bash -c 'wget -O - https://download.inktank.com/keys/release.asc | apt-key add -' "

        log.debug(self.repo)
        os.system(self.repo)

        log.debug(self.get_release_key)
        os.system(self.get_release_key)

    def install_ceph_deploy(self):

        log.info("installing ceph-deploy")
        self.install_cephdeploy = "sudo apt-get install ceph-deploy -y"
        os.system(self.install_cephdeploy)

    def enable_calamari_tools(self):

        print "enbaling calamari and tools repo"

        calamari_repo_link = (
            "'https://%s:%s@download.inktank.com/enterprise-testing/Ceph-1.3-Ubuntu-14.04-20150813.t.0/repos/debian/Calamari'"
            % (self.username, self.password)
        )

        self.calamari_repo = (
            "sudo ceph-deploy repo --repo-url  "
            + calamari_repo_link
            + " Calamari  `hostname -f`"
        )

        tools_repo_link = (
            "'https://%s:%s@download.inktank.com/enterprise-testing/Ceph-1.3-Ubuntu-14.04-20150813.t.0/repos/debian/Tools'"
            % (self.username, self.password)
        )

        self.tools_repo = (
            "sudo ceph-deploy repo --repo-url  "
            + tools_repo_link
            + " Tools `hostname -f`"
        )

        log.info("calamari Repo")
        log.debug(self.calamari_repo)

        os.system(self.calamari_repo)

        log.debug("tools repo")
        log.debug(self.tools_repo)
        os.system(self.tools_repo)
        os.system(self.apt_update)

    def install(self):

        log.info("installing the repos")
        self.set_repo()
        os.system(self.apt_update)

        self.install_ceph_deploy()
        self.enable_calamari_tools()


class MonRepos(object):
    def __init__(self, repo_username, repo_password, mons):
        self.apt_update = "sudo apt-get update -y"
        self.mons = mons
        self.username = repo_username
        self.password = repo_password

    def set_repo(self):

        log.info("setting mon repo")

        repo_url = (
            "https://%s:%s@download.inktank.com/enterprise-testing/Ceph-1.3-Ubuntu-14.04-20150813.t.0/repos/debian/MON"
            % (self.username, self.password)
        )
        gpg_url = "https://download.inktank.com/keys/release.asc"

        mon_hostname = []

        for each in self.mons:
            mon_hostname.append(str(each.hostname))

        self.repo = (
            "ceph-deploy repo --repo-url "
            + repo_url
            + " --gpg-url "
            + gpg_url
            + " Monitor "
            + " ".join(mon_hostname)
        )

        log.info("mon repo command")
        log.debug(self.repo)

        os.system(self.repo)

    def install(self):

        print "installing mon repo"

        self.set_repo()
        os.system(self.apt_update)


class OSDRepo(object):
    def __init__(self, repo_username, repo_password, osds):
        self.username = repo_username
        self.password = repo_password
        self.osds = osds
        self.repo = None
        self.apt_update = "sudo apt-get update -y"

    def set_repo(self):

        log.info("setting repo for osds")

        repo_url = (
            "https://%s:%s@download.inktank.com/enterprise-testing/Ceph-1.3-Ubuntu-14.04-20150813.t.0/repos/debian/OSD"
            % (self.username, self.password)
        )
        gpg_url = "https://download.inktank.com/keys/release.asc"

        osd_hostname = []

        for each in self.osds:
            osd_hostname.append(str(each.hostname))

        self.repo = (
            "ceph-deploy repo --repo-url "
            + repo_url
            + " --gpg-url "
            + gpg_url
            + " OSD "
            + " ".join(osd_hostname)
        )

        log.debug(self.repo)
        os.system(self.repo)

    def install(self):
        self.set_repo()
        os.system(self.apt_update)


class InstallRepo(object):
    def __init__(self, username, password, admin_node, mons, osds):
        self.username = username
        self.password = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

    def set_repos(self):
        self.calamari_repo = CalamariToolsRepo(
            self.username, self.password, self.admin_node
        )
        self.mon_repo = MonRepos(self.username, self.password, self.mons)
        self.osd_repos = OSDRepo(self.username, self.password, self.osds)

    def execute(self):

        log.info("setting repos for calamari, mon, osds")

        self.set_repos()
        self.calamari_repo.install()
        self.mon_repo.install()
        self.osd_repos.install()
        os.system("sudo apt-get install calamari-server calamari-clients")
        os.system("sudo calamari-ctl initialize")


class InstallCeph(object):
    def __init__(self, admin_node, mons, osds):
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

        self.install_cli_cmd = None
        self.install_osd_cmd = None
        self.install_mon_cmd = None

    def install_mon(self):

        log.info("installing  ceph on mons")

        mon_hostname = []
        for each in self.mons:
            mon_hostname.append((each.hostname))

        self.install_mon_cmd = "ceph-deploy install --no-adjust-repos --mon %s" % (
            " ".join(mon_hostname)
        )

        log.debug(self.install_mon_cmd)
        os.system(self.install_mon_cmd)

    def install_osd(self):

        log.info("installing ceph on ods")

        osd_hostname = []
        for each in self.osds:
            osd_hostname.append((each.hostname))

        self.install_osd_cmd = "ceph-deploy install --no-adjust-repos --osd %s" % (
            " ".join(osd_hostname)
        )
        log.debug(self.install_osd_cmd)
        os.system(self.install_osd_cmd)

    def install_cli(self):

        log.info("installing cli on calamari")
        self.install_cli_cmd = "ceph-deploy install --no-adjust-repos --cli %s" % (
            self.admin_node.hostname
        )

        log.debug(self.install_cli_cmd)
        os.system(self.install_cli_cmd)

    def execute(self):

        log.info("installing ceph from CDN")

        self.install_mon()
        self.install_osd()
        self.install_cli()


class CDNInstall(object):
    def __init__(self, username, password, admin_node, mons, osds, set_repo):

        self.username = username
        self.password = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds

        self.set_repo = set_repo  # set to True or False

        self.install_repo = InstallRepo(
            self.username, self.password, self.admin_node, self.mons, self.osds
        )
        self.install_ceph = InstallCeph(self.admin_node, self.mons, self.osds)

    def create_cluster(self):

        log.info('creating cluster, running "ceph-deploy new" ')

        self.mon_hostnames = []

        for each in self.mons:
            self.mon_hostnames.append(str(each.hostname))

        self.osd_hostnames = []

        self.create_cliuster_cmd = "ceph-deploy new %s" % (" ".join(self.mon_hostnames))

        log.debug(self.create_cliuster_cmd)
        os.system(self.create_cliuster_cmd)

    def execute(self):

        if not self.set_repo:
            pass

        else:
            self.install_repo.execute()

        self.create_cluster()
        self.install_ceph.execute()
