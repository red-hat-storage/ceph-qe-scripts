import os
import utils.log as log

class EnableRepos(object):
    def __init__(self,host, qa_username, qa_password, pool_id):
        self.username = qa_username
        self.password = qa_password
        self.poolid = pool_id
        self.host = host
        self.ssh = 'ssh %s ' %host.hostname     # do not forget add space after the format specifier

    def enable_rhel_repo(self):
        print "Subscribing to RHEL rpms"
        self.unregister = " 'sudo subscription-manager unregister' "
        self.register_node = " 'sudo subscription-manager register --username %s --password %s' " % (self.username, self.password)
        self.refresh_node = " 'sudo subscription-manager refresh' "
        self.attach_poolid = " 'sudo subscription-manager attach --pool=%s' " % (self.poolid)
        self.enable_repo = " 'sudo subscription-manager repos --enable=rhel-7-server-rpms' "
        self.yum_update = " 'sudo yum update -y' "

        return self.unregister, self.register_node, self.refresh_node, self.attach_poolid, self.enable_repo, self.yum_update,

    def execute(self):
        print "Enabling the repos"

        commands = self.enable_rhel_repo()
        for command in commands:
            command = self.ssh + command

            log.info("Enabling RHEL repos to admin Node")
            log.debug(command)
            os.system(command)


class AdminFireWallSettings(object):
    def __init__(self,host):
        self.host = host
        self.ssh = 'ssh %s ' %host.hostname     # do not forget add space after the format specifier

    def firewall_settings_commands(self):
        print 'in admin firewall'        # format to specifiy the command: " '<command>' "

        self.start_firewalld = " ' sudo systemctl start firewalld' "
        self.enable_firewalld = " ' sudo systemctl enable firewalld' "
        self.verify_firewalld = "' sudo systemctl status firewalld.service' "
        self.open_80 = " ' sudo firewall-cmd --zone=public --add-port=80/tcp --permanent' "
        self.open_2003 = " 'sudo firewall-cmd --zone=public --add-port=2003/tcp --permanent' "
        self.open_45005_4506 = " 'sudo firewall-cmd --zone=public --add-port=4505-4506/tcp --permanent' "
        self.saveiptables = " 'sudo firewall-cmd --reload' "


        return self.start_firewalld, self.enable_firewalld, self.verify_firewalld, self.open_80, self.open_2003, self.open_45005_4506, self.saveiptables,

    def execute(self):
        print 'in admin execute'

        commands = self.firewall_settings_commands()
        for command in commands:
            command = self.ssh + command

            log.info('execting firewall settings in admin node with command')
            log.debug(command)
            os.system(command)


class InstallNTP(object):
    def __init__(self,host):
        self.host = host
        self.ssh = 'ssh %s ' %host.hostname     # do not forget add space after the format specifier
    def install_ntp_commands(self):
        print 'Installing NTP'

        self.install_ntp = " 'sudo yum install ntp -y' "
        self.enable_ntp = " 'sudo systemctl enable ntpd.service' "
        self.start_ntp = " 'sudo systemctl start ntpd' "
        self.verify_ntp = " 'sudo systemctl status ntpd' "
        self.ntp_sync = " 'ntpq -p' "

        return self.install_ntp, self. enable_ntp, self.start_ntp, self.verify_ntp, self.ntp_sync,

    def execute(self):
        print 'Installing NTP on Admin Node'

        commands = self.install_ntp_commands()
        for command in commands:
            command = self.ssh + command

            log.info('Installing NTP in Admin Node ')
            log.debug(command)
            os.system(command)


class DisableSelinux(object):
    def __init__(self,host):
        self.host = host
        self.ssh = 'ssh %s ' %host.hostname

    def disable_selinux_commands(self):
        print "Disable Selinux"
        self.disable_cli = " 'sudo setenforce 0'"
        self.disable_config = " 'sudo sed -i s/SELINUX=enforcing/SELINUX=permissive/ /etc/selinux/config' "

        return self.disable_cli, self.disable_config,

    def execute(self):
        print 'Disabling Selinux'

        commands = self.disable_selinux_commands()
        for command in commands:
            command = self.ssh + command

            log.info('Disabling Selinux ')
            log.debug(command)
            os.system(command)

class Adjustpid(object):
    def __init__(self,host):
        self.host = host
        self.ssh = 'ssh %s ' %host.hostname

    def adjust_pid_command(self):
        print "adjust pid"
        self.modify = " 'echo 4194303 | sudo tee /proc/sys/kernel/pid_max' "
        self.save_changes = " 'sudo sysctl -p' "

        return self.modify, self.save_changes,

    def execute(self):
        print 'adjust pid'

        commands = self.adjust_pid_command()
        for command in commands:
            command = self.ssh + command

            log.info('adjust pid')
            log.debug(command)
            os.system(command)


class CreateUser(object):

    def __init__(self):
        pass


class DoAdminSettings(object):
    def __init__(self, admin_nodes, creds):
        self.admin_nodes = admin_nodes # split will return a list.
        self.qa_username = creds['qa_username']
        self.qa_password = creds['qa_password']
        self.pool_id = creds['pool_id']


        print 'prining global values of class for dict crdentials'
        print self.qa_username

    def do_settings(self):

        print 'in run admin pre-req'

        add_repos = EnableRepos(self.admin_nodes, self.qa_username, self.qa_password, self.pool_id)
        add_repos.execute()

        firewall_settings = AdminFireWallSettings(self.admin_nodes)
        firewall_settings.execute()

        install_ntp = InstallNTP(self.admin_nodes)
        install_ntp.execute()

        disable_selinux = DisableSelinux(self.admin_nodes)
        disable_selinux.execute()

        adjust_pid = Adjustpid(self.admin_nodes)
        adjust_pid.execute()



