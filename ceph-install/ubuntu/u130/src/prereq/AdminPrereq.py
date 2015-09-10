import os
import utils.log as log

class AdminFireWallSettings(object):
    def __init__(self,host):
        self.host = host
        self.ssh = 'ssh %s ' %host.hostname     # do not forget add space after the format specifier

    def firewall_settings_commands(self):

        # format to specifiy the command: " '<command>' "

        self.open_80 = " ' sudo iptables -I INPUT 1 -i eh0 -p tcp -s %s --dport 80 -j ACCEPT' " %(self.host.ip)
        self.open_2003 = " 'sudo iptables -I INPUT 1 -i eth0 -p tcp -s %s --dport 2003 -j ACCEPT' " %(self.host.ip)
        self.open_45005_4506 = " 'sudo iptables -I INPUT 1 -i eth0 -m multiport -p tcp -s %s --dports 4505:4506 -j ACCEPT' " %(self.host.ip)

        return self.open_80, self.open_2003, self.open_45005_4506

    def execute(self):

        commands = self.firewall_settings_commands()

        for command in commands:
            command = self.ssh + command

            log.info('execting firewall settings in admin node with command')
            log.debug(command)
            os.system(command)

class CreateUser(object):

    def __init__(self):
        pass


class DoAdminSettings(object):
    def __init__(self, admin_nodes):
        self.admin_nodes = admin_nodes # split will return a list.

    def do_settings(self):

        firewall_settings = AdminFireWallSettings(self.admin_nodes)
        firewall_settings.execute()