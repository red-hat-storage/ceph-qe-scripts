import os

import utils.log as log


class OSDFireWallSettings(object):
    def __init__(self, host):
        self.host = host
        self.ssh = (
            "ssh %s " % host.hostname
        )  # do not forget add space after the format specifier

    def firewall_settings_commands(self):

        # format to specifiy the command: " '<command>' "

        self.open_6789 = (
            " ' sudo iptables -I INPUT 1 -i eth0 -p tcp -s %s --dport 6789 -j ACCEPT' "
            % (self.host.ip)
        )
        self.saveiptables = " 'sudo apt-get install iptables-persistent' "
        return self.open_6789

    def execute(self):

        log.info("command for firewall settings for osd")
        command = self.firewall_settings_commands()
        command = self.ssh + command
        log.debug(command)
        os.system(command)


class NTPSettings(object):
    def __init__(self, host):
        self.host = host
        self.ssh = "ssh %s  " % (
            host.hostname
        )  # do not forget add space after the format specifier
        self.start_srv = None
        self.stop_srv = None
        self.ntp_sync = None

    def ntp_settings_commands(self):

        # format to specifiy the command: " '<command>' "
        self.install_ntp = " 'sudo apt-get install ntp -y' "
        self.start_srv = " 'sudo service ntp start' "
        self.stop_srv = " 'sudo service ntp status' "
        self.ntp_sync = " 'ntpq -p' "

        return self.install_ntp, self.start_srv, self.stop_srv, self.ntp_sync

    def execute(self):

        log.info("executing osd NTP settings")
        commands = self.ntp_settings_commands()

        for command in commands:
            command = self.ssh + command

            log.debug("running command: %s: " % command)
            log.debug(command)
            os.system(command)


class DoOSDSetting(object):
    def __init__(self, osds):
        self.osds = osds

    def do_settings(self):

        for each_osd in self.osds:
            log.debug("running firewall settings for %s" % each_osd.hostname)
            firewall_setting = OSDFireWallSettings(each_osd)
            firewall_setting.execute()
            ntp_setting = NTPSettings(each_osd)
            ntp_setting.execute()
