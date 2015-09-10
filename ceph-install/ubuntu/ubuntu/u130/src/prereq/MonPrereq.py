import os
import utils.log as log

class MonFireWallSettings(object):
    def __init__(self,host):
        self.host = host
        self.open_6789 = None
        self.ssh = 'ssh %s  ' %(host.hostname)       # do not forget add space after the access specifier

    def firewall_settings(self):
        self.open_6789 = self.ssh + " 'sudo iptables -I INPUT 1 -i eth0 -p tcp -s %s --dport 6789 -j ACCEPT' " %(self.host.ip)
        log.debug(self.open_6789)
        os.system(self.open_6789)

    def execute(self):

        log.info('executing mon firewall settings')

        log.debug( 'running firewall settings for mon: %s' %self.host.hostname )
        self.firewall_settings()

class NTPSettings(object):

    def __init__(self,host):
        self.host = host
        self.ssh = 'ssh %s  ' %(host.hostname)       # do not forget add space after the format specifier
        self.start_srv = None
        self.stop_srv = None
        self.ntp_sync = None

    def ntp_settings_commands(self):

        # format to specifiy the command: " '<command>' "

        self.start_srv = " 'sudo service ntp start' "
        self.stop_srv = " 'sudo service ntp status' "
        self.ntp_sync =  " 'ntpq -p' "

        return self.start_srv, self.stop_srv, self.ntp_sync

    def execute(self):

        log.info('executing mon NTP settings')
        commands = self.ntp_settings_commands()

        for command in commands:
            command = self.ssh + command

            log.debug( 'running command: %s: ' %command)
            log.debug(command)
            os.system(command)


class DoMonSettings(object):

    def __init__(self,mons):
        self.mons = mons

    def do_settings(self):

        log.info('in mon pre settings')

        for each_mon in self.mons:
            firewall_setting = MonFireWallSettings(each_mon)
            firewall_setting.execute()

            ntp_setting = NTPSettings(each_mon)
            ntp_setting.execute()
