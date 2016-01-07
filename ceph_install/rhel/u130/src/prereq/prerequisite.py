from AdminPrereq import DoAdminSettings
from MonPrereq import DoMonSettings
from OSDPrereq import DoOSDSetting
import utils.log as log


import os
import subprocess


class Prerequisites(object):
    def __init__(self, admin_nodes, mons, osds, creds):

        print 'in init of pre-req'
        self.admin_settings = DoAdminSettings(admin_nodes, creds)
        self.mon_settings = DoMonSettings(mons, creds)
        self.osd_settings = DoOSDSetting(osds,creds)


    def execute(self):

        print 'in exec of preq'

        log.debug('prereq execute functions')

        self.admin_settings.do_settings()
        self.mon_settings.do_settings()
        self.osd_settings.do_settings()
