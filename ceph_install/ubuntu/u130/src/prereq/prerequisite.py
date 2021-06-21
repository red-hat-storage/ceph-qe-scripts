import utils.log as log
from AdminPrereq import DoAdminSettings
from MonPrereq import DoMonSettings
from OSDPrereq import DoOSDSetting


class Prerequisites(object):
    def __init__(self, admin_nodes, mons, osds):
        self.admin_settings = DoAdminSettings(admin_nodes)
        self.mon_settings = DoMonSettings(mons)
        self.osd_settings = DoOSDSetting(osds)

    def execute(self):

        log.debug("prereq execute functions")

        self.admin_settings.do_settings()
        self.mon_settings.do_settings()
        self.osd_settings.do_settings()
