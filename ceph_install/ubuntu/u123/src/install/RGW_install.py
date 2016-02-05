import utils.log as log
import os

class rgw_install(object):

    def __init__(self, username, password, admin_node, mons, osds):
        self.username = username
        self.password = password
        self.admin_node = admin_node
        self.mons = mons
        self.osds = osds


        self.repoadd = " ceph-deploy install --repo "

