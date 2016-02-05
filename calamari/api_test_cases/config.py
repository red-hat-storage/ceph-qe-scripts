import json

from libs.http_client import AuthenticatedHttpClient
import utils.log as log
from utils.utils import Machines


class MakeMachines(object):
    def __init__(self):
        pass

    def osd(self):
        osd1 = Machines('10.8.128.61', 'magna061')
        osd2 = Machines('10.8.128.63', 'magna063')

        return osd1, osd2

    def mon(self):
        mon1 = Machines('10.8.128.61', 'magna061')
        mon2 = Machines('10.8.128.63', 'magna063')

        return mon1, mon2

    def admin(self):
        admin_node = Machines('10.8.128.28', 'magna028')

        return admin_node

    def calamari(self):
        username = 'admin'
        password = 'admin123'
        uri = 'http://10.8.128.28/api/v2/'

        return uri, username, password


def get_config():
    # http://10.8.128.28/api/v2/ --user admin --pass admin123

    make_machines = MakeMachines()

    admin_node = make_machines.admin()
    monsL = make_machines.mon()
    osdL = make_machines.osd()

    uri, username, password = make_machines.calamari()

    try:
        # login
        c = AuthenticatedHttpClient(uri, username, password)
        c.login()

        # GET Cluster
        cluster_response = c.request('GET', 'cluster')
        cluster_response.raise_for_status()
        pretty_cluster_details = json.dumps(cluster_response.json(), indent=2)
        pretty_cluster_json = json.loads(pretty_cluster_details)[0]

        config_data = {'auth': c,
                       'fsid': pretty_cluster_json['id'],
                       'admin_node': admin_node,
                       'monsL': monsL,
                       'osdL': osdL
                       }

    except Exception, e:
        log.error('error in auth')
        log.error(e)

        config_data = {'auth': None}

    return config_data
