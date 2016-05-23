import json

from libs.http_client import AuthenticatedHttpClient
from utils.utils import Machines, log


class MakeMachines(object):
    def __init__(self):
        pass

    def osd(self):
        osd1 = Machines('10.8.128.70', 'magna070')
        osd2 = Machines('10.8.128.72', 'magna072')
        osd3 = Machines('10.8.128.79', 'magna079')

        return osd1, osd2, osd3

    def mon(self):
        mon1 = Machines('10.8.128.70', 'magna070')

        return mon1

    def admin(self):
        admin_node = Machines('10.8.128.70', 'magna070')

        return admin_node

    def calamari(self):
        username = 'admin'
        password = 'admin123'
        uri = 'https://10.8.128.70:8002/api/v2/'

        return uri, username, password


def get_config():

    # http://10.8.128.28/api/v2/ --user admin --pass admin123

    username = 'admin'
    password = 'admin123'
    uri = 'https://10.8.128.70:8002/api/v2/'

    make_machines = MakeMachines()

    admin_node = make_machines.admin()
    monsL = make_machines.mon()
    osdL = make_machines.osd()

    try:
        # login
        c = AuthenticatedHttpClient(uri, username, password)
        c.login()

        # base API get
        response = c.request('GET', '' , verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug(pretty_response)


        # API Cluster response
        cluster_response = c.request('GET', 'cluster', verify=False)
        cluster_response.raise_for_status()
        pretty_cluster_details = json.dumps(cluster_response.json(), indent=2)
        pretty_cluster_json = json.loads(pretty_cluster_details)[0]

        # API grains
        # log.info('api grains list')
        # log.info('--------------------')
        # info_response = c.request('GET', 'info', verify=False)
        # info_response.raise_for_status()
        # pretty_info_response = json.dumps(info_response.json(), indent=2)
        # pretty_info_response_json = json.loads(pretty_info_response)
        # log.debug(pretty_info_response_json)
        # log.debug('-------------------------')


        # API User list
        log.info('api users list')
        log.info('--------------------')
        user_response = c.request('GET', 'user', verify=False)
        user_response.raise_for_status()
        pretty_user_response = json.dumps(user_response.json(), indent=2)
        pretty_user_response_json = json.loads(pretty_user_response)
        log.debug(pretty_user_response_json)

        # API grains
        # log.info('api grains list')
        # log.info('--------------------')
        # response_grains = c.request('GET', 'grains', verify=False)
        # response_grains.raise_for_status()
        # pretty_response_grains = json.dumps(response_grains.json(), indent=2)
        # pretty_response_grains_json = json.loads(pretty_response_grains)
        # #log.debug(pretty_response_grains_json)
        # log.debug('-------------------------')

        # API cluster with fsid
        cluster_with_fsid_api = 'cluster' + '/' + pretty_cluster_json['id']
        log.debug('cluster with fsid %s:' %cluster_with_fsid_api )

        cluster_id_response = c.request('GET', cluster_with_fsid_api, verify=False)
        cluster_id_response.raise_for_status()
        pretty_cluster_id = json.dumps(cluster_id_response.json(), indent=2)
        pretty_cluster_id_json = json.loads(pretty_cluster_id)
        log.debug('pretty cluster_id json data %s' %pretty_cluster_id_json)

        config_data ={'auth': c,
              'fsid': pretty_cluster_json['id'],
              'admin_node': admin_node,
              'monsL': monsL,
              'osdL': osdL
              }

    except Exception, e:
        log.error('error in auth')
        log.error(e)

        config_data ={'auth': None}

    return config_data
