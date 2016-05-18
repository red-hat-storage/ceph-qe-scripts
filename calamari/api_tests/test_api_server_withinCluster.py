import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIServerinCluster(object):
    def __init__(self, **api_details):

        self.fsid = api_details['fsid']
        self.base_api = 'cluster/'
        self.api = None

    def construct_api(self):
        self.api = self.base_api + self.fsid + '/' + 'server'
        log.debug(self.api)
        return self.api


class APIServerinClusterOps(APIServerinCluster):

    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        super(APIServerinClusterOps, self).__init__(**kwargs)
        self.json_resp = None

    def get_server(self):

        api = self.construct_api()
        response = self.auth.request('GET', api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from  api')
        log.debug(pretty_response)
        self.json_resp = json.loads(pretty_response)

    def get_server_fqdn(self):

            log.debug('api testing with each fqdn')
            log.debug('****************************************')

            for each_id in self.json_resp:
                api = self.construct_api() + '/' + str(each_id['fqdn'])
                log.debug('with id %s' % str(each_id['fqdn']))
                log.debug('api: %s' % api)

                response = self.auth.request('GET', api, verify=False)
                response.raise_for_status()
                log.debug('response: \n %s' % response.json())

                pretty_response = json.dumps(response.json(), indent=2)
                log.debug('pretty json response \n %s' % pretty_response)


    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(12, 'server with in cluster')
    add_test_info.started_info()

    try:

        api_server_cluster = APIServerinClusterOps(**config_data)
        api_server_cluster.get_server()
        api_server_cluster.get_server_fqdn()

        add_test_info.status('ok')

    except Exception, e:
        log.error('test error')
        log.error(e)
        add_test_info.status('error')

    add_test_info.completed_info()


if __name__ == '__main__':
    config_data = config.get_config()

    if not config_data['auth']:
        log.error('auth failed')

    else:
        exec_test(config_data)
