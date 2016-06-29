import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APILogs(object):
    def __init__(self, **api_details):
        self.fsid = api_details['fsid']
        self.server_fqdn = api_details['admin_node']

    def construct_cluster_api(self):
        self.cluster_api = 'cluster/' + self.fsid + '/' + 'log'
        log.debug(self.cluster_api)
        return self.cluster_api

    def contruct_server_api(self):
        self.server_api = 'server'
        log.debug(self.server_api)
        return self.server_api


class APILogsOps(APILogs):

    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        super(APILogsOps, self).__init__(**kwargs)
        self.json_config = None

    def get_cluster_log(self):

        log.debug('-----------cluster log api---------')

        api = self.construct_cluster_api()
        response = self.auth.request('GET', api, verify=False)
        response.raise_for_status()
        log.info('\n%s' %response.json())

        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from api %s\n' % pretty_response)


    def get_server_log(self):

        log.debug('--------------server logs api-----------')

        api = self.contruct_server_api()
        response = self.auth.request('GET', api, verify=False)
        response.raise_for_status()
        log.info('\n%s' %response.json())


        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from api %s\n' % pretty_response)


        for each_server in response.json():
            log.debug('---------------got server------------- %s' % each_server['fqdn'])
            server_log_api = api + '/' + each_server['fqdn'] + '/' + 'log'
            server_log_path = self.auth.request('GET', server_log_api, verify=False)
            server_log_path.raise_for_status()
            server_log_path_json = server_log_path.json()

            for path in server_log_path_json:

                skip = ['lastlog', 'wtmp']

                if path not in skip:
                    server_log = server_log_api + '/' + path
                    log.debug('log for:%s' % server_log)
                    logs = self.auth.request('GET', server_log, verify=False)
                    logs.raise_for_status()
                    logs.json()
                    #log.debug(logs)

            log.debug('Server with grains api')
            server_grains_api = api + '/' + each_server['fqdn'] + '/' + 'grains'
            log.debug(server_grains_api)
            server_grains = self.auth.request('GET', server_grains_api, verify=False)
            server_grains.raise_for_status()
            server_grains_json = server_grains.json()
            #log.debug('pretty json response\n%s' % server_grains_json)



    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(7, 'log tails')
    add_test_info.started_info()
    try:
        api_logs_ops = APILogsOps(**config_data)
        api_logs_ops.get_cluster_log()
        api_logs_ops.get_server_log()
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
