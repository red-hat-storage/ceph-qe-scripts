import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIMon(object):
    def __init__(self, **api_details):
        self.fsid = api_details['fsid']
        self.base_api = 'cluster/'
        self.api = None

    def construct_api(self):
        self.api = self.base_api + self.fsid + '/' + 'mon'
        log.debug(self.api)
        return self.api


class APIMonOps(APIMon):

    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        super(APIMonOps, self).__init__(**kwargs)
        self.json_mon = None

    def get_mon(self):

        api = self.construct_api()
        response = self.auth.request('GET', api)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from  api')
        log.debug(pretty_response)
        self.json_mon = json.loads(pretty_response)

    def get_mon_id(self):

            log.debug('api testing with mon id')
            log.debug('****************************************')

            for each_id in self.json_mon:

                # get mon_api_id
                api = self.construct_api() + '/' + str(each_id['name'])
                log.debug('mon with name %s' % str(each_id['name']))
                log.debug('api: %s' % api)

                response = self.auth.request('GET', api)
                response.raise_for_status()
                log.debug('response: \n %s' % response.json())

                pretty_response = json.dumps(response.json(), indent=2)
                log.debug('pretty json response \n %s' % pretty_response)

                # get mon_id_status

                mon_id_api = api + '/' + 'status'

                log.debug('api: %s' % mon_id_api)

                mon_status_response = self.auth.request('GET', mon_id_api)
                mon_status_response.raise_for_status()
                log.debug('response: \n %s' % mon_status_response.json())

                pretty_response = json.dumps(mon_status_response.json(), indent=2)
                log.debug('pretty json response \n %s' % pretty_response)

    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(8, 'mon and mon id status')
    add_test_info.started_info()

    try:

        api_mon_ops = APIMonOps(**config_data)
        api_mon_ops.get_mon()
        api_mon_ops.get_mon_id()

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

