import json

import config as config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIConfig(object):
    def __init__(self, **api_details):
        self.fsid = api_details['fsid']
        self.base_api = 'cluster/'
        self.api = None

    def construct_api(self):
        self.api = self.base_api + self.fsid + '/' + 'config'
        log.debug(self.api)
        return self.api


class APIConfigOps(APIConfig):

    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        super(APIConfigOps, self).__init__(**kwargs)
        self.json_config = None

    def get_config(self):

        api = self.construct_api()
        response = self.auth.request('GET', api)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from config api')
        log.debug(pretty_response)
        self.json_config = json.loads(pretty_response)

    def get_config_key(self):

            log.debug('api testing with each key in the config')
            log.debug('****************************************')

            for each_key in self.json_config:
                api = self.construct_api() + '/' + each_key['key']
                log.debug('config with key %s' % each_key['key'])
                log.debug('api: %s' % api)

                response = self.auth.request('GET', api)
                response.raise_for_status()

                log.debug('response: \n %s' % response.json())
                pretty_response = json.dumps(response.json(), indent=2)
                log.debug('pretty json response \n %s' % pretty_response)


    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(1, 'config and config with keys')
    add_test_info.started_info()

    try:
        api_config_ops = APIConfigOps(**config_data)
        api_config_ops.get_config()
        api_config_ops.get_config_key()
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
