import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APISaltKey(object):
    def __init__(self, **api_details):

        self.api = None

    def construct_api(self):
        self.api = 'key'
        log.debug(self.api)
        return self.api


class APISaltKeyOps(APISaltKey):

    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        super(APISaltKeyOps, self).__init__(**kwargs)
        self.json_salt_key = None

    def get_salt_key(self):

        api = self.construct_api()
        response = self.auth.request('GET', api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from  api')
        log.debug(pretty_response)
        self.json_salt_key = json.loads(pretty_response)

    def get_salt_key_id(self):

            log.debug('api testing with each id in the salt key')
            log.debug('****************************************')

            for each_id in self.json_salt_key:
                api = self.construct_api() + '/' + str(each_id['id'])
                log.debug('salt key with id %s' % str(each_id['id']))
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

    add_test_info = AddTestInfo(11, 'salt key and salt key id')
    add_test_info.started_info()

    try:

        api_salt_key = APISaltKeyOps(**config_data)
        api_salt_key.get_salt_key()
        api_salt_key.get_salt_key_id()

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
