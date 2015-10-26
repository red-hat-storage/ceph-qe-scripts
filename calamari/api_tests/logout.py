import json

import config
import utils.log
from utils.test_desc import AddTestInfo


class Logout(object):
    def __init__(self, **api_details):
        self.fsid = api_details['fsid']
        self.api = 'auth/logout'
        self.auth = api_details['auth']

    def do_logout(self):

        response = self.auth.request('GET', self.api)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        utils.log.debug('pretty json response from api')
        utils.log.debug(pretty_response)
        self.json_config = json.loads(pretty_response)


def exec_test(config_data):

    add_test_info = AddTestInfo(00, 'logout')
    add_test_info.started_info()

    try:
        logout = Logout(**config_data)
        logout.do_logout()

        add_test_info.status('ok')

    except Exception, e:
        utils.log.error('test error')
        utils.log.error(e)
        add_test_info.status('error')

    add_test_info.completed_info()


if __name__ == '__main__':
    config_data = config.get_config()

    if not config_data['auth']:
        utils.log.error('auth failed')

    else:
        exec_test(config_data)
