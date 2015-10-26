import json

import config
import utils.log
from utils.test_desc import AddTestInfo


class CLI(object):
    def __init__(self, **api_details):
        self.fsid = api_details['fsid']
        self.auth = api_details['auth']
        self.base_api = 'cluster/' + self.fsid + '/cli'


    def post_command(self, command):


        post_data = {'command': command}
        utils.log.debug('post_data\n%s' %post_data)

        response = self.auth.post(self.base_api, post_data)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        utils.log.debug('pretty json response from api')
        utils.log.debug(pretty_response)
        json_response = json.loads(pretty_response)
        utils.log.debug(json_response)


def exec_test(config_data):

    add_test_info = AddTestInfo(00, 'cli')
    add_test_info.started_info()

    try:
        cli = CLI(**config_data)
        cli.post_command('osd tree')

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
