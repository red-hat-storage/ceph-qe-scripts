import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from libs.request import APIRequest
import traceback
import json
from config import MakeMachines


class Test(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.api_request = APIRequest(self.http_request)

        self.url = self.http_request.base_url + "key"

    def get_key(self, url):

        try:

            response = self.http_request.get(url)

            log.info(response.content)

            response.raise_for_status()

            pretty_response = json.dumps(response.json(), indent=2)

            log.info(pretty_response)

            cleaned_response = json.loads(pretty_response)

            return cleaned_response

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(12, '\napi/v2/key\n'
                                   'api/v2/key/<minion_id>')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        cleaned_response = test.get_key(test.url)

        ids = [k['id'] for k in cleaned_response]

        get_minion_id = lambda x: test.get_key(test.url + "/" + x)

        map(get_minion_id, ids)

        add_test_info.status('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.status('test error')

    add_test_info.completed_info()


if __name__ == '__main__':

    machines_config = MakeMachines()

    calamari_config = machines_config.calamari()
    mons = machines_config.mon()
    osds = machines_config.osd()

    exec_test(calamari_config)

