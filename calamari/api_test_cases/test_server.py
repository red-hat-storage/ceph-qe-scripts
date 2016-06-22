import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from libs.request import APIRequest
import traceback
import json
from config import MakeMachines


class Test1(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.api_request = APIRequest(self.http_request)

        self.url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/" + "server"

        self.url2 = self.http_request.base_url + "server"

    def get_server(self, url):

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


def exec_test1(config_data):

    add_test_info = AddTestInfo(13, '\napi/v2/cluster/<fsid>/server\n'
                                   '\napi/v2/cluster/<fsid>/server/<fqdn>\n')

    add_test_info.started_info()

    try:
        test = Test1(**config_data)

        cleaned_response = test.get_server(test.url)

        ids = [k['fqdn'] for k in cleaned_response]

        get_server_by_ids = lambda x: test.get_server(test.url + "/" + x)

        map(get_server_by_ids, ids)

        add_test_info.status('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.status('test error')

    add_test_info.completed_info()


def exec_test2(config_data):

    add_test_info = AddTestInfo(14, '\napi/v2/server'
                                   'api/v2/server/<fqdn>\n'
                                   'api/v2/server/<fqdn>/grains')

    add_test_info.started_info()

    try:
        test = Test1(**config_data)

        cleaned_response = test.get_server(test.url2)

        fqdns = [k['fqdn'] for k in cleaned_response]

        get_server_by_ids = lambda x: test.get_server(test.url + "/" + x)

        map(get_server_by_ids, fqdns)

        # get_server_by_grains = lambda x: test.get_server(test.url + "/" + x + "/" + "grains")

        # map(get_server_by_grains, fqdns)

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

    exec_test1(calamari_config)
    exec_test2(calamari_config)

