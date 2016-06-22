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

        self.event_url = self.http_request.base_url + "event"

        self.cluster_event_url = self.http_request.base_url + "cluster/" + str(self.http_request.fsid) + "/event"

        self.server_event_url = self.http_request.base_url + "server"

        self.severity = ['INFO', 'WARNING', 'ERROR', 'RECOVERY']

    def get_event(self, url):

        try:

            response = self.http_request.get(url)

            log.info(response.content)

            response.raise_for_status()

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            log.debug(cleaned_response)

            return cleaned_response

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(5, '\napi/v2/event\n'
                                    'api/v2/cluster/<fsid>/event\n'
                                    'api/v2/server/<fqdn>/event\n')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        test.get_event(test.event_url)
        [test.get_event(test.event_url + '?severity=' + x) for x in test.severity]

        test.get_event(test.cluster_event_url)
        [test.get_event(test.cluster_event_url + '?severity=' + x) for x in test.severity]

        cleaned_response = test.get_event(test.server_event_url)
        servers = [server['fqdn'] for server in cleaned_response]
        [test.get_event(test.server_event_url + "/" + server) for server in servers]
        for server in servers:
            [test.get_event(test.server_event_url + "/" + server + '?severity=' + x) for x in test.severity]

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

