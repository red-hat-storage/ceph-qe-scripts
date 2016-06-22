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

        self.log_url = self.http_request.base_url + "cluster/" + str(self.http_request.fsid) + "/log"

        self.server_log_url = self.http_request.base_url + "server"

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

    add_test_info = AddTestInfo(7, '\napi/v2/cluster/<fsid>/log\n'
                                      'api/v2/server/<fqdn>/log\n'
                                      'api/v2/server/<fqdn>/log/<log_path>')
    add_test_info.started_info()

    try:

        test = Test(**config_data)

        # test.get_event(test.log_url)

        cleaned_response = test.get_event(test.server_log_url)
        fqdns = [fqdn['fqdn'] for fqdn in cleaned_response]

        cleaned_response = [test.get_event(test.server_log_url + "/" + fqdn + "/log") for fqdn in fqdns]

        igonores = ['lastlog', 'wtmp']

        log_paths = [x for x in cleaned_response if x not in igonores]

        get_logs = lambda x: test.get_event(test.server_log_url + "/" + fqdn + "/log/" + x)

        map(get_logs, log_paths)

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

