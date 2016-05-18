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

        self.cli_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/cli"

    def cli_commands(self, command):

        # testing post operation

        try:

            log.info('post for commands: %s' % command)

            url = self.cli_url

            data = {'command': command}

            response = self.http_request.post(url, data)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            log.debug(cleaned_response)

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(2, 'api/v2/cluster/<fsid>/cli')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        test.cli_commands(command=['ceph', 'osd', 'tree'])

        test.cli_commands(command='ceph -s')

        test.cli_commands(command='ceph osd dump')

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


