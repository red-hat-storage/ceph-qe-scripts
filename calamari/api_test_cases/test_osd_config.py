import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from utils.utils import check_request_id
from libs.request import APIRequest
import traceback
import json
from config import MakeMachines

OSD_Config = {
    "pause": False,
    "nobackfill": False,
    "noout": False,
    "nodeep-scrub": False,
    "noscrub": False,
    "noin": False,
    "noup": False,
    "norecover": False,
    "nodown": False
}


class Test(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.api_request = APIRequest(self.http_request)

        self.osd_config_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/osd_config"

        self.osd_config = None

    def get_osd_config(self):

        url = self.osd_config_url

        response = self.http_request.get(url)

        pretty_response = json.dumps(response.json(), indent=2)
        osd_config = json.loads(pretty_response)

        self.osd_config = osd_config

    def edit_osd_config(self, data):

        try:

            url = self.osd_config_url

            response = self.http_request.patch(url, data)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            patched = check_request_id(self.api_request, cleaned_response['request_id'])

            if patched:
                log.info('patched')

            response = self.http_request.get(url)
            pretty_response = json.dumps(response.json(), indent=2)
            self.osd_config = json.loads(pretty_response)

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(10, '\napi/v2/cluster/<fsid>/osd_config \n' )
    add_test_info.started_info()

    try:
        config_ops = Test(**config_data)

        data = {'nodeep-scrub': True,
                "nobackfill": True}

        config_ops.edit_osd_config(data)

        data = {'nodeep-scrub': False,
                "nobackfill": False,
                'noscrub': False}

        config_ops.edit_osd_config(data)

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
