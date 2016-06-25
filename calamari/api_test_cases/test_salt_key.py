import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        self.url = self.http_request.base_url + "key"


def exec_test(config_data):

    add_test_info = AddTestInfo(12, '\napi/v2/key\n'
                                    'api/v2/key/<minion_id>')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        cleaned_response = test.get(test.url)

        ids = [k['id'] for k in cleaned_response]

        get_minion_id = lambda x: test.get(test.url + "/" + x)

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

