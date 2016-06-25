import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        self.url = self.http_request.base_url + "info"


def exec_test(config_data):

    add_test_info = AddTestInfo(6, 'api/v2/info')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        test.get(test.url)

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


