import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        assert self.http_request.getfsid(), "failed to get fsid"

        self.url = self.http_request.base_url + "cluster/" + str(self.http_request.fsid) + "/crush_rule_set"


def exec_test(config_data):

    add_test_info = AddTestInfo(18, '\napi/v2/cluster/<fsid>/crush_rule_set\n')
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

