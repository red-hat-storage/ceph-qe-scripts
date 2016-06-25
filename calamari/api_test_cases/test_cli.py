import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        assert self.http_request.getfsid(), "failed to get fsid"

        self.cli_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/cli"


def exec_test(config_data):

    add_test_info = AddTestInfo(1, 'api/v2/cluster/<fsid>/cli')
    add_test_info.started_info()

    try:

        test = Test(**config_data)

        commands = ['ceph osd tree',
                    ['ceph', '-s'],
                    ["ceph", "osd", "dump"]
                    ]

        data_to_post = map(lambda x: {'command': x}, commands)

        results = [test.post(test.cli_url, each_data, request_api=False) for each_data in data_to_post]

        failed = [(command, result) for result, command in zip(results, commands)
                  if result['status'] != 0 and result['err'] != ""]

        if failed:
            raise AssertionError(failed)

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
