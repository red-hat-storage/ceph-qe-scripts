import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        assert self.http_request.getfsid(), "failed to get fsid"

        self.osd_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/osd"


def exec_test(config_data):

    add_test_info = AddTestInfo(9.1, '\naapi/v2/cluster/<fsid>/osd \n'
                                     'api/v2/cluster/<fsid>/osd/<osd_id> \n')

    add_test_info.started_info()

    try:
        osd_ops = Test(**config_data)

        contents = osd_ops.get(osd_ops.osd_url)

        osd_ids = [ids['id'] for ids in contents]

        patch = lambda data: [osd_ops.patch(osd_ops.osd_url + "/" + str(id), data) for id in osd_ids]

        data1 = {'up': False}

        patch(data1)

        data2 = {'up': True}

        patch(data2)

        add_test_info.status('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.status('test error')

    add_test_info.completed_info()


def exec_test2(config_data):

    add_test_info = AddTestInfo(9.2, '\napi/v2/cluster/<fsid>/osd/command \n'
                                     'api/v2/cluster/<fsid>/osd/<osd_id>/command \n'
                                     'api/v2/cluster/<fsid>/osd/<osd_id>/command/<command>\n')
    add_test_info.started_info()

    try:
        osd_ops = Test(**config_data)

        contents = osd_ops.get(osd_ops.osd_url)

        osd_ids = [ids['id'] for ids in contents]

        [osd_ops.get(osd_ops.osd_url + "/" + str(id) + "/command") for id in osd_ids]

        commands = osd_ops.get(osd_ops.osd_url + "/command")

        data = {'verify': False}

        [osd_ops.post(osd_ops.osd_url + "/" + str(osd_id) + "/" + "command" + "/" + command, data)
         for osd_id in osd_ids for command in commands]

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

    # exec_test2(calamari_config)
