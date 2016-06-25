import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize

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


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        assert self.http_request.getfsid(), "failed to get fsid"

        self.osd_config_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/osd_config"


def exec_test(config_data):

    add_test_info = AddTestInfo(10, '\napi/v2/cluster/<fsid>/osd_config \n' )
    add_test_info.started_info()

    try:

        config_ops = Test(**config_data)

        config_ops.get(config_ops.osd_config_url)

        patch = lambda data: config_ops.patch(config_ops.osd_config_url, data)

        data1 = {'nodeep-scrub': True,
                 "nobackfill": True}

        patch(data1)

        data2 = {'nodeep-scrub': False,
                 "nobackfill": False,
                 'noscrub': False}

        patch(data2)

        config_ops.get(config_ops.osd_config_url)

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
