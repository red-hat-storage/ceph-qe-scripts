import libs.log as log
from utils.test_desc import AddTestInfo
from http_ops import Initialize
import argparse
from utils.utils import get_calamari_config

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

        add_test_info.success('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed('test error')

    return add_test_info.completed_info()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation')

    parser.add_argument('-c', dest="config", default='config.yaml',
                        help='calamari config file: yaml file')

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)
