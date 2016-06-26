import libs.log as log
from utils.test_desc import AddTestInfo
from http_ops import Initialize
from utils.utils import get_calamari_config
import argparse


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        self.url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/" + "sync_object"


def exec_test(config_data):

    add_test_info = AddTestInfo(15, '\napi/v2/cluster/<fsid>/sync_object \n'
                                    'api/v2/cluster/<fsid>/sync_object/<sync_type>')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        cleaned_response = test.get(test.url)

        [test.get(test.url + "/" + k) for k in cleaned_response]

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

