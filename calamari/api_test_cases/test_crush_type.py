import libs.log as log
from utils.test_desc import AddTestInfo
from http_ops import Initialize
import argparse
from utils.utils import get_calamari_config


class Test(Initialize):
    def __init__(self, **config):
        super(Test, self).__init__(**config)

        self.config_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/crush_type"


def exec_test(config_data):
    add_test_info = AddTestInfo(18, '\napi/v2/cluster/fsid/crush_type \n'
                                    'api/v2/cluster/fsid/crush_type/<type_id>')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        cleaned_response = test.get(test.config_url)

        keys = [key['id'] for key in cleaned_response]

        get = lambda x: test.get(test.config_url + "/" + str(x))

        map(get, keys)

        add_test_info.success('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed('test error')

    return  add_test_info.completed_info()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation')

    parser.add_argument('-c', dest="config", default='config.yaml',
                        help='calamari config file: yaml file')

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)