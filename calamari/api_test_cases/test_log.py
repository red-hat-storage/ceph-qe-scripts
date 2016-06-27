import libs.log as log
from utils.test_desc import AddTestInfo
from http_ops import Initialize
import argparse
from utils.utils import get_calamari_config


class Test(Initialize):

    def __init__(self, **config_data):
        super(Test, self).__init__(**config_data)

        self.log_url = self.http_request.base_url + "cluster/" + str(self.http_request.fsid) + "/log"

        self.server_log_url = self.http_request.base_url + "server"


def exec_test(config_data):

    add_test_info = AddTestInfo(9,  '\napi/v2/cluster/<fsid>/log\n'
                                    'api/v2/server/<fqdn>/log\n'
                                    'api/v2/server/<fqdn>/log/<log_path>')
    add_test_info.started_info()

    try:

        test = Test(**config_data)

        test.get(test.log_url)

        cleaned_response = test.get(test.server_log_url)
        fqdns = [fqdn['fqdn'] for fqdn in cleaned_response]

        cleaned_response = [test.get(test.server_log_url + "/" + fqdn + "/log") for fqdn in fqdns]

        igonores = ['lastlog', 'wtmp']

        log_paths = [x for x in cleaned_response if x not in igonores]

        [test.get(test.server_log_url + "/" + fqdn + "/log" + "/" + path)
            for fqdn in fqdns for path in log_paths]

        add_test_info.success('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed('test error')

    return add_test_info.completed_info(config_data['log_copy_location'])


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation')

    parser.add_argument('-c', dest="config", default='config.yaml',
                        help='calamari config file: yaml file')

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)