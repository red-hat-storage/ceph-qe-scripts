import libs.log as log
from utils.test_desc import AddTestInfo
from config import MakeMachines
from http_ops import Initialize


class Test(Initialize):

    def __init__(self, **config_data):
        super(Test, self).__init__(**config_data)

        assert self.http_request.getfsid(), "failed to get fsid"

        self.log_url = self.http_request.base_url + "cluster/" + str(self.http_request.fsid) + "/log"

        self.server_log_url = self.http_request.base_url + "server"


def exec_test(config_data):

    add_test_info = AddTestInfo(7,  '\napi/v2/cluster/<fsid>/log\n'
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