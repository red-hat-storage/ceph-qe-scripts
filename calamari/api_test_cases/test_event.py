import argparse

import libs.log as log
from http_ops import Initialize
from utils.test_desc import AddTestInfo
from utils.utils import get_calamari_config


class Test(Initialize):
    def __init__(self, **config):

        super(Test, self).__init__(**config)

        self.event_url = self.http_request.base_url + "event"

        self.cluster_event_url = (
            self.http_request.base_url
            + "cluster/"
            + str(self.http_request.fsid)
            + "/event"
        )

        self.server_event_url = self.http_request.base_url + "server"

        self.severity = ["INFO", "WARNING", "ERROR", "RECOVERY"]


def exec_test(config_data):
    add_test_info = AddTestInfo(
        7,
        "\napi/v2/event\n"
        "api/v2/cluster/<fsid>/event\n"
        "api/v2/server/<fqdn>/event\n",
    )
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        test.get(test.event_url)
        [test.get(test.event_url + "?severity=" + x) for x in test.severity]

        test.get(test.cluster_event_url)
        [test.get(test.cluster_event_url + "?severity=" + x) for x in test.severity]

        cleaned_response = test.get(test.server_event_url)
        servers = [server["fqdn"] for server in cleaned_response]
        [test.get(test.server_event_url + "/" + server) for server in servers]
        for server in servers:
            [
                test.get(test.server_event_url + "/" + server + "?severity=" + x)
                for x in test.severity
            ]

        add_test_info.success("test ok")

    except AssertionError, e:
        log.error(e)
        add_test_info.failed("test error")

    return add_test_info.completed_info(config_data["log_copy_location"])


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Calamari API Automation")

    parser.add_argument(
        "-c",
        dest="config",
        default="config.yaml",
        help="calamari config file: yaml file",
    )

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)
