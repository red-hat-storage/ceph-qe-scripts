import argparse

import libs.log as log
from http_ops import Initialize
from utils.test_desc import AddTestInfo
from utils.utils import get_calamari_config

crush_rule_edition = {
    "name": "replicated_ruleset-TEST",
    "ruleset": 0,
    "min_size": 1,
    "max_size": 10,
    "steps": [
        {"item_name": "default", "item": -1, "op": "take"},
        {"num": 0, "type": "host", "op": "chooseleaf_firstn"},
        {"op": "emit"},
    ],
}

crush_rule_defination = {
    "name": "replicated_ruleset-TEST-new-2",
    "ruleset": 0,
    "type": "replicated",
    "min_size": 1,
    "max_size": 10,
    "steps": [
        {"item_name": "default", "item": -1, "op": "take"},
        {"num": 0, "type": "host", "op": "chooseleaf_firstn"},
        {"op": "emit"},
    ],
}


class Test(Initialize):
    def __init__(self, **config):

        super(Test, self).__init__(**config)

        self.crush_rule_url = (
            self.http_request.base_url
            + "cluster"
            + "/"
            + str(self.http_request.fsid)
            + "/crush_rule"
        )


def exec_test(config_data):

    add_test_info = AddTestInfo(
        4,
        "api/v2/cluster/<fsid>/crush_rule \n"
        "api/v2/cluster/<fsid>/crush_rule/<rule_id>",
    )
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        test.get(test.crush_rule_url)

        crush_rule_name = "rule_" + "api_testing"

        crush_rule_defination["name"] = crush_rule_name

        log.debug("json data: \n %s" % crush_rule_defination)

        test.post(test.crush_rule_url, crush_rule_defination)

        crush_rules = test.get(test.crush_rule_url)

        my_rule = None

        for rule in crush_rules:
            if crush_rule_name == rule["name"]:
                log.debug("matched")
                my_rule = rule
                log.debug(my_rule)
                break

        # my_rule = [rule for rule in crush_rules if crush_rule_name == rule['name']]

        # asserts if my_rule is none,
        assert my_rule is not None, "did not find any with name %s" % crush_rule_name

        test.patch(test.crush_rule_url + "/" + str(my_rule["id"]), crush_rule_edition)

        test.get(test.crush_rule_url)

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
