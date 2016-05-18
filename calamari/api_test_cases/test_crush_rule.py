import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from utils.utils import check_request_id
from libs.request import APIRequest
import traceback
import json
from config import MakeMachines


crush_rule_defination = {
        "name": None,     # string
        "ruleset": None,  # 1 or 0
        "type": None,     # replicated
        "min_size": 1,
        "max_size": 10,
        "steps": [
            {
                "item_name": "default",
                "item": -1,
                "op": "take"
            },
            {
                "num": 0,
                "type": "host",
                "op": "chooseleaf_firstn"
            },
            {
                "op": "emit"
            }
        ]
    }


class Test(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        logged_in = self.http_request.login()

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.crush_rule_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/crush_rule"

        self.rule_name = 'rule_' + "api_testing"
        self.crush_rule = None

    def get_cursh_rule(self):

        try:

            url = self.crush_rule_url

            response = self.http_request.get(url)

            pretty_response = json.dumps(response.json(), indent=2)
            rules = json.loads(pretty_response)

            my_rule = None

            for rule in rules:
                if self.rule_name == rule['name']:
                    log.debug('matched')
                    my_rule = my_rule
                    log.debug(my_rule)
                    break

            # asserts if my_rule is none,
            assert my_rule is not None, ("did not find any with name %s" % self.rule_name)

            self.crush_rule = my_rule

        except Exception:
            log.error('error: \n%s' % traceback.format_exc())
            raise AssertionError

    def create_crush_rule(self):

        # testing post operation

        try:

            url = self.crush_rule_url

            crush_rule_defination['name'] = self.rule_name
            crush_rule_defination['ruleset'] = 1
            crush_rule_defination['type'] = 'replicated'

            log.debug('definition complete')

            log.info(crush_rule_defination)

            response = self.http_request.post(url, crush_rule_defination)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            created = check_request_id(self.api_request, cleaned_response['request_id'])

            if created:
                log.info('created')

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def edit_crush_rule(self):

        try:

            # self.get_cursh_rule()

            url = self.crush_rule_url + "/" +str(2)

            data = {'name': self.rule_name + '_renamed'}

            print data

            response = self.http_request.patch(url, data)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            patched = check_request_id(self.api_request, cleaned_response['request_id'])

            if patched:
                log.info('patched')

            response = self.http_request.get(url)
            pretty_response = json.dumps(response.json(), indent=2)
            self.crush_rule = json.loads(pretty_response)

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def delete_crush_rule(self):

        try:

            url = self.crush_rule_url + "/" + str(self.crush_rule['id'])

            response = self.http_request.delete(url)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            deleted = check_request_id(self.api_request, cleaned_response['request_id'])

            if deleted:
                log.info('deleted')

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(4, 'api/v2/cluster/<fsid>/crush_rule \n'
                                   'api/v2/cluster/<fsid>/crush_rule/<rule_id>')
    add_test_info.started_info()

    try:
        pool_ops = Test(**config_data)

        # pool_ops.create_crush_rule()

        pool_ops.edit_crush_rule()

        pool_ops.delete_crush_rule()

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
