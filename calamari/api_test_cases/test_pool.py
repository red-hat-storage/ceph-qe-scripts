import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from utils.utils import check_request_id
from libs.request import APIRequest
import traceback
import json
from config import MakeMachines


class PoolDefinition(object):
    def __init__(self):
        pass


class Test(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.api_request = APIRequest(self.http_request)

        self.pool_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/pool"

        self.pool_name = 'pool_' + "api_testing"
        self.pool = None

    def get_pool(self):

        try:

            url = self.pool_url

            response = self.http_request.get(url)

            pretty_response = json.dumps(response.json(), indent=2)
            pools = json.loads(pretty_response)

            my_pool = None

            for pool in pools:
                if self.pool_name == pool['name']:
                    log.debug('got matching pool')
                    my_pool = pool
                    log.debug(my_pool)
                    break

            # asserts if my_pool is none,
            assert my_pool is not None, ("did not find any pool with the name %s" % self.pool_name)

            self.pool = my_pool


        except Exception:
            log.error('error %s:' % traceback.format_exc())

    def create_pool(self):

        # testing post operation

        try:

            url = self.pool_url

            pool_definition = PoolDefinition()

            pool_definition.name = self.pool_name
            pool_definition.size = 3
            pool_definition.pg_num = 64
            pool_definition.crush_ruleset = 0
            pool_definition.min_size = 2
            pool_definition.crash_replay_interval = 0
            pool_definition.pg_num = 64
            pool_definition.hashpspool = True
            pool_definition.quota_max_objects = 0
            pool_definition.quota_max_bytes = 0

            log.debug('pool definition complete')

            response = self.http_request.post(url, pool_definition.__dict__)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            pool_created = check_request_id(self.api_request, cleaned_response['request_id'])

            if pool_created:
                log.info('pool created')

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def edit_pool(self):

        try:

            self.get_pool()

            url = self.pool_url + "/" +str(self.pool['id'])

            pool_definition = PoolDefinition()

            pool_definition.name = self.pool_name + "_renamed"

            self.pool_name = pool_definition.name

            response = self.http_request.patch(url, pool_definition.__dict__)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            pool_created = check_request_id(self.api_request, cleaned_response['request_id'])

            if pool_created:
                log.info('pool patched')

            response = self.http_request.get(url)
            pretty_response = json.dumps(response.json(), indent=2)
            self.pool = json.loads(pretty_response)

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def delete_pool(self):

        try:

            url = self.pool_url + "/" + str(self.pool['id'])

            response = self.http_request.delete(url)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            pool_created = check_request_id(self.api_request, cleaned_response['request_id'])

            if pool_created:
                log.info('pool deleted')

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(4, '\n api/v2/cluster/<fsid>/crush_node \n'
                                   'api/v2/cluster/<fsid>/crush_node/<node_id>')
    add_test_info.started_info()

    try:
        pool_ops = Test(**config_data)

        pool_ops.create_pool()

        pool_ops.edit_pool()

        pool_ops.delete_pool()

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
