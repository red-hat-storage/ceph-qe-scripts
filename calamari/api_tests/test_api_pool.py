import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIPool(object):
    def __init__(self, **api_details):
        self.fsid = api_details['fsid']
        self.base_api = 'cluster/'
        self.api = None

    def construct_api(self):
        self.api = self.base_api + self.fsid + '/' + 'pool'
        log.debug(self.api)
        return self.api


class APIPoolOps(APIPool):

    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        super(APIPoolOps, self).__init__(**kwargs)
        self.json_pool = None

    def get_pool(self):

        api = self.construct_api()
        response = self.auth.request('GET', api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(),indent=2)
        log.debug('pretty json response from  api')
        log.debug(pretty_response)
        self.json_pool = json.loads(pretty_response)

    def get_pool_id(self):

            log.debug('api testing with each id in the crush node')
            log.debug('****************************************')

            for each_id in self.json_pool:

                print 'each_id type %s' % type(each_id)

                api = self.construct_api() + '/' + str(each_id['id'])
                log.debug('pool with id %s' % str(each_id['id']))
                log.debug('api: %s' % api)

                response = self.auth.request('GET', api, verify=False)
                response.raise_for_status()
                log.debug('response: \n %s' % response.json())

                pretty_response = json.dumps(response.json(), indent=2)
                log.debug('pretty json response \n %s' % pretty_response)


    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(9, 'test pool and pool id')
    add_test_info.started_info()

    try:

        api_pool_ops = APIPoolOps(**config_data)
        api_pool_ops.get_pool()
        api_pool_ops.get_pool_id()

        add_test_info.status('ok')

    except Exception, e:
        log.error('test error')
        log.error(e)
        add_test_info.status('error')

    add_test_info.completed_info()


if __name__ == '__main__':
    config_data = config.get_config()

    if not config_data['auth']:
        log.error('auth failed')

    else:
        exec_test(config_data)
