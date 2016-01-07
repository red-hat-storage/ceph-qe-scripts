from libs.pool import Pool, PoolDefinition
from libs.request import Request
import config
from utils.test_desc import AddTestInfo
import utils.log as log
from utils.utils import check_request_id


class PoolOps(object):
    def __init__(self, **kwargs):
        self.pool = Pool(**kwargs)
        self.request = Request(**config_data)

    def create_pool(self, part_pool_name):

        pool_definition = PoolDefinition()
        
        pool_definition.name = 'pool_' + str(part_pool_name)
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
        
        content = self.pool.create(pool_definition.__dict__)

        assert content, 'pool create failed'

        log.debug('pool created')

        pool_created = check_request_id(self.request, content['request_id'])

        if pool_created:
            log.info('pool created')

        pools = self.pool.get()

        my_pool = None

        for pool in pools:
            if pool_definition.name == pool['name']:
                log.debug('got matching pool')
                my_pool = pool
                log.debug(my_pool)
                break

        # asserts if my_pool is none,
        assert my_pool is not None, ("did not find any pool with the name %s" % pool_definition.name )

        return my_pool

    def edit_pool(self, pool_id):
        pass

    def cancel_pool_creation(self):
        t = self.request.cancel_request('d88d268d-fcf7-48f0-9da1-e93b023ac93c')
        print t

    def delete_pool(self, pool_id):

        content = self.pool.delete(pool_id)
        assert content, 'delete pool failed'

        pool_deleted = check_request_id(self.request, content['request_id'])

        if pool_deleted:
            log.info('pool deleted')

        return content


def exec_test(config_data):

    add_test_info = AddTestInfo(1, 'Pool testing')
    add_test_info.started_info()

    no_of_pools = 5

    for i in range(no_of_pools):

        print 'iteration no %s' % (i+1)

        log.info('---------------------iteration no %s-----------------' %(i+1))

        try:
            pool_ops = PoolOps(**config_data)
            pool_details = pool_ops.create_pool(str(i))
            log.debug('got created pool details\n%s' % pool_details)

            pool_ops.delete_pool(pool_details['id'])
            add_test_info.status('test ok')

        except AssertionError, e:
            log.error(e)
            add_test_info.status('test error')

    add_test_info.completed_info()


if __name__ == '__main__':
    config_data = config.get_config()

    if not config_data['auth']:
        log.error('auth failed')

    else:
        exec_test(config_data)