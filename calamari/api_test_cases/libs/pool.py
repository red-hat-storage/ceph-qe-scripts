import utils.log as log
from utils.utils import pretty_ressponse, validate_http


class PoolDefinition(object):
    def __init__(self):
        self.name = None
        self.size = None
        self.pg_num = None
        self.crush_ruleset = None
        self.min_size = None
        self.crash_replay_interval = None
        self.pgp_num = None
        self.hashpspool = None
        self.quota_max_objects = None
        self.quota_max_bytes = None


class APIPool(object):
    def __init__(self, fsid):
        self.fsid = fsid
        self.base_api = 'cluster/' + self.fsid + '/' + 'pool'

    def pool(self):
        return self.base_api

    def pool_id(self, id):
        api = self.base_api + '/' + str(id)
        return api


class Pool(object):
    def __init__(self, **kwargs):
        self.auth = kwargs['auth']
        self.api = APIPool(kwargs['fsid'])

    def create(self, pool_def):

        log.debug('in create pool')

        response = self.auth.post(self.api.pool(), pool_def)
        content = validate_http(response)
        return content

    def get(self):
        log.debug('in get pools')
        response = self.auth.request('GET', self.api.pool())
        content = validate_http(response)
        return content

    def delete(self, pool_id):

        log.debug('in delete pool')

        response = self.auth.delete(self.api.pool_id(pool_id))
        content = validate_http(response)
        return content

    def edit(self, pool_id, patch_def):

        log.debug('in patch pool')

        response = self.auth.patch(self.api.pool_id(pool_id), patch_def)
        content = validate_http(response)
        return content





