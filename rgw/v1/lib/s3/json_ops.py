import v1.utils.log as log
from v1.utils.utils import FileOps


class JBucket(FileOps):
    def __init__(self, fname):
        self.fname = fname
        self.type = 'json'
        super(JBucket, self).__init__(self.fname, self.type)

    def add(self, bucket_name):
        json_data = self.get_data()
        bucket = json_data['buckets']
        new_bucket = {bucket_name: {'keys': list()}}
        bucket.update(new_bucket)
        self.add_data(json_data)
        return bucket_name


class JKeys(FileOps):
    def __init__(self, fname):
        self.fname = fname
        self.type = 'json'
        super(JKeys, self).__init__(self.fname, self.type)

    def add(self, bucket_name, **new_key):
        json_data = self.get_data()
        bucket = json_data['buckets'][bucket_name]['keys']
        bucket.append(new_key)
        self.add_data(json_data)

    def modify(self):
        pass


class JMulpipart(FileOps):
    def __init__(self, fname):
        self.type = 'json'
        self.fname = fname
        self.mp_id = None
        self.key_name = None
        self.total_parts_count = 0
        self.bucket_name = None
        self.remaining_file_parts = []
        super(JMulpipart, self).__init__(self.fname, self.type)

    def create_json_data(self):
        log.info('creating json data')
        json_data = {'mp_id': self.mp_id,
                     'key_name': self.key_name,
                     'total_parts': self.total_parts_count,
                     'bucket_name': self.bucket_name,
                     'remaining_parts': self.remaining_file_parts
                     }
        return json_data

    def create_update_json_file(self):
        log.debug('creating_updating json file')
        json_data = self.create_json_data()
        self.add_data(json_data)

    def refresh_json_data(self):
        log.info('loading / refreshing json file')
        json_data = self.get_data()
        self.total_parts_count = json_data['total_parts']
        self.remaining_file_parts = json_data['remaining_parts']
        self.key_name = json_data['key_name']
        self.mp_id = json_data['mp_id']
