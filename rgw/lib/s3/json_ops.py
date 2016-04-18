import json
import utils.log as log


class JsonFileOps(object):

    def __init__(self, filename):

        self.fname = filename

    def get_data(self):

        with open(self.fname) as fp:
            json_data = json.load(fp)
        fp.close()

        return json_data

    def add_data(self, data):

        with open(self.fname, "w") as fp:
            json.dump(data, fp, indent=4)
        fp.close()


class JBucket(JsonFileOps):

    def __init__(self, fname):

        self.fname = fname
        super(JBucket, self).__init__(self.fname)

    def add(self, bucket_name):

        json_data = self.get_data()

        bucket = json_data['buckets']

        new_bucket = {bucket_name: {'keys': list()}}

        bucket.update(new_bucket)

        self.add_data(json_data)

        return bucket_name


class JKeys(JsonFileOps):

    def __init__(self, fname):

        self.fname = fname

        super(JKeys, self).__init__(self.fname)

    def add(self, bucket_name, **new_key):

        json_data = self.get_data()

        bucket = json_data['buckets'][bucket_name]['keys']

        bucket.append(new_key)

        self.add_data(json_data)


class JMulpipart(JsonFileOps):

    def __init__(self, fname):
        self.fname = fname
        self.mp_id = None
        self.key_name = None
        self.total_parts_count = 0
        self.bucket_name = None
        self.remaining_file_parts = []

        super(JMulpipart, self).__init__(self.fname)

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