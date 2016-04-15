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

