import utils.log as log
from utils.utils import FileOps

IO_INFO_FNAME = 'io_info.yaml'


# class to generate the yaml structure.

class IOInfoStructure(object):
    def __init__(self):
        self.initial = lambda: {'users': list()}

        self.user = lambda **args: {'user_id': args['user_id'],
                                    'access_key': args['access_key'],
                                    'secret_key': args['secret_key'],
                                    'bucket': list()
                                    }

        self.bucket = lambda **args: {'name': args['bucket_name'], 'keys': list(), 'test_op_code': args['test_op_code']}

        self.key = lambda **args: {'name': args['key_name'],
                                   'size': args['size'],
                                   'md5_on_s3': args['md5_on_s3'],
                                   'upload_type': args['upload_type'],
                                   'test_op_code': args['test_op_code']}


# class to add io info to yaml file

class AddIOInfo(object):
    def __init__(self, yaml_fname=IO_INFO_FNAME):

        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type='yaml')

        self.io_structure = IOInfoStructure()

    def initialize(self):

        initial_data = self.io_structure.initial()
        log.info('initial_data: %s' % (initial_data))

        self.file_op.add_data(initial_data)


    def add_user_info(self, **user):

        user_info = self.io_structure.user(**user)

        log.info('got user info structure: %s' % user_info)

        yaml_data = self.file_op.get_data()

        log.info('got yaml data %s' % yaml_data)

        yaml_data['users'].append(user_info)

        log.info('data to add: %s' % yaml_data)

        self.file_op.add_data(yaml_data)

    def add_bucket_info(self, access_key, **bucket):

        bucket_info = self.io_structure.bucket(**bucket)

        yaml_data = self.file_op.get_data()

        indx = None

        for i, k in enumerate(yaml_data['users']):
            if k['access_key'] == access_key:
                indx = i
                break

        yaml_data['users'][indx]['bucket'].append(bucket_info)

        self.file_op.add_data(yaml_data)

    def add_keys_info(self, access_key, bucket_name, **key):

        yaml_data = self.file_op.get_data()

        access_key_indx = None
        bucket_indx = None

        for i, k in enumerate(yaml_data['users']):
            if k['access_key'] == access_key:
                access_key_indx = i
                break

        for i, k in enumerate(yaml_data['users'][access_key_indx]['bucket']):

            if k['name'] == bucket_name:
                bucket_indx = i
                break

        key_info = self.io_structure.key(**key)

        yaml_data['users'][access_key_indx]['bucket'][bucket_indx]['keys'].append(key_info)

        self.file_op.add_data(yaml_data)


if __name__ == '__main__':
    # test data

    user_data1 = {'user_id': 'batman',
                  'access_key': '235sff34',
                  'secret_key': '87324skfs',
                  }

    user_data2 = {'user_id': 'heman',
                  'access_key': 'sfssf',
                  'secret_key': '87324skfs',
                  }

    user_data3 = {'user_id': 'antman',
                  'access_key': 'fwg435',
                  'secret_key': '87324skfs',
                  }

    io_info = AddIOInfo('io_info.yaml')
    io_info.initialize()

    io_info.add_user_info(**user_data1)

    io_info.add_bucket_info(access_key='235sff34', **{'bucket_name': 'b1'})
    io_info.add_bucket_info(access_key='235sff34', **{'bucket_name': 'b2'})
    io_info.add_bucket_info(access_key='235sff34', **{'bucket_name': 'b3'})

    key_info1 = {'key_name': 'k1', 'size': 374, 'md5_on_s3': 'sfsf734', 'upload_type': 'normal'}
    key_info2 = {'key_name': 'k2', 'size': 242, 'md5_on_s3': 'sgg345', 'upload_type': 'normal'}
    key_info3 = {'key_name': 'k3', 'size': 3563, 'md5_on_s3': 'sfy4hfd', 'upload_type': 'normal'}

    key_info4 = {'key_name': 'k4', 'size': 2342, 'md5_on_s3': 'sfsf3534', 'upload_type': 'normal'}

    io_info.add_keys_info(access_key='235sff34', bucket_name='b1', **key_info1)
    io_info.add_keys_info(access_key='235sff34', bucket_name='b3', **key_info2)
    io_info.add_keys_info(access_key='235sff34', bucket_name='b3', **key_info3)
    io_info.add_keys_info(access_key='235sff34', bucket_name='b3', **key_info4)
