from auth import Authenticate
from bucket import Bucket
from objects import KeyOp, PutContentsFromFile, MultipartPut
import v1.utils.log as log
import v1.utils.utils as utils
import os
import names
from v1.lib.admin import UserMgmt
import random
import string


def create_users(no_of_users_to_create, cluster_name='ceph'):
    admin_ops = UserMgmt()

    all_users_details = []

    for i in range(no_of_users_to_create):
        user_details = admin_ops.create_admin_user(
            names.get_first_name().lower() + random.choice(string.ascii_lowercase) + "." +
            str(random.randint(1, 1000)) + ".",
            names.get_full_name().lower(), cluster_name)

        all_users_details.append(user_details)

    return all_users_details


class BaseOp(object):
    def __init__(self, user_details):
        log.debug('class: %s' % self.__class__.__name__)

        self.user_id = user_details['user_id']
        self.access_key = user_details['access_key']
        self.secret_key = user_details['secret_key']
        # self.port = user_details['port']

        auth = Authenticate(self.access_key, self.secret_key, self.user_id)

        self.connection = auth.do_auth()

        assert self.connection['status'], self.connection['msgs']
        connection = self.connection['conn']

        self.canonical_id = connection.get_canonical_user_id()

        self.json_file_upload = self.connection['upload_json_file']
        self.json_file_download = self.connection['download_json_file']

        self.bucket_ops = Bucket(connection)


class BucketOps(BaseOp):

    def __init__(self, config, user_details):
        # user_details['port'] = config.port

        super(BucketOps, self).__init__(user_details)

        self.buckets_created = []

        self.enable_versioning = False
        self.version_count = None
        self.version_ids = None
        self.move_version = False
        self.grants = None
        self.acls = None

        self.bucket_names = []
        self.bucket_create_nos = config.bucket_count

        self.bucket_ops.test_op_code = 'create'

    def create_bucket(self):

            log.info('no of buckets to create: %s' % self.bucket_create_nos)

            log.info('buckets_creating......')

            for bucket_no in range(self.bucket_create_nos):

                log.debug('iter: %s' % bucket_no)

                bucket_name = self.user_id + "." + str('bucky') + "." + str(bucket_no)

                self.bucket_names.append(bucket_name)

                log.info('bucket_name: %s' % bucket_name)

                bucket_created = self.bucket_ops.create(bucket_name, self.json_file_upload)

                if not bucket_created['status']:
                    raise AssertionError, bucket_created['msgs']

                print 'created bucket'
                print bucket_created

                self.buckets_created.append(bucket_created['bucket'])

                log.info('bucket created')

            return self.buckets_created

    def get_bucket(self):

        log.info('getting buckets from already created bucket names')

        tmp = []

        for bucket_name in self.bucket_names:

            print '-----------%s' % bucket_name

            bucket = self.bucket_ops.get(bucket_name)

            if bucket['status']:
                tmp.append(bucket['bucket'])

            elif not bucket['status']:
                raise AssertionError, bucket['msgs']

        self.buckets_created = tmp

        return self.buckets_created

    def delete_bucket(self):

        for bucket_name in self.bucket_names:

            bucket_deleted = self.bucket_ops.delete(bucket_name)

            if not bucket_deleted['status']:
                raise AssertionError, bucket_deleted['msgs']

            log.info('bucket deleted')

    def set_bucket_properties(self):

        if not self.buckets_created:
            assert "No buckets created"

        for bucket in self.buckets_created:

            if self.grants is not None:
                self.bucket_ops.set_user_grant(bucket, self.grants)

            if self.version_count is not None:
                self.bucket_ops.enable_disable_versioning(bucket, self.enable_versioning)

            if self.acls is not None:
                self.bucket_ops.set_acls(bucket, self.acls)

        return self.buckets_created


class ObjectOps(BucketOps):
    def __init__(self, config, user_details):

        super(ObjectOps, self).__init__(config, user_details)

        self.keys_put = []
        self.version_count = None
        self.version_ids = None
        self.move_version = False

        self.objects_count = config.objects_count
        self.objects_size_range = config.objects_size_range

        self.set_cancel_multipart = False
        self.break_upload_at_part_no = 0

    def upload(self, buckets_created, object_base_name='key', test_op_code='create'):

        object_create_nos = self.objects_count

        log.info('no of obejcts in a bucket to create %s' % object_create_nos)

        for bucket_created in buckets_created:

            object_size = self.objects_size_range

            min_object_size = object_size['min']
            max_object_size = object_size['max']

            log.info('objects min size: %s' % min_object_size)
            log.info('objects max size: %s' % max_object_size)

            for key in range(object_create_nos):

                key_name = object_base_name + "." + str(key)

                log.info('key name to create %s' % key_name)

                size = utils.get_file_size(min_object_size, max_object_size)

                log.info('size of the file to create %s' % size)

                random_file = utils.create_file(key_name, size)

                key_op = KeyOp(bucket_created)

                key_created = key_op.create(key_name)

                if key_created is None:
                    raise AssertionError, "key name creation failed"

                log.info('key created')

                put_file = PutContentsFromFile(key_created, self.json_file_upload)

                if self.enable_versioning:

                    self.keys_put.append(key_name)

                    log.info('creating versions of the key')

                    keys_with_version = [key_name + ".version." + str(i) for i in range(self.version_count)]

                    log.info('version_key_names %s:\n' % keys_with_version)

                    files_with_version = map(lambda x: utils.create_file(x, size), keys_with_version)

                    for each_version in files_with_version:

                        put = put_file.put(each_version)

                        if not put['status']:
                            raise AssertionError, put['msgs']

                    current_key_version_id = key_created.version_id
                    log.info('current_key_version_id: %s' % current_key_version_id)

                    versions = list(bucket_created.list_versions(key_created.name))
                    log.info('listing all version')
                    version_details = [{'key': k.name, 'version_id': k.version_id} for k in versions]
                    self.version_ids = [i['version_id'] for i in version_details]
                    map(log.info, version_details)

                    if self.move_version:
                        log.info('reverting to a random version.')

                        bucket_created.copy_key(key_created.name, bucket_created.name, key_created.name,
                                                src_version_id=random.choice(self.version_ids))

                        versions = list(bucket_created.list_versions(key_created.name))

                        log.info('listing all version')
                        version_details = [{'key': k.name, 'version_id': k.version_id} for k in versions]
                        self.version_ids = [i['version_id'] for i in version_details]
                        map(log.info, version_details)

                    current_key_version_id = key_created.version_id
                    log.info('current_key_version_id after moving version: %s' % current_key_version_id)

                else:

                    print 'code here '

                    put = put_file.put(random_file, test_op_code)

                    if not put['status']:
                        return put['status']
                    else:
                        self.keys_put.append(key_name)

    def multipart_upload(self, buckets_created):

        object_size = self.objects_size_range

        min_object_size = object_size['min']
        max_object_size = object_size['max']

        for bucket in buckets_created:

            for object_count in range(self.objects_count):

                key_name = bucket.name + "." + str(object_count) + ".key" + ".mpFile"

                if not os.path.exists(key_name):

                    size = utils.get_file_size(min_object_size, max_object_size)

                    log.info('size of the file to create %s' % size)

                    log.info('file does not exists, so creating the file')

                    filename = utils.create_file(key_name, size)

                else:

                    log.info('file exists')
                    filename = os.path.abspath(key_name)
                    md5 = utils.get_md5(filename)

                log.info('got filename %s' % filename)

                log.debug('got file dirname %s' % os.path.dirname(filename))

                json_file = os.path.join(os.path.dirname(filename), os.path.basename(filename) + ".json")

                log.info('json_file_name %s' % json_file)

                multipart = MultipartPut(bucket, filename)

                multipart.break_at_part_no = self.break_upload_at_part_no
                multipart.cancel_multpart = self.set_cancel_multipart

                multipart.iniate_multipart(json_file)

                put = multipart.put()

                print put['status']

                if not put['status']:
                    raise AssertionError, put['msgs']

    def delete_key_version(self):

        for bucket_name in self.bucket_names:

            bucket = self.bucket_ops.get(bucket_name)

            for each_key in self.keys_put:
                key_op = KeyOp(bucket['bucket'])

                key_name = key_op.get(each_key)

                del_key_version = lambda x: key_op.delete(key_name, version_id=x)

                map(del_key_version, self.version_ids)

    def delete_keys(self, delete_bucket=True):

        log.info('deleted buckets with keys')

        for bucket_name in self.bucket_names:

            log.info('ops on bucket name: %s' % bucket_name)

            bucket = self.bucket_ops.get(bucket_name)

            all_keys_in_bucket = bucket['bucket'].list()

            if all_keys_in_bucket:

                log.info('got all keys in bucket: %s' % all_keys_in_bucket)

                key_op = KeyOp(bucket['bucket'])

                log.info('delete of all keys')

                keys_deleted = key_op.multidelete_keys(all_keys_in_bucket)

                if keys_deleted is None:
                    log.error('key not deleted')
                    raise AssertionError

                log.info('all keys deleted')

    def download_keys(self):

        download_dir = os.path.join(os.getcwd(), "Download")

        if not os.path.exists(download_dir):
            os.makedirs(download_dir)

        for bucket_name in self.bucket_names:
            log.info('ops on bucket name: %s' % bucket_name)

            bucket_dir = os.path.join(download_dir, bucket_name)

            if not os.path.exists(bucket_dir):
                os.makedirs(bucket_dir)

            bucket = self.bucket_ops.get(bucket_name, self.json_file_download)

            all_keys_in_bucket = bucket['bucket'].list()

            for each_key in all_keys_in_bucket:

                get_contents = PutContentsFromFile(each_key, self.json_file_download)

                filename = os.path.join(bucket_dir, each_key.key)

                download = get_contents.get(filename)

                if not download['status']:
                    log.error(download['msgs'])
                    raise AssertionError
                else:
                    log.info('download complete')
                    log.info('after download, deleting key: %s' % filename)
                    os.unlink(filename)


class Config(object):
    def __init__(self):
        pass
