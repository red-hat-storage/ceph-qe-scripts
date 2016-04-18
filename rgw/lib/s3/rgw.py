from auth import Authenticate
from bucket import Bucket
from objects import KeyOp, PutContentsFromFile, PutContentsFromString, MultipartPut
import utils.log as log
import utils.utils as utils
from random import randint
import os


class BaseOp(object):

    def __init__(self, access_key, secret_key, user_id):

        log.debug('class: %s' % self.__class__.__name__)

        self.user_id = user_id

        auth = Authenticate(access_key, secret_key, self.user_id)

        self.connection = auth.do_auth()

        assert self.connection['status']
        connection = self.connection['conn']

        self.json_file = self.user_id + ".json"

        self.bucket = Bucket(connection, self.json_file)


class RGW(BaseOp):

    def __init__(self, access_key, secret_key, user_id):

        super(RGW, self).__init__(access_key, secret_key, user_id)

    def create_bucket_with_keys(self, bucket_create_nos, object_create_nos, **object_size):

        self.buckets_created = []

        log.info('no of buckets to create: %s' % bucket_create_nos)
        log.info('no of obejcts in a bucket to create %s' % object_create_nos)

        for bucket_no in range(bucket_create_nos):

            log.debug('iter: %s' % bucket_no)

            bucket_name = self.user_id + "." + str('bucky') + "." + str(bucket_no)

            log.info('bucket_name: %s' % bucket_name)

            bucket_created = self.bucket.create(bucket_name)

            if not bucket_created['status']:
                raise AssertionError

            log.info('bucket created')

            self.buckets_created.append(bucket_name)

            if object_create_nos > 0:

                min_object_size = object_size['min']
                max_object_size = object_size['max']

                log.info('objects min size: %s' % min_object_size)
                log.info('objects max size: %s' % max_object_size)

                for key in range(object_create_nos):

                    key_name = str("key") + "." + str(key)

                    log.info('key name to create %s' % key_name)

                    size = randint(min_object_size, max_object_size)

                    log.info('size of the file to create %s' % size)

                    random_file, md5 = utils.create_file(key_name, size)

                    key_op = KeyOp(bucket_created['bucket'])

                    key_created = key_op.create(key_name)

                    if key_created is None:
                        raise AssertionError

                    log.info('key created')

                    put_file = PutContentsFromFile(key_created, self.json_file)

                    log.info('\nrandom filename created :%s\n md5 of the file: %s' % (random_file, md5))

                    put = put_file.put(random_file)

                    if not put['status']:
                        raise AssertionError

                    log.info('put of the file completed')

                    key_on_rgw_node = key_op.get(key_name)

                    log.info('key on RGW %s\n' % key_on_rgw_node)

    def delete_bucket_with_keys(self):

        log.info('deleted buckets with keys')

        for bucket_name in self.buckets_created:

            log.info('ops on bucket name: %s' % bucket_name)

            bucket = self.bucket.get(bucket_name)

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

                log.info('delete of bucket')

                bucket_deleted = self.bucket.delete(bucket_name)

                if not bucket_deleted['status']:
                    log.error('bucket not deleted')
                    raise AssertionError

                log.info('bucket deleted')

    def download_objects(self):

        download_dir = "Download"

        if not os.path.exists(download_dir):
            os.makedirs(download_dir)

        for bucket_name in self.buckets_created:
            log.info('ops on bucket name: %s' % bucket_name)

            bucket_dir = download_dir + "." + bucket_name

            if not os.path.exists(bucket_dir):
                os.makedirs(bucket_dir)

            bucket = self.bucket.get(bucket_name)

            all_keys_in_bucket = bucket['bucket'].list()

            for each_key in all_keys_in_bucket:

                get_contents = PutContentsFromFile(each_key, self.json_file)

                filename = bucket_dir + "." + each_key.key

                download = get_contents.get(filename)

                if not download['status']:
                    log.error(download['msgs'])
                    raise AssertionError

                else:
                    log.info('download complete')


class RGWMultpart(BaseOp):

    def __init__(self, access_key, secret_key, user_id):

        super(RGWMultpart, self).__init__(access_key, secret_key, user_id)

        self.set_cancel_multipart = False

        self.break_upload_at_part_no = 0

    def upload(self, size, bucket_name):

            bucket_name = self.user_id + "." + bucket_name

            key_name = bucket_name + "." + "mpFile"

            if not os.path.exists(key_name):

                log.info('size of the file to create %s' % size)

                log.info('file does not exists, so creating the file')

                filename, md5 = utils.create_file(key_name, size)

            else:

                log.info('file exists')
                filename = os.path.abspath(key_name)
                md5 = utils.get_md5(filename)

            log.info('got filename %s' % filename)

            log.debug('got file dirname %s' % os.path.dirname(filename))

            json_file = os.path.join(os.path.dirname(filename), os.path.basename(filename) + ".json")

            log.info('json_file_name %s' % json_file)

            bucket = self.connection['conn'].lookup(bucket_name)

            if bucket is None:

                log.info('bucket does not exists, so creating the bucket')

                bucket_created = self.bucket.create(bucket_name)
                bucket = bucket_created['bucket']

                if not bucket_created['status']:
                    raise AssertionError

            multipart = MultipartPut(bucket, filename)

            multipart.break_at_part_no = self.break_upload_at_part_no
            multipart.cancel_multpart = self.set_cancel_multipart

            multipart.iniate_multipart(json_file)
            put = multipart.put()

            print put['status']

            if not put['status']:
                raise AssertionError

    def download(self, bucket_name):

        # wip code

        download_dir = "Mp.Download"

        if not os.path.exists(download_dir):
            os.makedirs(download_dir)

        bucket_dir = download_dir + "." + bucket_name

        if not os.path.exists(bucket_dir):
            os.makedirs(bucket_dir)

        bucket = self.bucket.get(bucket_name)

        all_keys_in_bucket = bucket['bucket'].list()

        for each_key in all_keys_in_bucket:

            contents = PutContentsFromFile(each_key, self.json_file)

            filename = bucket_dir + "." + each_key.key

            download = contents.get(filename)

            if not download['status']:
                log.error(download['msgs'])
                raise AssertionError

            else:
                log.info('download complete')




