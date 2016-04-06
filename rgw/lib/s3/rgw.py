from auth import Authenticate
from bucket import Bucket
from objects import KeyOp, PutContentsFromFile, PutContentsFromString, MultipartPut
import utils.log as log
import utils.utils as utils
from random import randint


class BaseOp(object):

    def __init__(self, access_key, secret_key):

        log.debug('class: %s' % self.__class__.__name__)

        auth = Authenticate(access_key, secret_key)
        connection = auth.do_auth()

        assert connection['status']
        connection = connection['conn']

        self.bucket = Bucket(connection)


class RGW(BaseOp):

    def __init__(self, access_key, secret_key):

        super(RGW, self).__init__(access_key, secret_key)

    def create_bucket_with_keys(self, bucket_create_nos, object_create_nos, multipart_upload = False, **object_size):

        min_object_size = object_size['min']
        max_object_size = object_size['max']

        self.buckets_created = []

        log.info('no of buckets to create: %s' % bucket_create_nos)
        log.info('no of obejcts in a bucket to create %s' % object_create_nos)

        for bucket_no in range(bucket_create_nos):

            log.debug('iter: %s' % bucket_no)

            bucket_name = str('buckey') + "." + str(bucket_no)

            log.info('bucket_name: %s' % bucket_name)

            bucket_created = self.bucket.create(bucket_name)

            if not bucket_created['status']:
                raise AssertionError

            log.info('bucket created')

            self.buckets_created.append(bucket_name)

            if object_create_nos > 0:

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

                    put_file = PutContentsFromFile(key_created)

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

    def multipart_upload(self, size, bucket_name):

        bucket_created = self.bucket.create(bucket_name)

        if not bucket_created['status']:
            raise AssertionError

        log.info('bucket created')

        log.info('multpart upload enabled')

        multipart = MultipartPut(bucket_created['bucket'])

        log.info('size of the file to create %s' % size)

        key_name = bucket_name + "." + "mpFile"

        file_created, md5 = utils.create_file(key_name, size)

        put = multipart.put(filename=file_created, chunk_size=size / 10)

        if not put['status']:
            raise AssertionError
