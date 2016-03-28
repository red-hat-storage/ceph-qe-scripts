from auth import Authenticate
from bucket import Bucket
from objects import KeyOp, PutContentsFromFile, PutContentsFromString
import utils.log as log
import utils.utils as utils
from random import randint


class RGW(object):

    def __init__(self, access_key, secret_key):

        log.debug('class: %s' % self.__class__.__name__)

        auth = Authenticate(access_key, secret_key)
        connection = auth.do_auth()

        assert connection['status']
        connection = connection['conn']

        self.bucket = Bucket(connection)

    def create_bucket_with_keys(self, bucket_create_nos,
                                object_create_nos,
                                **object_size):

        min_object_size = object_size['min']
        max_object_size = object_size['max']

        log.info('no of buckets to create: %s' % bucket_create_nos)
        log.info('no of obejcts in a bucket to create %s' % object_create_nos)

        for bucket in range(bucket_create_nos):

            log.debug('iter: %s' % bucket)

            bucket_name = str('buckey') + "." + str(bucket)

            log.info('bucket_name: %s' % bucket_name)

            bucket_created = self.bucket.create(bucket_name)

            if not bucket_created['status']:
                raise AssertionError

            log.info('bucket created')

            if object_create_nos > 0:

                log.info('objects min size: %s' % min_object_size)
                log.info('objects max size: %s' % max_object_size)

                for key in range(object_create_nos):

                    key_name = str("key") + "." + str(key)

                    log.info('key name to create %s' % key_name)

                    key_op = KeyOp(bucket_created['bucket'])

                    key_created = key_op.create(key_name)

                    if key_created is None:
                        raise AssertionError

                    log.info('key created')

                    put_file = PutContentsFromFile(key_created)

                    size = randint(min_object_size, max_object_size)

                    log.info('size of the file to create %s' % size)

                    random_file, md5 = utils.create_file(key_name, size)

                    log.info('\nrandom filename created :%s\n md5 of the file: %s' % (random_file, md5))

                    put = put_file.put(random_file)

                    if not put['status']:
                        raise AssertionError

                    log.info('put of the file completed')

                    key_on_rgw_node = key_op.get(key_name)

                    log.info('key on RGW %s\n' % key_on_rgw_node)
