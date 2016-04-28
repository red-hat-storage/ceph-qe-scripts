import boto.exception as exception
import utils.log as log
from json_ops import JBucket


class Bucket(object):
    def __init__(self, connection):
        self.connection = connection

        log.debug('class: %s' % self.__class__.__name__)

    def create(self, bucket_name, json_file):

        log.debug('function: %s' % self.create.__name__)

        log.info('in create bucket')

        """
        :param bucket_name: string
        :rtype: dict
        :return: create_bucket_stack:
                        args:
                            1.status: True, bucket created or False if bucket creation failed
                            2.bucket: bucket objects
                            3.msgs: error messages
        """

        try:

            bucket = self.connection.create_bucket(bucket_name)

            create_bucket_stack = {'status': True,
                                   'bucket': bucket}

            add_bucket_to_json = JBucket(json_file)

            add_bucket_to_json.add(bucket_name)

        except (exception.AWSConnectionError, exception.BotoClientError, exception.S3ResponseError,
                exception.S3CreateError, IOError), e:
            log.error(e)
            create_bucket_stack = {'status': False,
                                   'msgs': e}

        return create_bucket_stack

    def get(self, bucket_name, json_file=None):

        log.debug('function: %s' % self.get.__name__)

        log.info('in get bucket')

        """

        :param bucket_name:string
        :rtype: dict
        :return: get_bucket_stack:
                    args:
                         status: True, if got bucket or  False,  no get bucket
                         attribs: bucket object
                         msgs: error messges
        """

        try:

            bucket = self.connection.get_bucket(bucket_name)

            if json_file is not None:
                add_bucket_to_json = JBucket(json_file)
                add_bucket_to_json.add(bucket_name)

            get_bucket_stack = {'status': True,
                                'bucket': bucket}

        except (exception.S3ResponseError, exception.AWSConnectionError), e:

            log.error(e)
            get_bucket_stack = {'status': False,
                                'msgs': e}

        return get_bucket_stack

    def delete(self, bucket_name):

        log.debug('function: %s' % self.delete.__name__)

        log.info('in delete bucket')

        """

        :param bucket_name: string
        :rtype: dict
        :return: delete_bucket_stack:
                    args:
                        status: True, if bucket is deleted or False if not deleted
                        msgs: error messages
        """

        try:

            self.connection.delete_bucket(bucket_name)

            delete_bucket_stack = {'status': True}

        except exception.S3ResponseError, e:
            log.error(e)
            delete_bucket_stack = {'status': False,
                                   'msgs': e}

        return delete_bucket_stack

    def enable_disable_versioning(self, enabled, bucket):

        try:

            bucket.enable_versioning(enabled)

            return True

        except (exception.S3ResponseError, exception.BotoClientError) as e:
            log.error(e)

            return False


def check_if_bucket_empty(bucket):

        log.debug('function: %s' % check_if_bucket_empty.__name__)

        log.info('checking if bucket is empty')

        """

        :param bucket: bucket object
        :rtype: dict
        :return: check_for_empty_stack:
                    args:
                        1.contents: empty list ( [] ) or list of buckets
                        2.msgs: error messages
        """

        try:
            bucket_contents = bucket.list()

            check_for_empty_stack = {'contents': bucket_contents}

        except (exception.S3ResponseError, exception.AWSConnectionError), e:
            log.error(e)
            check_for_empty_stack = {'contents': [],
                                     'msgs': e}

        return check_for_empty_stack


def list_all_buckets(connection):

    log.debug('function: %s' % list_all_buckets.__name__)

    log.info('listing all buckets')

    """

    :param connection: AWS authentication connection
    :rtype: dict
    :return: list_buckets_stack:
                args:
                    1.attribs: list of all buckets or None
                    2. msgs: error messages
    """

    try:

        all_buckets = connection.get_all_buckets()
        list_buckets_stack = {'all_buckets': all_buckets}

    except (exception.S3ResponseError, exception.AWSConnectionError), e:
        log.error(e)

        list_buckets_stack = {'all_buckets': None,
                              'msgs': e
                              }

    return list_buckets_stack
