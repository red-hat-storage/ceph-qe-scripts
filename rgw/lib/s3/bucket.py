from boto.s3.connection import S3Connection
import boto.s3.connection
import boto.exception as exception
import utils.log as log
from utils.utils import Attribs


class Bucket(object):
    def __init__(self, connection):
        self.connection = connection

    def create(self, bucket_name):

        """
        :param bucket_name: string
        :return: Create_bucket_stack (dictionary):
                        args:
                            1.status: True, bucket created or False if bucket creation failed
                            2.attribs: bucket objects
                            3.msgs: error messages
        """

        attribs = Attribs()

        try:
            bucket = self.connection.create_bucket(bucket_name)
            attribs.bucket = bucket

            create_bucket_stack = {'status': True,
                                   'attribs': attribs}

        except (exception.AWSConnectionError, exception.S3CreateError), e:
            log.error(e)
            create_bucket_stack = {'status': False,
                                   'msgs': e}

        return create_bucket_stack

    def get(self, bucket_name):

        """

        :param bucket_name:string
        :return: get_bucket_stack:(dictionary)
                    args:
                         status: True, if got bucket or  False,  no get bucket
                         attribs: bucket object
                         msgs: error messges
        """

        attribs = Attribs()

        try:
            bucket = self.connection.get_bucket(bucket_name)
            attribs.bucket = bucket

            get_bucket_stack = {'status': True,
                                'attribs': attribs}

        except (exception.S3ResponseError, exception.AWSConnectionError), e:

            log.error(e)
            get_bucket_stack = {'status': False,
                                'msgs': e}

        return get_bucket_stack


class DeleteBucket(object):

    def __init__(self, connection):
        self.connection = connection

    def check_if_bucket_empty(self, bucket):

        """

        :param bucket: bucket object
        :return: check_for_empty_stack (dictionary):
                    args:
                        1.contents: empty list ( [] ) or list of buckets
                        2.msgs: error messages
        """

        try:
            bucket_contents = bucket.list()

            check_for_empty_stack = {'contents':  bucket_contents}

        except (exception.S3ResponseError, exception.AWSConnectionError),e :
            log.error(e)
            check_for_empty_stack = {'contents': [],
                                     'msgs': e}

        return check_for_empty_stack

    def delete(self, bucket_name):

        """

        :param bucket_name: string
        :return: delete_bucket_stack (dictionary):
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


def list_all_buckets(connection):

        """

        :param connection: AWS authentication connection
        :return: list_buckets_stack (dictionay):
                    args:
                        1.attribs: list of all buckets or None
                        2. msgs: error messages
        """

        attribs = Attribs()

        try:

            all_buckets = connection.get_all_buckets()
            attribs.all_buckets = all_buckets

            list_buckets_stack = {'attribs': attribs}

        except (exception.S3ResponseError, exception.AWSConnectionError),e :
            log.error(e)

            list_buckets_stack = {'attribs': None,
                                  'msgs': e
                                  }

        return list_buckets_stack
