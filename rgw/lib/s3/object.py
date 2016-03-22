import boto.exception as exception
import utils.log as log
from boto.s3.key import Key


class KeyOp(object):
    def __init__(self, bucket):
        self.bucket = bucket

    def create(self, key_name):

        """

        :param key_name: string
        :return: key object or None
        """
        try:
            k = Key(self.bucket)
            k.key = key_name
            return k
        except exception.BotoClientError, e:
            log.error(e)
            return None

    def get(self, key_name):

        """

        :param key_name: string
        :return: key object or None
        """
        try:
            key = self.bucket.get_key(key_name)
            return key

        except exception.BotoClientError, e:
            log.error(e)
            return None

    def delete(self, key_name):

        """

        :param key_name: string
        :return: deleted key object.. or None

        try to check delete_marker was created for this delete.

        """

        try:

            key_deleted = self.bucket.delete_key(key_name)
            return key_deleted

        except exception.BotoClientError, e:
            log.error(e)
            return None

    def multidelete_keys(self, keys_list):

        """

        :param keys_list: list of key names
        :return: instace of multidelete or None
        """

        try:

            keys_deleted = self.bucket.delete_keys(keys_list)

            return keys_deleted

        except exception.BotoClientError, e:
            log.error(e)
            return None


class UploadContentsFromString(object):
    def __init__(self, key):
        self.key = key

    def upload(self, string_val):

        """

        :param string_val: string
        :return: upload_status (dictionary):
                    args:
                        1.status: True or False
                        2. msgs : error messages
        """

        try:

            self.key.set_contents_from_string(string_val)

            upload_status = {'status': True}

        except exception.BotoClientError, e:

            upload_status = {'status': False,
                             'msgs': e}

        return upload_status

    def check_contents(self):

        """

        can also be used for getting the contents. i.e download

        :return: string_exists_status (dictionary):
                    args:
                    1. status: True
                    2. contents: contents of string
                    3. msgs: error messages
        """

        try:

            string_contents = self.key.get_contents_as_string()

            string_exists_status = {'status': True,
                                    'contents': string_contents}

        except exception.BotoClientError, e:
            log.error(e)
            string_exists_status = {'status': False,
                                    'msgs': e}

        return string_exists_status


class UploadContentsFromFile(object):

    def __init__(self, key):
        self.key = key

    def upload(self, filename):

        """

        :param filename: filename i.e along with location
        :return: dictionary, args:
                                1. status: True for successful upload or False for failed upload,
                                2. msgs : error messages

        """

        try:
            self.key.set_contents_from_filename(filename)

            upload_status = {'status': True}

        except exception.BotoClientError, e:
            log.error(e)

            upload_status = {'status': True,
                             'msgs': e}

        return upload_status

    def download(self, filename):

        """

        :param filename: mention the filename which will be used to get the contents from s3 to this file.
                can be different from the original filename

        :return: dictionary, args:
                                1. status: True for successful download or False for failed download,
                                2. msgs : error messages
        """

        try:
            self.key.get_contents_to_filename(filename)

            download_status = {'status': True}

        except exception.BotoClientError, e:
            log.error(e)

            download_status = {'status': False,
                               'msgs': e}

        return download_status
