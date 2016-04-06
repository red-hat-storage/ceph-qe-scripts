import boto.exception as exception
import utils.log as log
from boto.s3.key import Key
import math, os
from filechunkio import FileChunkIO
from utils.utils import  JsonOps
import utils.utils as utils
import glob


class KeyOp(object):
    def __init__(self, bucket):

        log.debug('class: %s' % self.__class__.__name__)

        self.bucket = bucket

    def create(self, key_name):

        log.debug('function: %s' % self.create.__name__)

        log.info('creating key %s' % key_name)

        """

        :param key_name: string
        :return: key object or None
        """

        log.info('create key %s' % key_name)

        try:
            k = Key(self.bucket)
            k.key = key_name
            return k
        except exception.BotoClientError, e:
            log.error(e)
            return None

    def get(self, key_name):

        log.debug('function: %s' % self.get.__name__)

        log.info('in get key: %s' % key_name)

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

        log.debug('function: %s' % self.delete.__name__)

        log.debug('in delete key %s:' % key_name)

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

        log.debug('function: %s' % self.multidelete_keys.__name__)

        log.info('in mutiple keys delete %s' % keys_list)

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


class PutContentsFromString(object):
    def __init__(self, key):

        log.debug('class: %s' % self.__class__.__name__)

        self.key = key

    def set_metadata(self, **metadata):

        log.debug('function: %s' % self.set_metadata.__name__)

        log.info('setting metadata %s' % metadata)

        metadata_name = metadata.keys()[0]
        metadata_value = metadata.values()[0]

        try:
            self.key.set_metadata(metadata_name, metadata_value)
            return True

        except exception.BotoClientError, e:
            log.error(e)
            return False

    def put(self, string_val):

        log.debug('function: %s' % self.put.__name__)

        log.info('upload of string %s' % string_val)

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

        log.debug('function: %s' % self.check_contents.__name__)

        log.info('checking contents or getting the string val')

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


class PutContentsFromFile(object):

    def __init__(self, key):

        log.debug('class: %s' % self.__class__.__name__)

        self.key = key

    def set_metadata(self, **metadata):

        log.debug('function: %s' % self.set_metadata.__name__)

        log.info('setting metadata %s' % metadata)

        metadata_name = metadata.keys()[0]
        metadata_value = metadata.values()[0]

        try:
            self.key.set_metadata(metadata_name, metadata_value)
            return True

        except exception.BotoClientError, e:
            log.error(e)
            return False

    def put(self, filename):

        log.debug('function: %s' % self.put.__name__)

        log.info('upload of file: %s' % filename)

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

    def get(self, filename):

        log.debug('function: %s' % self.get.__name__)

        log.info('getting the contents of file %s:' % self.key)

        log.info('download or get the file to filename: %s' % filename)

        """

        :param: filename: mention the filename which will be used to get the contents from s3 to this file.
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


class MultipartPut(object):

    def __init__(self, bucket, json_file):

        log.debug('class: %s' % self.__class__.__name__)

        self.bucket = bucket
        self.split_files_list = []
        self.json_ops = JsonOps(json_file)

        if not os.path.exists(json_file):

            log.info('no json file found, so fresh multipart upload')
            self.json_ops.total_parts_count = 0
            self.json_ops.remaining_file_parts = []

            self.json_ops.create_update_json_file()

    def put(self, filename, chunk_size=5):

        try:

            file_size = os.stat(filename).st_size
            file_path = os.path.dirname(filename)

            mp = self.bucket.initiate_multipart_upload(os.path.basename(filename))

            log.info('loading the json data')
            self.json_ops.refresh_json_data()

            if self.json_ops.total_parts_count == 0:

                log.info('got filename: %s\ngot filepath: %s' % (filename, file_path)
                         )

                log.info('fresh multipart upload')

                utils.split_file(filename)

                self.split_files_list = sorted(glob.glob(file_path + '/' + 'x*'))

                log.info('split files list: %s' % self.split_files_list)

                self.json_ops.total_parts_count = len(self.split_files_list)

                log.info('total file parts %s' % self.json_ops.total_parts_count)

                remaining_file_parts = []

                for each_file in self.split_files_list:
                    remaining_file_parts.append((each_file,
                                                 (self.split_files_list.index(each_file) + 1)
                                                 )
                                                )

                log.info('remainig file parts structure :%s' % remaining_file_parts)

                self.json_ops.remaining_file_parts = remaining_file_parts
                self.json_ops.create_update_json_file()

            self.json_ops.refresh_json_data()

            remaining_file_parts = self.json_ops.remaining_file_parts

            remaining_file_parts_copy = remaining_file_parts

            for each_file_part in remaining_file_parts:

                log.info('file part to upload: %s\nfile part number: %s' % (each_file_part[0], each_file_part[1]))

                mp.upload_part_from_file(os.path.basename(each_file_part[0]), each_file_part[1])

                remaining_file_parts_copy.remove(each_file_part)
                self.json_ops.remaining_file_parts = remaining_file_parts_copy

                log.info('updating json file')
                self.json_ops.create_update_json_file()

            mp.complete_upload()
            log.info('multpart complete')

            upload_status = {'status': True}

            """

            # the following code is better than splitting the file,
            # but commenting this for now and going ahead with splting the files


            chunk_count = int(math.ceil(filename / float(chunk_size)))

            # Send the file parts, using FileChunkIO to create a file-like object
            # that points to a certain byte range within the original file. We
            # set bytes to never exceed the original file size

            for i in range(chunk_count):

                offset = chunk_size * i
                bytes = min(chunk_size, file_size - offset)
                with FileChunkIO(filename, 'r', offset=offset, bytes=bytes) as fp:
                    mp.upload_part_from_file(fp, part_num=i + 1)

            # Finish the upload

            """

        except exception.BotoClientError, e:

            log.error(e)

            upload_status = {'status': False,
                             'msg': e}

        return upload_status

