import boto.exception as exception
import utils.log as log
from boto.s3.key import Key
import boto
import math, os
#from filechunkio import FileChunkIO
from utils.utils import  JsonOps
import utils.utils as utils
import glob
from json_ops import JKeys


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

    def __init__(self, key, json_file):

        log.debug('class: %s' % self.__class__.__name__)

        self.json_file = json_file
        self.jkey = JKeys(self.json_file)
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

            key_details = {'key_name': self.key.key,
                           'size': os.stat(filename).st_size,
                           'md5': utils.get_md5(filename)}

            self.jkey.add(self.key.bucket.name, **key_details)

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

    def __init__(self, bucket, filename):

        log.debug('class: %s' % self.__class__.__name__)

        self.bucket = bucket
        self.split_files_list = []

        self.filename = filename

        self.json_ops = None

        self.cancel_multpart = False

        self.mp = None

        self.break_at_part_no = 0

    def iniate_multipart(self, json_file):

        try:

            self.json_ops = JsonOps(json_file)

            log.info('initaiting multipart upload')

            file_path = os.path.dirname(self.filename)

            key_name = os.path.basename(self.filename)

            if not os.path.exists(json_file):

                log.info('fresh multipart upload')

                log.info('got filename: %s\ngot filepath: %s' % (self.filename, file_path))

                utils.split_file(self.filename)

                self.split_files_list = sorted(glob.glob(file_path + '/' + 'x*'))

                # log.info('split files list: %s' % self.split_files_list)

                self.json_ops.total_parts_count = len(self.split_files_list)

                log.info('total file parts %s' % self.json_ops.total_parts_count)

                remaining_file_parts = []

                for each_file in self.split_files_list:
                    remaining_file_parts.append((each_file,
                                                 (self.split_files_list.index(each_file) + 1)
                                                 )
                                                )

                # log.info('remainig file parts structure :%s' % remaining_file_parts)

                self.json_ops.remaining_file_parts = remaining_file_parts

                self.mp = self.bucket.initiate_multipart_upload(key_name)

                self.json_ops.mp_id = self.mp.id
                self.json_ops.key_name = self.mp.key_name

                log.info('multipart_id :%s' % self.mp.id)
                log.info('key_name %s' % self.mp.key_name)

                self.json_ops.create_update_json_file()

            else:
                log.info('not fresh mulitpart')

                self.json_ops.refresh_json_data()

                self.mp = boto.s3.multipart.MultiPartUpload(self.bucket)
                self.mp.key_name = self.json_ops.key_name
                self.mp.id = self.json_ops.mp_id

                log.info('multipart_id :%s' % self.mp.id)
                log.info('key_name %s' % self.mp.key_name)

        except exception.BotoClientError, e:
            log.error(e)
            return False

    def put(self):

            try:

                log.info('loading the json data')
                self.json_ops.refresh_json_data()

                self.json_ops.refresh_json_data()

                log.debug('remaining parts assigning')

                log.debug('making a copy of remaining parts')

                remaining_file_parts_copy = list(self.json_ops.remaining_file_parts)

                log.debug('starting the loop')

                for each_file_part in self.json_ops.remaining_file_parts:

                    log.info('file part to upload: %s\nfile part number: %s' % (each_file_part[0], int(each_file_part[1])))

                    log.info('entering iteration')

                    if self.break_at_part_no != 0 and self.break_at_part_no == int(each_file_part[1]):

                        log.info('upload stopped at partno : %s' % each_file_part[1])
                        break

                    fp = open(each_file_part[0], 'rb')

                    self.mp.upload_part_from_file(fp, int(each_file_part[1]))

                    fp.close()

                    log.info('part of file uploaded')

                    remaining_file_parts_copy.remove(each_file_part)
                    self.json_ops.remaining_file_parts = remaining_file_parts_copy

                    log.info('updating json file')
                    self.json_ops.create_update_json_file()

                log.info('printing all the uploaded parts')

                for part in self.mp:
                    log.info('%s: %s' % (part.part_number, part.size))

                if self.break_at_part_no == 0:

                    # if self.cancel_multpart:
                    #     log.info('cancelling upload')
                    #
                    #     self.mp.cancel_upload()
                    #
                    #     if not self.mp:
                    #         upload_status = {'status': False}
                    #

                    log.info('completing upload')
                    self.mp.complete_upload()

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

