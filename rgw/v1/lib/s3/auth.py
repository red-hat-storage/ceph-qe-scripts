import json
import os
import socket

import boto.exception as exception
import boto.s3.connection
import v1.utils.log as log
import v2.utils.utils as utils_v2


class Authenticate(object):
    def __init__(self, access_key, secret_key, user_id, port=None):

        log.debug("class: %s" % self.__class__.__name__)

        self.access_key = access_key
        self.secret_key = secret_key
        self.hostname = socket.gethostname()
        self.port = int(utils_v2.get_radosgw_port_no())
        self.is_secure = False
        self.user_id = user_id
        self.json_file_upload = self.user_id + "." + "upload" + "." + "json"
        self.json_file_download = self.user_id + "." + "download" + "." + "json"

    def dump_to_json_upload(self):

        if not os.path.exists(self.json_file_upload):

            log.info("json file does not exists, so creating one ")

            data = {
                "access_key": self.access_key,
                "secret_key": self.secret_key,
                "user_id": self.user_id,
                "buckets": {},
            }

            with open(self.json_file_upload, "w") as fp:
                json.dump(data, fp, indent=4)

            fp.close()

    def dump_to_json_download(self):

        if not os.path.exists(self.json_file_download):
            log.info("json file does not exists,so creating one ")

            data = {
                "access_key": self.access_key,
                "secret_key": self.secret_key,
                "user_id": self.user_id,
                "buckets": {},
            }

            with open(self.json_file_download, "w") as fp:
                json.dump(data, fp, indent=4)

            fp.close()

    def do_auth(self):

        log.debug("function: %s" % self.do_auth.__name__)

        try:
            log.info("got the credentials")
            # conn = S3Connection(self.ak, self.sk)

            self.dump_to_json_upload()
            self.dump_to_json_download()

            conn = boto.connect_s3(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                host=self.hostname,
                port=self.port,
                is_secure=self.is_secure,
                calling_format=boto.s3.connection.OrdinaryCallingFormat(),
            )
            log.info("acess_key %s\nsecret_key %s" % (self.access_key, self.secret_key))

            auth_stack = {
                "status": True,
                "conn": conn,
                "upload_json_file": self.json_file_upload,
                "download_json_file": self.json_file_download,
            }

        except (
            boto.s3.connection.HostRequiredError,
            exception.AWSConnectionError,
            Exception,
        ) as e:

            log.error("connection failed")
            log.error(e)

            auth_stack = {"status": False, "msgs": e}

        return auth_stack
