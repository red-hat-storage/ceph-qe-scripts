from boto.s3.connection import S3Connection
import boto.s3.connection
import boto.exception as exception
import utils.log as log
import socket
import os
import json


class Authenticate(object):

    def __init__(self, access_key, secret_key, user_id):

        log.debug('class: %s' % self.__class__.__name__)

        self.access_key = access_key
        self.secret_key = secret_key
        self.hostname = socket.gethostname()
        self.port = 7280
        self.is_secure = False
        self.user_id = user_id
        self.json_file = self.user_id + ".json"

    def dump_to_json(self):

        if not os.path.exists(self.json_file):

            log.info('json file does not exists')

            data = {'access_key': self.access_key,
                    'secret_key': self.secret_key,
                    'user_id': self.user_id,
                    'buckets': {}
                    }

            with open(self.json_file, "w") as fp:
                json.dump(data, fp, indent=4)

            fp.close()

    def do_auth(self):

        log.debug('function: %s' % self.do_auth.__name__)

        try:
            log.info('got the credentials')
            # conn = S3Connection(self.ak, self.sk)

            self.dump_to_json()

            conn = boto.connect_s3(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                host=self.hostname,
                port=self.port,
                is_secure=self.is_secure,
                calling_format=boto.s3.connection.OrdinaryCallingFormat()
            )
            log.info('acess_key %s\nsecret_key %s' % (self.access_key, self.secret_key))

            auth_stack = {'status': True,
                          'conn': conn,
                          'josn_file': self.json_file}

        except (boto.s3.connection.HostRequiredError, exception.AWSConnectionError, Exception), e:

            log.error('connection failed')
            log.error(e)

            auth_stack = {'status': False,
                          'msgs': e}

        return auth_stack

