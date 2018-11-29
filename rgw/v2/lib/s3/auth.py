import boto3
import socket
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
import v2.utils.utils as utils
from botocore.client import Config


class Auth(object):

    def __init__(self, user_info):
        self.access_key = user_info['access_key']
        self.secret_key = user_info['secret_key']
        self.hostname = socket.gethostname()
        self.port = 8080
        self.is_secure = False
        self.user_id = user_info['user_id']

        log.info('access_key: %s' % self.access_key)
        log.info('secret_key: %s' % self.secret_key)
        log.info('hostname: %s' % self.hostname)
        log.info('port: %s' % self.port)
        log.info('user_id: %s' % self.user_id)

    def do_auth(self, **config):
        log.info('performing authentication')
        additional_config = Config(signature_version=config.get('signature_version', None))
        rgw = boto3.resource('s3',
                             aws_access_key_id=self.access_key,
                             aws_secret_access_key=self.secret_key,
                             endpoint_url='http://%s:%s' % (self.hostname, self.port),
                             use_ssl=False,
                             config=additional_config,
                             )

        return rgw

    def do_auth_using_client(self, **config):
        log.info('performing authentication using client module')
        additional_config = Config(signature_version=config.get('signature_version', None))
        rgw = boto3.client('s3',
                           aws_access_key_id=self.access_key,
                           aws_secret_access_key=self.secret_key,
                           endpoint_url='http://%s:%s' % (self.hostname, self.port),
                           config=additional_config,
                           )
        return rgw
