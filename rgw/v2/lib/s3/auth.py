import boto3
import socket
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
import v2.utils.utils as utils
from botocore.client import Config


class Auth(object):

    def __init__(self, user_info, **extra_kwargs):
        self.access_key = user_info['access_key']
        self.secret_key = user_info['secret_key']
        self.hostname = socket.gethostname()
        self.ip = socket.gethostbyname(self.hostname)
        self.ssl = extra_kwargs.get('ssl', False)
        self.port = utils.get_radosgw_port_no()
        self.endpoint_url = 'https://{}:{}'.format(self.ip, self.port) if self.ssl \
                                else 'http://{}:{}'.format(self.ip, self.port)
        self.is_secure = False
        self.user_id = user_info['user_id']

        log.info('access_key: %s' % self.access_key)
        log.info('secret_key: %s' % self.secret_key)
        log.info('hostname: %s' % self.hostname)
        log.info('port: %s' % self.port)
        log.info('user_id: %s' % self.user_id)
        log.info('endpoint url: %s' % self.endpoint_url)
        log.info('ssl: %s' % self.ssl)

    def do_auth(self, **config):
        log.info('performing authentication')
        additional_config = Config(signature_version=config.get('signature_version', None))
        
        rgw = boto3.resource('s3',
                             aws_access_key_id=self.access_key,
                             aws_secret_access_key=self.secret_key,
                             endpoint_url=self.endpoint_url,
                             use_ssl=self.ssl,
                             verify=False,
                             config=additional_config,
                             )

        log.info('connected')

        return rgw

    def do_auth_using_client(self, **config):
        log.info('performing authentication using client module')
        additional_config = Config(signature_version=config.get('signature_version', None))
        rgw = boto3.client('s3',
                           aws_access_key_id=self.access_key,
                           aws_secret_access_key=self.secret_key,
                           endpoint_url=self.endpoint_url,
                           config=additional_config,
                           )
        return rgw

