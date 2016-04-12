from boto.s3.connection import S3Connection
import boto.s3.connection
import boto.exception as exception
import utils.log as log
import socket


class Authenticate(object):

    def __init__(self, access_key, secret_key):

        log.debug('class: %s' % self.__class__.__name__)

        self.ak = access_key
        self.sk = secret_key
        self.hostname = socket.gethostname()
        self.port = 7480
        self.is_secure = False

    def do_auth(self):

        log.debug('function: %s' % self.do_auth.__name__)

        try:
            log.info('got the credentials')
            #conn = S3Connection(self.ak, self.sk)

            conn = boto.connect_s3(
                aws_access_key_id=self.ak,
                aws_secret_access_key=self.sk,
                host=self.hostname,
                port=self.port,
                is_secure=self.is_secure,
                calling_format=boto.s3.connection.OrdinaryCallingFormat()
            )
            log.info('acess_key %s\nsecret_key %s' % (self.ak, self.sk))

            auth_stack = {'status': True,
                          'conn': conn}

        except (boto.s3.connection.HostRequiredError, exception.AWSConnectionError), e:

            log.error('connection failed')
            log.error(e)

            auth_stack = {'status': False,
                          'msgs': e}

        return auth_stack

