from boto.s3.connection import S3Connection
import boto.s3.connection
import boto.exception as exception
import utils.log as log


class Authenticate(object):

    def __init__(self, access_key, secret_key):

        log.debug('class: %s' % self.__class__.__name__)

        self.ak = access_key
        self.sk = secret_key

    def do_auth(self):

        log.debug('function: %s' % self.do_auth.__name__)

        try:
            log.info('got the credentials')
            conn = S3Connection(self.ak, self.sk)
            log.info('acess_key %s\n secret_key %s' % (self.ak, self.sk))

            auth_stack = {'status': True,
                          'conn': conn}

        except (boto.s3.connection.HostRequiredError, exception.AWSConnectionError), e:

            log.error('connection failed')
            log.error(e)

            auth_stack = {'status': False,
                          'msgs': e}

        return auth_stack

