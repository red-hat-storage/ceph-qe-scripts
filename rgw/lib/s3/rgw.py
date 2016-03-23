from auth import Authenticate
from bucket import Bucket
from objects import  KeyOp, UploadContentsFromString, UploadContentsFromFile
import utils.log as log
import objects, bucket


class RGW(object):

    def __init__(self, access_key, secret_key):

        log.debug('class: %s' % self.__class__.__name__)

        auth = Authenticate(access_key, secret_key)
        connection = auth.do_auth()

        assert connection['status']
        connection = connection['conn']

        self.bucket = Bucket(connection)








