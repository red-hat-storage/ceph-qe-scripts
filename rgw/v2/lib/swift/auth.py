import swiftclient
import socket
import os, sys
import logging

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.utils as utils

log = logging.getLogger()


class Auth(object):
    """
        This class is used to authenticate using swift

        The functions in this class are
        1. do_auth()
    """
    def __init__(self, user_info):
        """
            Initializes the user_info variables
        """
        self.secret_key = user_info['key']
        self.hostname = socket.gethostname()
        self.port = int(utils.get_radosgw_port_no())
        self.is_secure = False
        self.user_id = user_info['user_id']

    def do_auth(self):
        """
            This function is to perform authentication using swift

            Parameters:

            Returns:
                rgw: returns the connection details
        """
        log.info('performing authentication using swift')
        # user = 'tenant3$tuffy3:swift'
        # key = 'm4NsRGjghOpUPX3OZZFeIYUylNjO22lMVDXATnNi' -- secret key

        rgw = swiftclient.Connection(user=self.user_id,
                                     key=self.secret_key,
                                     authurl='http://%s:%s/auth' % (self.hostname, self.port),
                                     )
        return rgw
