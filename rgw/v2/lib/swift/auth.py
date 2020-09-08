import swiftclient
import socket
import os, sys
import logging

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.utils as utils

log = logging.getLogger()


class Auth(object):

    def __init__(self, user_info):
        self.secret_key = user_info['key']
        self.hostname = socket.gethostname()
        self.port = int(utils.get_radosgw_port_no())
        self.is_secure = False
        self.user_id = user_info['user_id']

    def do_auth(self):
        log.info('performing authentication usinf swift')
        # user = 'tenant3$tuffy3:swift'
        # key = 'm4NsRGjghOpUPX3OZZFeIYUylNjO22lMVDXATnNi' -- secret key

        rgw = swiftclient.Connection(user=self.user_id,
                                     key=self.secret_key,
                                     authurl='http://%s:%s/auth' % (self.hostname, self.port),
                                     )
        return rgw
