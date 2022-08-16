import logging
import os
import socket
import sys

import swiftclient

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.utils as utils

log = logging.getLogger()


class Auth(object):
    """
    This class is used to authenticate using swift

    The functions in this class are
    1. do_auth()
    """

    def __init__(self, user_info, ssh_con=None, is_secure=False):
        """
        Initializes the user_info variables
        """
        self.secret_key = user_info["key"]
        if ssh_con is not None:
            stdin, stdout, stderr = ssh_con.exec_command("hostname")
            self.hostname = stdout.readline().strip()
            self.port = utils.get_radosgw_port_no(ssh_con)
        else:
            self.hostname = socket.gethostname()
            self.port = utils.get_radosgw_port_no()
        self.is_secure = is_secure
        self.user_id = user_info["user_id"]

    def do_auth(self):
        """
        This function is to perform authentication using swift

        Parameters:

        Returns:
            rgw: returns the connection details
        """
        log.info("performing authentication using swift")
        # user = 'tenant3$tuffy3:swift'
        # key = 'm4NsRGjghOpUPX3OZZFeIYUylNjO22lMVDXATnNi' -- secret key

        proto = "https" if self.is_secure else "http"

        rgw = swiftclient.Connection(
            user=self.user_id,
            key=self.secret_key,
            insecure=True,
            authurl=f"{proto}://{self.hostname}:{self.port}/auth",
        )
        return rgw
