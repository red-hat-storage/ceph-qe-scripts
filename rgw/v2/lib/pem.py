import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import traceback

import v2.utils.utils as utils

SSL_CERT_PATH = "/etc/ceph/"
PEM_FILE_NAME = "server.pem"
PEM_FILE_PATH = os.path.join(SSL_CERT_PATH, PEM_FILE_NAME)

import logging

log = logging.getLogger()


def create_pem():
    """
    creates a pem file.

    Parameters:

    Returns:
    PEM_FILE_PATH :  returns the pem file path
    """
    try:
        log.info("Creating pem file")
        cmd = (
            "openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.csr -days 365 -nodes "
            '-subj "/C=IN/ST=KA/L=BLR/O=Carina Company/OU=Redhat/CN=*.ceph.redhat.com"'
        )
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            raise Exception("Key file creation error")
        log.info("output :%s" % out)
        cmd2 = "cat server.csr server.key > {pem_file_path}".format(
            pem_file_path=PEM_FILE_PATH
        )
        out2 = utils.exec_shell_cmd(cmd2)
        if out2 is False:
            raise Exception("Pem file generation error")
        log.info("output :%s" % out2)
        log.info("pem file created")
        return PEM_FILE_PATH

    except Exception as e:
        log.info(e)
        log.info(traceback.format_exc())
        sys.exit(1)


def check_pem_file_exists():
    return os.path.exists(PEM_FILE_PATH)
