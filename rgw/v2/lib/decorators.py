import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
from functools import wraps

import v2.lib.pem as pem

log = logging.getLogger()


def check_pem(function):
    """
    Function checks if the pem file exists and creates one if it doesn't.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):
        log.info("kwargs: {}".format(kwargs))
        log.info("args: {}".format(args[2]))
        log.info("executing func: {name}".format(name=function.__name__))
        log.info("ssl: {}".format(kwargs.get("ssl")))
        ssh_con = args[2]
        if kwargs.get("ssl"):
            log.info("in decorator: checking if pem file exists ")
            if not pem.check_pem_file_exists(ssh_con):
                log.info("pem file does not exist")
                log.info("creating pem file")
                pem.create_pem(ssh_con)
            else:
                log.info("in decorator: pem file already exists")
        else:
            log.info("ssl not enabled")
        return function(*args, **kwargs)

    return wrapper
