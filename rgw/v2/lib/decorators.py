import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from functools import wraps
import v2.utils.utils as utils
import v2.lib.pem as pem
from v2.lib.exceptions import RGWBaseException
import traceback
import logging

log = logging.getLogger()


def check_pem(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        log.info('kwargs: {}'.format(kwargs))
        log.info('executing func: {name}'.format(name=function.__name__))
        log.info('ssl: {}'.format(kwargs.get('ssl')))
        if kwargs.get('ssl'):
            log.info('in decorator: checking if pem file exists ')
            if not pem.check_pem_file_exists():
                log.info('pem file does not exist')
                log.info('creating pem file')
                pem.create_pem()
            else:
                log.info('in decorator: pem file already exists')
        else:
            log.info('ssl not enabled')
        return function(*args, **kwargs)
    return wrapper
