import os
import logging
from time import gmtime, strftime

LOG_PATH = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..'))
LOG_FILENAME = os.path.join(LOG_PATH, 'ceph-medic.txt')

if os.path.exists(LOG_FILENAME): os.unlink(LOG_FILENAME)

logging.basicConfig(format='%(asctime)s : %(levelname)s: %(message)s', datefmt='[%m/%d/%Y - %I:%M:%S %p]',filename=LOG_FILENAME,level=logging.DEBUG)


def debug(debug_msg):
    print  '[' ,strftime("%Y-%m-%d %H:%M:%S", gmtime()), ']' , debug_msg
    logging.debug(debug_msg)


def error(error_msg):
    # type: (object) -> object
    print '[' ,strftime("%Y-%m-%d %H:%M:%S", gmtime()), ']' , error_msg
    logging.error(error_msg)


def info(information):
    print '[' ,strftime("%Y-%m-%d %H:%M:%S", gmtime()), ']',information
    logging.info(information)
