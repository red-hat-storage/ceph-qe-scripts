import logging

LOG_FILENAME = 'clog.txt'
logging.basicConfig(format='%(asctime)s : %(levelname)s: %(message)s', datefmt='[%m/%d/%Y - %I:%M:%S %p]',filename=LOG_FILENAME,level=logging.DEBUG)


def debug(debug_msg):
    logging.debug(debug_msg)


def error(error_msg):
    logging.error(error_msg)


def info(information):
    logging.info(information)
