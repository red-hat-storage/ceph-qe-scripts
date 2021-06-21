import logging
import os

LOG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILENAME = os.path.join(LOG_PATH, "api_log.txt")

if os.path.exists(LOG_FILENAME):
    os.unlink(LOG_FILENAME)

logging.basicConfig(
    format="%(asctime)s : %(levelname)s: %(message)s",
    datefmt="[%m/%d/%Y - %I:%M:%S %p]",
    filename=LOG_FILENAME,
    level=logging.DEBUG,
)


def debug(debug_msg):
    logging.debug(debug_msg)


def error(error_msg):
    logging.error(error_msg)


def info(information):
    logging.info(information)
