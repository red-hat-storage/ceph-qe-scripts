import logging
import os

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))


def configure_logging(f_name="rgw_test", set_level="info"):

    set_level = logging.getLevelName(set_level.upper())
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

    c_fnane = os.path.join(LOG_DIR, f_name + ".console.log")
    v_fname = os.path.join(LOG_DIR, f_name + ".verbose.log")

    if os.path.exists(c_fnane):
        os.unlink(c_fnane)
    if os.path.exists(v_fname):
        os.unlink(v_fname)
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    log = logging.getLogger()
    log.setLevel(logging.DEBUG)

    # file handler settings for verbose_file
    # logging_level is set to DEBUG
    file_handler = logging.FileHandler(v_fname)
    file_handler.setFormatter(formatter)

    # handler settings for simple log file as well as console
    # logging level can be set for both the handlers
    file_handler2 = logging.FileHandler(c_fnane)
    file_handler2.setFormatter(formatter)
    file_handler2.setLevel(set_level)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(set_level)

    log.addHandler(stream_handler)
    log.addHandler(file_handler)
    log.addHandler(file_handler2)
