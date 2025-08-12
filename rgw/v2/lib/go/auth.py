"""
go auth file
"""
import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))
log = logging.getLogger()


from v2.utils import utils


def install_go():
    """
    Method to install go on local node
    """
    out = utils.exec_shell_cmd("sudo yum install -y golang")
    if out is False:
        raise AssertionError("go Installation Failed")
