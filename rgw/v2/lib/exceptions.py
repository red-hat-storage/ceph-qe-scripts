import boto3
import socket
import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
import v2.utils.utils as utils


class RGWBaseException(Exception):
    pass


class RGWIOGenException(RGWBaseException):
    # exception raised when io gen occurs
    pass


class TestExecError(RGWBaseException):
    # test execution error
    pass


class NFSGaneshaBaseException(Exception):
    # Base exception for NFS-Ganesha
    pass


class NFSGaneshaMountError(NFSGaneshaBaseException):
    # NFS Mount error
    pass