import boto3
import socket
import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
import v2.utils.utils as utils


class RGWBaseException(Exception):
    # RGW Base Exception Class
    def __init__(self, message=None,):
        super().__init__(message)
        self.message = message


class ConfigError(RGWBaseException):
    # exception when config error occurs
    def __init__(self, message=None):
        super().__init__(message)
        self.message = message


class RGWIOGenException(RGWBaseException):
    # exception raised when io gen occurs
    def __init__(self, message=None, ):
        super().__init__(message)
        self.message = message


class TestExecError(RGWBaseException):
    # test execution error
    def __init__(self, message=None, ):
        super().__init__(message)
        self.message = message


class NFSGaneshaBaseException(Exception):
    # Base exception for NFS-Ganesha
    def __init__(self, message=None, ):
        super().__init__(message)
        self.message = message


class NFSGaneshaMountError(NFSGaneshaBaseException):
    # NFS Mount error
    def __init__(self, message=None, ):
        super().__init__(message)
        self.message = message
