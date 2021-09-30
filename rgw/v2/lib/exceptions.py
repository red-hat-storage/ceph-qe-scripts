import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging

from botocore import exceptions as BotocoreExceptions

log = logging.getLogger()


class RGWBaseException(Exception):
    # RGW Base Exception Class
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class ConfigError(RGWBaseException):
    # exception when config error occurs
    def __init__(self, message=None):
        super().__init__(message)
        self.message = message


class RGWIOGenException(RGWBaseException):
    # exception raised when io gen occurs
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class TestExecError(RGWBaseException):
    # test execution error
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class S3CMDConfigFileNotFound(RGWBaseException):
    # s3cmd file not exists
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class AccessDeniedObjectDeleted(RGWBaseException):
    # Access denied object got deleted
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class ObjectVersionCountMismatch(RGWBaseException):
    # object count mismatch
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class S3CommandExecError(RGWBaseException):
    # s3cmd Command execution error
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class NFSGaneshaBaseException(Exception):
    # Base exception for NFS-Ganesha
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class NFSGaneshaMountError(NFSGaneshaBaseException):
    # NFS Mount error
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class InvalidCephConfigOption(RGWBaseException):
    # Invalid ceph config error
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class MFAVersionError(Exception):
    # exception raised when enabling MFA and versioning fails
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class SyncFailedError(Exception):
    # exception raised when there is sync error in multisite
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message


class DefaultDatalogBackingError(Exception):
    # get default datalog backing error
    def __init__(
        self,
        message=None,
    ):
        super().__init__(message)
        self.message = message
