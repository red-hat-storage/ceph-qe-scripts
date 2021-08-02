import os
import socket
import sys

import boto3

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging

import v2.utils.utils as utils
from botocore.client import Config

log = logging.getLogger()


class Auth(object):
    """
    This class is used to perform authentication.
    The functions in this class are
    1. do_auth() : Authenticate using resource
    2. do_auth_using_client() : Authenticate using client
    """

    def __init__(self, user_info, **extra_kwargs):
        """
        Initializes the variables of user_info parameter
        """
        self.access_key = user_info["access_key"]
        self.secret_key = user_info["secret_key"]
        self.hostname = socket.gethostname()
        self.ip = socket.gethostbyname(self.hostname)
        self.ssl = extra_kwargs.get("ssl", False)
        self.port = utils.get_radosgw_port_no()
        self.endpoint_url = (
            "https://{}:{}".format(self.ip, self.port)
            if self.ssl
            else "http://{}:{}".format(self.ip, self.port)
        )
        self.is_secure = False
        self.user_id = user_info["user_id"]
        self.session_token = user_info.get("session_token")

        log.info("access_key: %s" % self.access_key)
        log.info("secret_key: %s" % self.secret_key)
        log.info("hostname: %s" % self.hostname)
        log.info("port: %s" % self.port)
        log.info("user_id: %s" % self.user_id)
        log.info("endpoint url: %s" % self.endpoint_url)
        log.info("ssl: %s" % self.ssl)
        log.info("session_token: %s" % self.session_token)

    def do_auth(self, **config):
        """
        This function is to perform authentication using resource
        Parameters:
            **config: Configuration details
        Returns:
            rgw: Connection status
        """
        log.info("performing authentication")
        additional_config = Config(
            signature_version=config.get("signature_version", None)
        )

        rgw = boto3.resource(
            "s3",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            endpoint_url=self.endpoint_url,
            use_ssl=self.ssl,
            verify=False,
            config=additional_config,
            aws_session_token=self.session_token if self.session_token else None,
        )

        log.info("connected")

        return rgw

    def do_auth_using_client(self, **config):
        """
        This function is to perform authentication using client module

        Parameters:
            **config: Configuration details

        Returns:
            rgw: Connection status
        """
        log.info("performing authentication using client module")
        additional_config = Config(
            signature_version=config.get("signature_version", None)
        )
        rgw = boto3.client(
            "s3",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            endpoint_url=self.endpoint_url,
            config=additional_config,
            verify=False,
            aws_session_token=self.session_token if self.session_token else None,
        )
        return rgw

    def do_auth_iam_client(self, **extra_config):
        """
        perform authentication using iam client
        :param extra_config: extra config for config key
        :return: rgw connection object
        """

        log.info("performing authentication using sts client")
        rgw = boto3.client(
            "iam",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            endpoint_url=self.endpoint_url,
            region_name="",
        )

        return rgw

    def do_auth_sts_client(
        self,
    ):
        """
        :return: connection object
        """

        sts_client = boto3.client(
            "sts",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            endpoint_url=self.endpoint_url,
            region_name="",
        )

        return sts_client
