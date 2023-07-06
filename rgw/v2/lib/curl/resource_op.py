"""
Performs rgw operations using curl
"""

import logging

from v2.tests.aws import reusable as aws_reusable

log = logging.getLogger()


class CURL:
    def __init__(self, user_info, ssh_con):
        """
        Constructor for curl class
        user_info(dict) : user details
        ssh_con(str) : rgw ip address
        """
        self.username = user_info["access_key"]
        self.password = user_info["secret_key"]
        self.endpoint_url = aws_reusable.get_endpoint(ssh_con)
        self.prefix = f"curl --show-error --fail -v -s --aws-sigv4 aws:amz:us-east-1:s3 -u '{self.username}:{self.password}'"

    def command(
        self,
        http_method="GET",
        headers=None,
        input_file=None,
        output_file=None,
        url_suffix=None,
    ):
        """
        Args:
            http_method(str): http method for the curl command like GET, PUT, DELETE
            headers(dict): dict of headers with key and value like -H 'x-amz-content-sha256: UNSIGNED-PAYLOAD'
            input_file(str): input file path to be passed for some operations like upload_object
            output_file(str): output file path to be passed for some operations like download_object
            url_suffix(str): suffix that is followed by url like http://ip:port/bkt1?max-keys=25
        Returns: command to be executed
        """
        cmd = self.prefix

        cmd = f"{cmd} -X {http_method}"
        header_string = ""
        if headers:
            for key, val in headers.items():
                # any underscores in the header will automatically be converted to hyphen by curl
                header_string = f"{header_string} -H '{key}:{val}'"
        cmd = f"{cmd} {header_string}"
        if input_file:
            cmd = f"{cmd} -T {input_file}"
        if output_file:
            cmd = f"{cmd} -o {output_file}"

        url = self.endpoint_url
        if url_suffix:
            url = f"{url}/{url_suffix}"
        cmd = f"{cmd} {url}"
        log.info(f"CURL command created: {cmd}")
        return cmd
