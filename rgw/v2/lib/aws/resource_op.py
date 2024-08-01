"""
Performs aws oprations
"""


import logging

log = logging.getLogger()


class AWS:
    def __init__(self, options=None, ssl=None):
        """
        Constructor for aws class
        options(list): Optional options for the command
        """
        bin_path = "/usr/local/bin/"
        self.prefix = bin_path + "aws s3api"
        if ssl:
            self.prefix = self.prefix + " --no-verify-ssl"
        if options is None:
            options = []
        self.options = " ".join(options)

    def command(self, operation, params=None):
        """
        Args:
            params(list): list of params to be passed in the command
            operation(str): aws operations
        Returns: command to be executed
        """
        if params is None:
            params = []
        command_list = [self.prefix, self.options, operation] + params
        cmd = list(filter(lambda cmd: len(cmd) > 0, command_list))
        cmd = " ".join(cmd)
        log.info(f"AWS command created {cmd}")
        return cmd
