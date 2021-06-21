"""
Performs s3cmd oprations
"""


import logging

log = logging.getLogger()


class S3CMD:
    def __init__(self, operation, options=None):
        """
        Constructor for S3CMD class
        operation(str): S3CMD operation, E.g: ls, mb, etc...
        options(list): Optional options for the command
        """
        bin_path = "/home/cephuser/venv/bin/"
        self.prefix = bin_path + "s3cmd"
        if options is None:
            options = []
        self.operation = operation
        self.options = " ".join(options)

    def command(self, params=None):
        """
        Args:
            params(list): list of params to be passed in the command
        Returns: command to be executed
        """
        if params is None:
            params = []
        command_list = [self.prefix, self.options, self.operation] + params
        cmd = list(filter(lambda cmd: len(cmd) > 0, command_list))
        cmd = " ".join(cmd)
        log.info('S3CMD command "%s" created' % cmd)
        return cmd
