"""
Performs s5cmd operations
"""


import logging

log = logging.getLogger()


class S5CMD:
    def __init__(self, options=None, ssl=None):
        """
        Constructor for s5cmd class
        options(list): Optional options for the command
        """
        self.prefix = "s5cmd"
        if ssl:
            self.prefix = self.prefix + " --no-verify-ssl"
        if options is None:
            options = []
        self.options = " ".join(options)

    def command(self, operation, params=None):
        """
        Args:
            params(list): list of params to be passed in the command
            operation(str): s5cmd operations
        Returns: command to be executed
        """
        if params is None:
            params = []
        command_list = [self.prefix, self.options, operation] + params
        cmd = list(filter(lambda cmd: len(cmd) > 0, command_list))
        cmd = " ".join(cmd)
        log.info(f"S5CMD command created {cmd}")
        return cmd
