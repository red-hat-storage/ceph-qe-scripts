"""
Performs s3cmd oprations
"""


from subprocess import check_output


class S3CMD:
    def __init__(self, operation, options=None):
        """
        Constructor for S3CMD class
        operation(str): S3CMD operation, E.g: ls, mb, etc...
        options(list): Optional options for the command
        """
        self.prefix = "s3cmd"
        if options is None:
            options = []
        self.operation = operation
        self.options = " ".join(options)

    def command(self, params=None):
        """
        Args:
            params(list): list of params to be passed in the command
        """
        if params is None:
            params = []
        command_list = [self.prefix, self.options, self.operation] + params
        self.command = list(filter(lambda cmd: len(cmd) >0, command_list))

    def execute(self):
        """
        Executes s3cmd command
        Returns: S3 Command output
        """
        output = check_output(self.command)
        return output
