"""
Performs s3cmd oprations
"""


import logging
import os
import shutil
import sys

log = logging.getLogger()


def get_s3cmd_path():
    """
    Resolve s3cmd without hardcoded install paths.

    Lookup order:
      1. S3CMD_BIN env override
      2. PATH (shutil.which) — works when venv is activated
      3. Same bin/ as the current Python interpreter (any venv location)
      4. VIRTUAL_ENV/bin/s3cmd
      5. ~/venv/bin/s3cmd and ~cephuser/venv/bin/s3cmd (common lab layouts)
      6. System locations (/usr/bin, /usr/local/bin)
    """
    override = os.environ.get("S3CMD_BIN")
    if override and os.path.isfile(override):
        return override

    path = shutil.which("s3cmd")
    if path:
        return path

    # Prefer the venv that is running this test (portable across hosts)
    python_bin_dir = os.path.dirname(os.path.abspath(sys.executable))
    sibling = os.path.join(python_bin_dir, "s3cmd")
    if os.path.isfile(sibling):
        return sibling

    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        candidate = os.path.join(venv, "bin", "s3cmd")
        if os.path.isfile(candidate):
            return candidate

    for candidate in (
        os.path.expanduser("~/venv/bin/s3cmd"),
        os.path.expanduser("~cephuser/venv/bin/s3cmd"),
        "/usr/local/bin/s3cmd",
        "/usr/bin/s3cmd",
    ):
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        "s3cmd not found. Activate the venv that has s3cmd, install s3cmd on PATH, "
        "or set S3CMD_BIN to the full path of the s3cmd binary."
    )


class S3CMD:
    def __init__(self, operation, options=None):
        """
        Constructor for S3CMD class
        operation(str): S3CMD operation, E.g: ls, mb, etc...
        options(list): Optional options for the command
        """
        self.prefix = get_s3cmd_path()
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
