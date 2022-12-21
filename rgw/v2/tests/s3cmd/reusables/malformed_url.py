import logging
import os
from itertools import permutations

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def execute_command_with_permutations(sample_cmd, config):
    """executes command and checks for"""
    special_characters = [
        "ab",
        "~",
        "!",
        "@",
        "#",
        "$",
        "%",
        "^",
        "-",
        "_",
        "/",
        "?",
        "+",
        "=",
        ":",
        ",",
        ".",
        "cd",
    ]
    random_strings_list = [
        "".join(p) for p in permutations(special_characters, config.permutation_count)
    ]
    random_strings = " ".join(random_strings_list)

    # execute the command with malformed s3uri, refer this bz https://bugzilla.redhat.com/show_bug.cgi?id=2138921
    s3uri = "s3://https:///example.com/%2f.."
    cmd = sample_cmd.replace("s3uri", s3uri)

    # set the environment variable for the execution of shell script
    os.environ["random_strings"] = random_strings

    # execute the command with special characters at the end
    utils.exec_shell_cmd(cmd)
    cmd = (
        "for i in ${random_strings[@]};"
        + f"do echo {sample_cmd.replace('s3uri', 's3://${i}')};"
        + f"{sample_cmd.replace('s3uri', 's3://${i}')};"
        + "done;"
    )
    out = utils.exec_long_running_shell_cmd(cmd)
    log.info(out)
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")
