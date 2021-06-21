import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../")))
import argparse
import subprocess

from utils import log
from utils.utils import *


class CliValidationTest(object):
    def __init__(self, cluster_name):

        self.cluster_name = cluster_name

        log.info("got cluster name : %s" % self.cluster_name)

        self.check_op = (
            lambda error_to_check, cmd_output: True
            if error_to_check in cmd_output
            else False
        )

    def cli_validation(self, cmd, err_to_check, err_desc):

        try:
            cmd_output = subprocess.check_output(cmd).strip("\n")

            error_exixts = self.check_op(err_to_check, cmd_output)

            if error_exixts:

                log.info("Test case for %s has  passed " % (err_desc))

            else:
                log.error("Test case for %s has failed " % (err_desc))

        except (subprocess.CalledProcessError) as e:
            log.error(e)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Ceph medic automation")

    parser.add_argument(
        "-cluster", dest="cluster_name", help="Cluster name ", default="ceph"
    )

    args = parser.parse_args()

    CLUSTER_NAME = args.cluster_name

    cli_validation_op = CliValidationTest(CLUSTER_NAME)
    test_desc = []
    for key in invalid_cmd_err:
        test_desc.append(key)

    test_result = [
        cli_validation_op.cli_validation(
            cmd=[
                "ceph-medic",
                "--inventory",
                "{}".format(invalid_inventory),
                "--cluster",
                "{}".format(CLUSTER_NAME),
                "check",
            ],
            err_to_check=invalid_cmd_err["Invalid Inventory"][
                "Invalid inventory error"
            ],
            err_desc=test_desc[0],
        ),
        cli_validation_op.cli_validation(
            cmd=[
                "ceph-medic",
                "--ssh-config",
                "{}".format(invalid_ssh),
                "--cluster",
                "%s" % CLUSTER_NAME,
                "--inventory",
                "check",
            ],
            err_to_check=invalid_cmd_err["Invalid SSH"]["Invalid ssh error"],
            err_desc=test_desc[1],
        ),
        cli_validation_op.cli_validation(
            cmd=[
                "ceph-medic",
                "--ssh-config",
                "{}".format(invalid_ssh),
                "--cluster",
                "{}".format(CLUSTER_NAME),
                "--inventory",
                "{}".format(invalid_inventory),
                "check",
            ],
            err_to_check=invalid_cmd_err["Invalid Invenotory and SSH"][
                "Invalid invenotory and ssh error"
            ],
            err_desc=test_desc[2],
        ),
        cli_validation_op.cli_validation(
            cmd=["ceph-medic", "--cluster", "{}".format(invalid_cluster), "check"],
            err_to_check=ERRORS.common_errs["ECOM1"]["error_code"],
            err_desc=ERRORS.common_errs["ECOM1"]["error_code"],
        ),
        cli_validation_op.cli_validation(
            cmd=["ceph-medic", "{}".format(invalid_cmd)],
            err_to_check=invalid_cmd_err["Invalid Command"]["Invalid command error"],
            err_desc=test_desc[3],
        ),
    ]
