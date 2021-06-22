import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../")))
import argparse
import subprocess

from utils import log
from utils.errors_to_revert import ErrorToRevert
from utils.errors_to_simulate import ErrorSimulation
from utils.utils import ERRORS


class ErrrosCheckTest(object):
    def __init__(self, cluster_name):

        self.check_op = (
            lambda error_code_to_check, cmd_output: True
            if error_code_to_check in cmd_output
            else False
        )
        self.cluster_name = cluster_name
        log.info("Got cluster name %s" % (self.cluster_name))

    def check_and_revert(self, cmd_list, error_code_to_check, error_to_revert):

        try:

            cmd_output = subprocess.check_output(
                cmd_list
            ).split()  # converting the output to list for parsing

            error_code_exixts = self.check_op(error_code_to_check, cmd_output)

            if not error_code_exixts:
                raise Exception, "Error code %s not exists,failed" % (
                    error_code_to_check
                )
            else:
                log.info("%s code has occured,Passed" % (error_code_to_check))

        except Exception, e:

            print e

            log.error(e)

        finally:

            if error_to_revert is not None:

                error_to_revert()

    def induce(self, error_to_simulate):

        try:

            if error_to_simulate is not None:

                error_to_simulate()

        except Exception as e:

            log.error(e)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Ceph medic automation")

    parser.add_argument(
        "-cluster", dest="cluster_name", help="Cluster name", default="ceph"
    )

    args = parser.parse_args()

    CLUSTER_NAME = args.cluster_name

    cmd = ["ceph-medic", "--cluster", "%s" % (CLUSTER_NAME), "check"]

    simulate = ErrorSimulation(CLUSTER_NAME)

    revert = ErrorToRevert(CLUSTER_NAME)

    # Checking for ECOM1 error

    ecom1 = ErrrosCheckTest(CLUSTER_NAME)

    ecom1.induce(error_to_simulate=simulate.ecom1_err)

    ecom1.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.common_errs["ECOM1"]["error_code"],
        error_to_revert=revert.ecom1_err_revert,
    )

    # Checking for ECOM2 error

    ecom2 = ErrrosCheckTest(CLUSTER_NAME)

    ecom2.induce(error_to_simulate=simulate.ecom2_err)

    ecom2.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.common_errs["ECOM2"]["error_code"],
        error_to_revert=revert.ecom2_err_revert,
    )

    # Checking for ECOM3 error

    ecom3 = ErrrosCheckTest(CLUSTER_NAME)

    ecom3.induce(error_to_simulate=simulate.ecom3_err)

    ecom3.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.common_errs["ECOM3"]["error_code"],
        error_to_revert=revert.ecom3_err_revert,
    )

    # Checking for ECOM4 error

    ecom4 = ErrrosCheckTest(CLUSTER_NAME)

    ecom4.induce(error_to_simulate=simulate.ecom4_err)

    ecom4.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.common_errs["ECOM4"]["error_code"],
        error_to_revert=revert.ecom4_err_revert,
    )

    # Checking for ECOM5 error

    ecom5 = ErrrosCheckTest(CLUSTER_NAME)

    ecom5.induce(error_to_simulate=simulate.ecom5_err)

    ecom5.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.common_errs["ECOM5"]["error_code"],
        error_to_revert=revert.ecom5_err_revert,
    )

    # Checking for WMON1 warning

    wmon1 = ErrrosCheckTest(CLUSTER_NAME)

    wmon1.induce(error_to_simulate=simulate.wmon1_warning)

    wmon1.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.monitor_warnings["WMON1"]["warning_code"],
        error_to_revert=revert.wmon1_revert,
    )

    # Checking for WMON2 warning

    wmon2 = ErrrosCheckTest(CLUSTER_NAME)

    wmon2.induce(error_to_simulate=None)

    wmon2.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.monitor_warnings["WMON2"]["warning_code"],
        error_to_revert=None,
    )

    # Checking for WOSD1 warning

    wosd1 = ErrrosCheckTest(CLUSTER_NAME)

    wosd1.induce(error_to_simulate=simulate.wosd1_warning)

    wosd1.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.monitor_warnings["WOSD1"]["warning_code"],
        error_to_revert=revert.wosd1_revert,
    )

    # Checking for EMON1 error

    emon1 = ErrrosCheckTest(CLUSTER_NAME)

    emon1.induce(error_to_simulate=simulate.emon1_err)

    emon1.check_and_revert(
        cmd_list=cmd,
        error_code_to_check=ERRORS.monitor_err["EMON1"]["error_code"],
        error_to_revert=revert.emon1_err_revert,
    )
