import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../")))
import subprocess

from utils import log
from utils.utils import *


def install_ceph_medic(cmd):
    check_os = subprocess.check_output(cmd).split()

    if get_os[0] in check_os:

        install_in_ubuntu = subprocess.call(["apt-get", "-y", "install", "ceph-medic"])
        # checking return code
        if install_in_ubuntu == 0:
            log.info("installation success for Ubuntu")
        else:
            log.error("installation failed for Ubuntu")
    else:
        install_in_rh = subprocess.call(["yum", "-y", "install", "ceph-medic"])
        if install_in_rh == 0:
            log.info("installation success for RHEL")
        else:
            log.error("installation failed for RHEL")


if __name__ == "__main__":

    install_ceph_medic(cmd=["lsb_release", "-a"])
