# Script to execute the test CEPH 9873
#  Test Description: Check the timing with fast-diff enabled and fast-diff disabled.
#                    Enabling fast-diff will help us to export the Image faster.
#  Success: exit code: 0
#  Failure: Failed commands with the Error code in output and Non Zero Exit

import datetime
from subprocess import PIPE, Popen
from time import sleep

# Variables and List
START = datetime.datetime.now()
CLUSTER_NAME = "ceph"
POOL_NAME = "test_rbd_pool"
DIR_PATH = "/path"
F_COUNT = 0
failed_commands = []


# Exception Class
class CmdError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# Function Executing the command
def cmd(args):
    global F_COUNT
    while " " in args:
        args.remove(" ")
    print "************************************************************************************************************"
    command = " ".join(map(str, args))
    print "Executing the command :", command

    try:
        process = Popen(args, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        print "-----Output-----"
        print stdout, stderr
        if process.returncode == 0:
            return 0
        else:
            F_COUNT += 1
            print "Command Failed"
            raise CmdError(process.returncode)
    except CmdError as e:
        failed_commands.append(
            ["Command : " + command, ", Error Code : " + str(e.value)]
        )


# Directories Creation
def create_dir():
    cmd(["mkdir", "{}".format(DIR_PATH)])


# Directories deletion
def delete_dir():
    cmd(["rm", "-rf", "{}".format(DIR_PATH)])


# Export Time Check
def export_time():
    cmd(["rm", "-f", "{}/clonetestimg".format(DIR_PATH)])
    export_start = datetime.datetime.now()
    cmd(
        [
            "rbd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "export",
            "{}/clonetestimg".format(POOL_NAME),
            "{}/clonetestimg".format(DIR_PATH),
        ]
    )
    return datetime.datetime.now() - export_start


if __name__ == "__main__":
    # CleanUp
    delete_dir()
    cmd(
        [
            "ceph",
            "osd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "pool",
            "delete",
            "{}".format(POOL_NAME),
            "{}".format(POOL_NAME),
            "--yes-i-really-really-mean-it",
        ]
    )

    # Directory & Pool Creation
    create_dir()
    cmd(
        [
            "ceph",
            "osd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "pool",
            "create",
            "{}".format(POOL_NAME),
            "128",
            "128",
        ]
    )

    # Test Steps
    cmd(
        [
            "rbd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "create",
            "-s",
            "50G",
            "{}/testimg".format(POOL_NAME),
        ]
    )
    cmd(
        [
            "rbd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "bench-write",
            "--io-total",
            "45G",
            "{}/testimg".format(POOL_NAME),
        ]
    )
    cmd(
        [
            "rbd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "snap",
            "create",
            "{}/testimg@snapimg".format(POOL_NAME),
        ]
    )
    cmd(
        [
            "rbd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "snap",
            "protect",
            "{}/testimg@snapimg".format(POOL_NAME),
        ]
    )
    cmd(
        [
            "rbd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "clone",
            "{}/testimg@snapimg".format(POOL_NAME),
            "{}/clonetestimg".format(POOL_NAME),
        ]
    )

    for ITERATION in range(1, 4):
        print "####### ITERATION: {} #######".format(ITERATION)
        if ITERATION != 1:
            cmd(
                [
                    "rbd",
                    "--cluster",
                    "{}".format(CLUSTER_NAME),
                    "feature",
                    "enable",
                    "{}/clonetestimg".format(POOL_NAME),
                    "fast-diff",
                ]
            )
            cmd(
                [
                    "rbd",
                    "--cluster",
                    "{}".format(CLUSTER_NAME),
                    "object-map",
                    "rebuild",
                    "{}/clonetestimg".format(POOL_NAME),
                ]
            )
        time_fast_diff_enable = export_time()
        cmd(
            [
                "rbd",
                "--cluster",
                "{}".format(CLUSTER_NAME),
                "feature",
                "disable",
                "{}/clonetestimg".format(POOL_NAME),
                "fast-diff",
            ]
        )
        time_fast_diff_disable = export_time()
        print "Time taken for export with fast-diff feature enabled:", time_fast_diff_enable
        print "Time taken for export with fast-diff feature disabled:", time_fast_diff_disable
        if time_fast_diff_enable < time_fast_diff_disable:
            print "The export operation with fast-diff feature enabled is faster"
        else:
            F_COUNT += 1
            print "The export operation with fast-diff feature enabled is not faster"
        if ITERATION != 3:
            cmd(
                [
                    "rbd",
                    "--cluster",
                    "{}".format(CLUSTER_NAME),
                    "bench-write",
                    "--io-total",
                    "45G",
                    "{}/clonetestimg".format(POOL_NAME),
                ]
            )
        sleep(10)

    # CleanUp
    delete_dir()
    cmd(
        [
            "ceph",
            "osd",
            "--cluster",
            "{}".format(CLUSTER_NAME),
            "pool",
            "delete",
            "{}".format(POOL_NAME),
            "{}".format(POOL_NAME),
            "--yes-i-really-really-mean-it",
        ]
    )

    print "Execution time for the script : " + str(datetime.datetime.now() - START)
    if F_COUNT == 0:
        print "********** TEST PASSED **********"
        exit(0)
    else:
        print "********** TEST FAILED **********"
        print "FAILED COMMANDS:"
        for values in failed_commands:
            print values[0], values[1]
        exit(1)
