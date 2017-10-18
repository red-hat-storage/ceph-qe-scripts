import time
import subprocess

POOL_NAME = "testpool_QAfreedisk"
IMAGE_NAME = "testimage"
IMAGE_SIZE = 10240
SNAP_NAME = "testsnap"
CLUSTER_NAME = "ceph"
ITERATION = 0
RAW_INITIAL = 0.00
RAW_INTERMEDIATE = 0.00
RAW_FINAL = 0.00

def rawUsed():
    cmd_output = subprocess.check_output(["ceph", "--cluster", "{}".format(CLUSTER_NAME), "df"])
    cmd_output_list = cmd_output.split()
    return float(cmd_output_list[10])

RAW_INITIAL = rawUsed()
RAW_INTERMEDIATE = RAW_INITIAL

print "%RAW Used Currently = ",RAW_INITIAL

subprocess.Popen(
    ["ceph", "osd", "--cluster", "{}".format(CLUSTER_NAME), "pool", "create", "{}".format(POOL_NAME), "128",
     "128"]).wait()

while RAW_INTERMEDIATE <= RAW_INITIAL + 2.00:
    ITERATION += 1
    print "#############################"
    print "Iteration No. : ", ITERATION
    print "%RAW Used initially = ", RAW_INITIAL
    print "%RAW Used currently = ", RAW_INTERMEDIATE
    print "#############################"
    subprocess.Popen(["rbd", "--cluster", "{}".format(CLUSTER_NAME), "create", "--size", "{}".format(IMAGE_SIZE),
                      "{}/{}{}".format(POOL_NAME, IMAGE_NAME, ITERATION)]).wait()

    subprocess.Popen(["rbd", "--cluster", "{}".format(CLUSTER_NAME), "snap", "create",
                      "{}/{}{}@{}{}".format(POOL_NAME, IMAGE_NAME, ITERATION, SNAP_NAME, ITERATION)]).wait()

    subprocess.Popen(["rbd", "--cluster", "{}".format(CLUSTER_NAME), "bench-write",
                      "{}/{}{}".format(POOL_NAME, IMAGE_NAME, ITERATION)]).wait()

    time.sleep(5)

    RAW_INTERMEDIATE = rawUsed()

time.sleep(30)

for x in range(1, ITERATION + 1):
    subprocess.Popen(["rbd", "snap", "--cluster", "{}".format(CLUSTER_NAME), "rm",
                      "{}/{}{}@{}{}".format(POOL_NAME, IMAGE_NAME, x, SNAP_NAME, x)]).wait()

time.sleep(10)
print "######################"
print "Waiting for 10 minutes"
print "######################"

for x in range(1, 11):
    RAW_FINAL = rawUsed()
    if RAW_FINAL < RAW_INTERMEDIATE:
        print "%RAW Used before removing snaps and after image benchwrites = ", RAW_INTERMEDIATE
        print "%RAW Used after removing snaps = ", RAW_FINAL
        print "Test Passed"
        print "Space is released"
        subprocess.Popen(["ceph", "osd", "--cluster", "{}".format(CLUSTER_NAME), "pool", "delete", "{}".format(POOL_NAME),
                          "{}".format(POOL_NAME), "--yes-i-really-really-mean-it"]).wait()
        exit(0)
    time.sleep(60)


print "%RAW Used before removing snaps and after image benchwrites = ", RAW_INTERMEDIATE
print "%RAW Used after removing snaps = ", RAW_FINAL
print "Test Failed"
print "Space is not released"
exit(1)
