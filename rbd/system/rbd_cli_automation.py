# Script to test the RBD Positive CLIs
#  Test Description:
#   a) Invoke various rbd cli commands with positive options
#   b) Verify the cli executes properly
#  Success: exit code: 0
#  Failure: Failed commands with Error code in output and Non Zero Exit

import datetime
import json
import logging
import os
import shlex
import subprocess
from time import sleep

# Variables
START = datetime.datetime.now()
ITERATOR = 0
ITERATOR2 = 0
ITERATOR3 = 1
CLUSTER_NAME = "ceph"
FEATUREVAR = " "
FAILED_COUNT = 0

# Lists and dictionaries
failed_commands = []
parameters = {}

pool_name = {
    "pool_name": {
        "pool1": {"arg": "-p", "val": "test_rbd_pool"},
        "pool2": {"arg": "-p", "val": "test_rbd_pool2"},
    }
}

image_format_parameters = {
    "image_format_parameters": {
        "null": {"arg": " ", "val": " "},
        "image-format 1": {"arg": "--image-format", "val": "1"},
        "image-format 2": {"arg": "--image-format", "val": "2"},
    }
}

image_feature_parameters = {
    "image_feature_parameters": {
        "null": {"arg": " ", "val": " "},
        "layering": {"arg": "--image-feature", "val": "layering"},
        "striping": {"arg": "--image-feature", "val": "striping"},
        "exclusive-lock": {"arg": "--image-feature", "val": "exclusive-lock"},
        "object-map": {"arg": "--image-feature", "val": "exclusive-lock,object-map"},
        "fast-diff": {
            "arg": "--image-feature",
            "val": "exclusive-lock,object-map,fast-diff",
        },
        "deep-flatten": {"arg": "--image-feature", "val": "deep-flatten"},
        "journaling": {"arg": "--image-feature", "val": "exclusive-lock,journaling"},
    }
}

image_feature_disable_parameters = [
    "layering",
    "striping",
    "fast-diff",
    "object-map",
    "deep-flatten",
    "journaling",
    "exclusive-lock",
]

image_feature_enable_parameters = list(reversed(image_feature_disable_parameters))

image_shared_parameters = {
    "image_shared_parameters": {"image-shared": {"arg": "--image-shared", "val": " "}}
}

image_size_parameters = {
    "image_size_parameters": {
        "size_MB": {"arg": "-s", "val": "100M"},
        "size_GB": {"arg": "-s", "val": "10G"},
        "size_TB": {"arg": "-s", "val": "1T"},
    }
}

image_resize_parameters = {
    "image_resize_parameters": {
        "expand_size_TB": {"arg": "-s", "val": "2T"},
        "shrink_size_GB": {"arg": "-s 512G", "val": "--allow-shrink"},
        "shrink_size_MB": {"arg": "-s 1536M", "val": "--allow-shrink"},
    }
}

object_size_parameters = {
    "object_size_parameters": {
        "null": {"arg": " ", "val": " "},
        "size_B": {"arg": "--object-size", "val": "8192B"},
        "size_KB": {"arg": "--object-size", "val": "256K"},
        "size_MB": {"arg": "--object-size", "val": "32M"},
    }
}

stripe_parameters_2 = {
    "stripe_parameters": {
        "null": {
            "stripe-unit": {"arg": " ", "val": " "},
            "stripe-count": {"arg": " ", "val": " "},
        },
        "size_B": {
            "stripe-unit": {"arg": "--stripe-unit", "val": "2048"},
            "stripe-count": {"arg": "--stripe-count", "val": "16"},
        },
        "size_KB": {
            "stripe-unit": {"arg": "--stripe-unit", "val": "65536"},
            "stripe-count": {"arg": "--stripe-count", "val": "16"},
        },
        "size_MB": {
            "stripe-unit": {"arg": "--stripe-unit", "val": "16777216"},
            "stripe-count": {"arg": "--stripe-count", "val": "16"},
        },
    }
}

stripe_parameters_3 = {
    "stripe_parameters": {
        "null": {
            "stripe-unit": {"arg": " ", "val": " "},
            "stripe-count": {"arg": " ", "val": " "},
        },
        "size_B": {
            "stripe-unit": {"arg": "--stripe-unit", "val": "2048B"},
            "stripe-count": {"arg": "--stripe-count", "val": "16"},
        },
        "size_KB": {
            "stripe-unit": {"arg": "--stripe-unit", "val": "64K"},
            "stripe-count": {"arg": "--stripe-count", "val": "16"},
        },
        "size_MB": {
            "stripe-unit": {"arg": "--stripe-unit", "val": "16M"},
            "stripe-count": {"arg": "--stripe-count", "val": "16"},
        },
    }
}

io_type_parameters_2 = {"io_type_parameters": {"write": {"arg": " ", "val": "write"}}}

io_type_parameters_3 = {
    "io_type_parameters": {
        "read": {"arg": "--io-type", "val": "read"},
        "write": {"arg": "--io-type", "val": "write"},
    }
}

io_size_parameters = {
    "io_size_parameters": {
        "null": {"arg": " ", "val": " "},
        "size_KB": {"arg": "--io-size", "val": "256K"},
    }
}

io_threads_parameters = {
    "io_threads_parameters": {
        "null": {"arg": " ", "val": " "},
        "num1": {"arg": "--io-threads", "val": "20"},
    }
}

io_total_parameters = {
    "io_total_parameters": {"size_MB": {"arg": "--io-total", "val": "50M"}}
}

io_pattern_parameters = {
    "io_pattern_parameters": {
        "null": {"arg": " ", "val": " "},
        "pattern_seq": {"arg": "--io-pattern", "val": "seq"},
        "pattern_rand": {"arg": "--io-pattern", "val": "rand"},
    }
}

limit_parameters = {"limit_parameters": {"arg": "--limit", "val": "10"}}


# Function Executing the command
def execute_command(args, return_output=False):
    global FAILED_COUNT
    print "{:-^120}".format("")
    command = shlex.split(args)
    logging.info("Command:" + " ".join(command))
    try:
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        output, error = process.communicate()
        if process.returncode == 0:
            if return_output is True:
                return output
            if output:
                logging.info("Output: \n" + output)
            if error:
                logging.warning(error)

        else:
            FAILED_COUNT += 1
            logging.error(error)
            failed_commands.append(
                "Command: {}, Return Code: {}".format(
                    " ".join(command), process.returncode
                )
            )

    except subprocess.CalledProcessError as e:
        logging.error(e.output + str(e.returncode))

    except Exception as e:
        logging.error(e)


logger = logging.getLogger(__name__)
logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)

if __name__ == "__main__":
    parameters.update(pool_name)
    parameters.update(image_format_parameters)
    parameters.update(image_feature_parameters)
    parameters.update(image_size_parameters)
    parameters.update(image_resize_parameters)
    parameters.update(object_size_parameters)
    parameters.update(io_size_parameters)
    parameters.update(io_threads_parameters)
    parameters.update(io_total_parameters)
    parameters.update(io_pattern_parameters)
    parameters.update(image_shared_parameters)

    os.environ["CEPH_ARGS"] = "--cluster {}".format(CLUSTER_NAME)
    ceph_version = execute_command("ceph -v", return_output=True)
    if "version 10" in ceph_version:
        parameters.update(stripe_parameters_2)
        parameters.update(io_type_parameters_2)
    elif "version 12" in ceph_version:
        parameters.update(stripe_parameters_3)
        parameters.update(io_type_parameters_3)
        parameters.update(limit_parameters)

    # Deletion Of existing Test Pools
    for k, v in parameters["pool_name"].iteritems():
        execute_command(
            "ceph osd pool delete {pool} {pool} --yes-i-really-really-mean-it".format(
                pool=v["val"]
            )
        )

    # Pool Creation
    timer = datetime.datetime.now()
    execute_command(
        "ceph osd pool create {} 128 128".format(
            parameters["pool_name"]["pool1"]["val"]
        )
    )
    execute_command(
        "ceph osd pool create {} 128 128".format(
            parameters["pool_name"]["pool2"]["val"]
        )
    )
    print "Execution time for Pool Creation : " + str(datetime.datetime.now() - timer)

    # Simple Image Creation
    timer = datetime.datetime.now()
    for k, v in parameters["image_format_parameters"].iteritems():
        execute_command(
            "rbd create {} {} {} {} {} {} testimg{}".format(
                parameters["image_size_parameters"]["size_GB"]["arg"],
                parameters["image_size_parameters"]["size_GB"]["val"],
                v["arg"],
                v["val"],
                parameters["pool_name"]["pool1"]["arg"],
                parameters["pool_name"]["pool1"]["val"],
                ITERATOR,
            )
        )
        ITERATOR += 1
    print "Execution time for Image Creation : " + str(datetime.datetime.now() - timer)

    # Image Creation With Options
    timer = datetime.datetime.now()
    for k1, v1 in parameters["image_size_parameters"].iteritems():
        for k2, v2 in parameters["object_size_parameters"].iteritems():
            for k3, v3 in parameters["stripe_parameters"].iteritems():
                for k4, v4 in parameters["image_feature_parameters"].iteritems():
                    if " " in v3["stripe-unit"]["arg"]:
                        if "striping" in k4:
                            continue

                    if k2 != k3:
                        continue

                    else:
                        execute_command(
                            "rbd create {} {} {} {} {} {} {} {} {} {} {}/testimg{}".format(
                                v1["arg"],
                                v1["val"],
                                v2["arg"],
                                v2["val"],
                                v3["stripe-unit"]["arg"],
                                v3["stripe-unit"]["val"],
                                v3["stripe-count"]["arg"],
                                v3["stripe-count"]["val"],
                                v4["arg"],
                                v4["val"],
                                parameters["pool_name"]["pool1"]["val"],
                                ITERATOR,
                            )
                        )
                        ITERATOR += 1
    print "Execution time for Image Creation with various options : " + str(
        datetime.datetime.now() - timer
    )

    # Feature Disable & Enable and Object-map rebuild
    timer = datetime.datetime.now()
    for _ in range(0, 2):
        execute_command(
            "rbd create -s 10G --object-size 32M --stripe-unit 16777216 --stripe-count 16 --image-feature \
        layering,striping,exclusive-lock,object-map,fast-diff,deep-flatten,journaling {}/testimg{}".format(
                parameters["pool_name"]["pool1"]["val"], ITERATOR
            )
        )
        ITERATOR += 1

    ITERATOR -= 1
    for k in image_feature_disable_parameters:
        if "layering" not in k and "striping" not in k:
            execute_command(
                "rbd feature disable {}/testimg{} {}".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR, k
                )
            )

    for k in image_feature_enable_parameters:
        if "deep-flatten" not in k and "layering" not in k and "striping" not in k:
            execute_command(
                "rbd feature enable {}/testimg{} {}".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR, k
                )
            )
            if str(k) == "fast-diff" or str(k) == "object-map":
                execute_command(
                    "rbd object-map rebuild {}/testimg{}".format(
                        parameters["pool_name"]["pool1"]["val"], ITERATOR
                    )
                )
    print "Execution time for Image Features Disable and Enable : " + str(
        datetime.datetime.now() - timer
    )

    # Resize
    timer = datetime.datetime.now()
    for k, v in parameters["image_resize_parameters"].iteritems():
        execute_command(
            "rbd resize {} {} {}/testimg{}".format(
                v["arg"], v["val"], parameters["pool_name"]["pool1"]["val"], ITERATOR
            )
        )
    print "Execution time for Resizing Images : " + str(datetime.datetime.now() - timer)

    # Images Deletion
    timer = datetime.datetime.now()
    for index in range(0, 10):
        execute_command(
            "rbd rm {}/testimg{}".format(parameters["pool_name"]["pool1"]["val"], index)
        )
    print "Execution time for Image Deletion : " + str(datetime.datetime.now() - timer)

    # Snap Creation
    timer = datetime.datetime.now()
    ITERATOR -= 1
    for _ in range(0, 2):
        for ITERATOR2 in range(1, 4):
            execute_command(
                "rbd snap create {}/testimg{}@snapimg{}".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
                )
            )
        ITERATOR += 1
    print "Execution time for Snap Creation : " + str(datetime.datetime.now() - timer)

    ITERATOR -= 1
    ITERATOR2 = 1

    # Copy Images and Snaps
    timer = datetime.datetime.now()
    execute_command(
        "rbd cp {}/testimg{} {}/cptestimg".format(
            parameters["pool_name"]["pool1"]["val"],
            ITERATOR,
            parameters["pool_name"]["pool2"]["val"],
        )
    )

    execute_command(
        "rbd cp {}/testimg{}@snapimg{} {}/cpsnapimg".format(
            parameters["pool_name"]["pool1"]["val"],
            ITERATOR,
            ITERATOR2,
            parameters["pool_name"]["pool2"]["val"],
        )
    )
    print "Execution time for Copying Images & Snaps : " + str(
        datetime.datetime.now() - timer
    )

    # Renaming Images
    timer = datetime.datetime.now()
    execute_command(
        "rbd mv {}/cptestimg {}/mvtestimg".format(
            parameters["pool_name"]["pool2"]["val"],
            parameters["pool_name"]["pool2"]["val"],
        )
    )
    print "Execution time for Renaming Images : " + str(datetime.datetime.now() - timer)

    # Image-meta set
    timer = datetime.datetime.now()
    for num in range(0, 2):
        execute_command(
            "rbd image-meta set {}/mvtestimg key{num} {num}".format(
                parameters["pool_name"]["pool2"]["val"], num=num
            )
        )
    print "Execution time for Setting Image-meta : " + str(
        datetime.datetime.now() - timer
    )

    # Image-meta list
    timer = datetime.datetime.now()
    execute_command(
        "rbd image-meta list {}/mvtestimg".format(
            parameters["pool_name"]["pool2"]["val"]
        )
    )
    print "Execution time for Listing Image-meta : " + str(
        datetime.datetime.now() - timer
    )

    # Image-meta get
    timer = datetime.datetime.now()
    for num in range(0, 2):
        execute_command(
            "rbd image-meta get {}/mvtestimg key{}".format(
                parameters["pool_name"]["pool2"]["val"], num
            )
        )
    print "Execution time for Getting Image-meta : " + str(
        datetime.datetime.now() - timer
    )

    # Image-meta Removing
    timer = datetime.datetime.now()
    for num in range(0, 2):
        execute_command(
            "rbd image-meta remove {}/mvtestimg key{}".format(
                parameters["pool_name"]["pool2"]["val"], num
            )
        )
    print "Execution time for Removing Image-meta : " + str(
        datetime.datetime.now() - timer
    )

    # Listing Images and Snapshots In the Pool
    timer = datetime.datetime.now()
    for k, v in parameters["pool_name"].iteritems():
        execute_command("rbd ls -l {}".format(parameters["pool_name"][k]["val"]))
    print "Execution time for Listing Images & Snaps in the pool : " + str(
        datetime.datetime.now() - timer
    )

    # Listing Snap of Images
    timer = datetime.datetime.now()
    execute_command(
        "rbd snap ls {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    print "Execution time for Listing Snaps of a Image: " + str(
        datetime.datetime.now() - timer
    )

    # Bench
    timer = datetime.datetime.now()
    execute_command(
        "rbd create -s 10G {}/testbench".format(parameters["pool_name"]["pool1"]["val"])
    )
    for k, v in parameters["io_type_parameters"].iteritems():
        for k1, v1 in parameters["io_size_parameters"].iteritems():
            for k2, v2 in parameters["io_threads_parameters"].iteritems():
                for k3, v3 in parameters["io_total_parameters"].iteritems():
                    for k4, v4 in parameters["io_pattern_parameters"].iteritems():
                        if "version 10" in ceph_version:
                            execute_command(
                                "rbd bench-{} {} {} {} {} {} {} {} {} {}/testbench".format(
                                    v["val"],
                                    v1["arg"],
                                    v1["val"],
                                    v2["arg"],
                                    v2["val"],
                                    v3["arg"],
                                    v3["val"],
                                    v4["arg"],
                                    v4["val"],
                                    parameters["pool_name"]["pool1"]["val"],
                                )
                            )
                        elif "version 12" in ceph_version:

                            execute_command(
                                "rbd bench {} {} {} {} {} {} {} {} {} {} {}/testbench".format(
                                    v["arg"],
                                    v["val"],
                                    v1["arg"],
                                    v1["val"],
                                    v2["arg"],
                                    v2["val"],
                                    v3["arg"],
                                    v3["val"],
                                    v4["arg"],
                                    v4["val"],
                                    parameters["pool_name"]["pool1"]["val"],
                                )
                            )
    print "Execution time for Bench : " + str(datetime.datetime.now() - timer)

    sleep(10)

    # Image Rollback
    timer = datetime.datetime.now()
    execute_command(
        "rbd snap rollback {}/testimg{}@snapimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
        )
    )
    print "Execution time for Image Rollback : " + str(datetime.datetime.now() - timer)

    # Snap Protection
    timer = datetime.datetime.now()
    execute_command(
        "rbd snap protect {}/testimg{}@snapimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
        )
    )
    execute_command(
        "rbd snap protect {}/testimg{}@snapimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR - 1, ITERATOR2
        )
    )
    print "Execution time for Snap Protection : " + str(datetime.datetime.now() - timer)

    # Cloning
    timer = datetime.datetime.now()
    for k1, v1 in parameters["object_size_parameters"].iteritems():
        for k2, v2 in parameters["stripe_parameters"].iteritems():
            for k3, v3 in parameters["image_feature_parameters"].iteritems():
                for k4, v4 in parameters["image_shared_parameters"].iteritems():
                    if " " in v2["stripe-unit"]["arg"]:
                        if "striping" in k3:
                            continue

                    if k3 == "null" or k3 == "layering":
                        FEATUREVAR = ""

                    else:
                        FEATUREVAR = "layering,"

                    if k1 != k2:
                        continue

                    else:
                        if 15 < ITERATOR3 < 17:
                            ITERATOR -= 1

                        execute_command(
                            "rbd clone {} {} {} {} {} {} {} {} {} {}/testimg{}@snapimg{} {}/clonetestimg{}".format(
                                v1["arg"],
                                v1["val"],
                                v2["stripe-unit"]["arg"],
                                v2["stripe-unit"]["val"],
                                v2["stripe-count"]["arg"],
                                v2["stripe-count"]["val"],
                                v3["arg"],
                                FEATUREVAR + v3["val"],
                                v4["arg"],
                                parameters["pool_name"]["pool1"]["val"],
                                ITERATOR,
                                ITERATOR2,
                                parameters["pool_name"]["pool1"]["val"],
                                ITERATOR3,
                            )
                        )

                        ITERATOR3 += 1

    print "Execution time for Cloning : " + str(datetime.datetime.now() - timer)

    # Listing Clones
    timer = datetime.datetime.now()
    for _ in range(0, 2):
        for ITERATOR2 in range(1, 4):
            execute_command(
                "rbd children {}/testimg{}@snapimg{}".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
                )
            )
        ITERATOR += 1
    print "Execution time for Listing Clones of Snaps : " + str(
        datetime.datetime.now() - timer
    )

    ITERATOR -= 1
    ITERATOR2 = 1

    # Making child independent of the parent
    timer = datetime.datetime.now()
    for k in range(1, 16):
        execute_command(
            "rbd flatten {}/clonetestimg{}".format(
                parameters["pool_name"]["pool1"]["val"], k
            )
        )
    print "Execution time for Flatten Images : " + str(datetime.datetime.now() - timer)

    # Snap Unprotect
    timer = datetime.datetime.now()
    execute_command(
        "rbd snap unprotect {}/testimg{}@snapimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
        )
    )
    print "Execution time for Unprotecting snap : " + str(
        datetime.datetime.now() - timer
    )

    if "version 12" in ceph_version:
        # Setting limit for number of snapshots
        timer = datetime.datetime.now()
        execute_command(
            "rbd snap limit set {} {} {}/testimg{}".format(
                parameters["limit_parameters"]["arg"],
                parameters["limit_parameters"]["val"],
                parameters["pool_name"]["pool1"]["val"],
                ITERATOR,
            )
        )
        print "Execution time for setting limit for number of snapshots : " + str(
            datetime.datetime.now() - timer
        )

        # Remove previous limit for number of snapshots
        timer = datetime.datetime.now()
        execute_command(
            "rbd snap limit clear {}/testimg{}".format(
                parameters["pool_name"]["pool1"]["val"], ITERATOR
            )
        )
        print "Execution time for Removing the limit previously set : " + str(
            datetime.datetime.now() - timer
        )

    # Image or Snap Info
    timer = datetime.datetime.now()
    execute_command(
        "rbd info {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    execute_command(
        "rbd info {}/testimg{}@snapimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
        )
    )
    print "Execution time for showing image/snap info : " + str(
        datetime.datetime.now() - timer
    )

    # Image Status
    timer = datetime.datetime.now()
    execute_command(
        "rbd status {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    print "Execution time for Image Status : " + str(datetime.datetime.now() - timer)

    # Disk Usage
    timer = datetime.datetime.now()
    execute_command(
        "rbd du {} {}".format(
            parameters["pool_name"]["pool2"]["arg"],
            parameters["pool_name"]["pool2"]["val"],
        )
    )
    execute_command(
        "rbd du {} {} {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["arg"],
            parameters["pool_name"]["pool1"]["val"],
            parameters["pool_name"]["pool1"]["val"],
            ITERATOR,
        )
    )
    execute_command(
        "rbd du {}/testimg{}@snapimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR, ITERATOR2
        )
    )
    print "Execution time for Disk usage : " + str(datetime.datetime.now() - timer)

    # Snap Rename
    timer = datetime.datetime.now()
    execute_command(
        "rbd snap rename {}/testimg{}@snapimg{} {}/testimg{}@snapimgrenamed".format(
            parameters["pool_name"]["pool1"]["val"],
            ITERATOR,
            ITERATOR2,
            parameters["pool_name"]["pool1"]["val"],
            ITERATOR,
        )
    )
    print "Execution time for Snap Rename : " + str(datetime.datetime.now() - timer)

    # Snap Deletion
    timer = datetime.datetime.now()
    execute_command(
        "rbd snap rm {}/testimg{}@snapimgrenamed".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    execute_command(
        "rbd snap purge {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    print "Execution time for Snap deletion : " + str(datetime.datetime.now() - timer)

    # Add Lock
    timer = datetime.datetime.now()
    execute_command(
        "rbd lock add {}/testimg{} 007".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    ITERATOR -= 1

    for lock_id in range(0, 2):
        execute_command(
            "rbd lock add --shared tag {}/testimg{} {}".format(
                parameters["pool_name"]["pool1"]["val"], ITERATOR, lock_id
            )
        )
    print "Execution time for Adding Lock : " + str(datetime.datetime.now() - timer)

    # List Lock
    timer = datetime.datetime.now()
    execute_command(
        "rbd lock list {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    ITERATOR += 1
    execute_command(
        "rbd lock list {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    print "Execution time for List locked Images : " + str(
        datetime.datetime.now() - timer
    )

    # Remove Lock
    timer = datetime.datetime.now()
    for _ in range(0, 2):
        json_output = json.loads(
            execute_command(
                "rbd lock list {}/testimg{} --format=json".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR
                ),
                return_output=True,
            )
        )
        for k, v in json_output.iteritems():
            execute_command(
                "rbd lock remove {}/testimg{} {} {}".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR, k, v["locker"]
                )
            )
        ITERATOR -= 1
    print "Execution time for Removing Lock : " + str(datetime.datetime.now() - timer)

    # Mapping Images to block-device
    timer = datetime.datetime.now()
    ITERATOR += 3
    if "ubuntu" in execute_command("lsb_release -is", return_output=True).lower():
        execute_command("ceph osd crush tunables hammer")
    execute_command(
        "rbd create -s 5G --image-feature layering {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    execute_command(
        "rbd snap create {}/testimg{}@snapmapimg".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )

    execute_command(
        "rbd map {}/testimg{}".format(parameters["pool_name"]["pool1"]["val"], ITERATOR)
    )
    execute_command(
        "rbd map --read-only {}/testimg{}@snapmapimg".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    print "Execution time for Mapping Images : " + str(datetime.datetime.now() - timer)

    # Listing Mapped Images
    timer = datetime.datetime.now()
    execute_command("rbd showmapped")
    print "Execution time for Listing Mapped Images : " + str(
        datetime.datetime.now() - timer
    )

    # Unmap Images
    timer = datetime.datetime.now()
    execute_command(
        "rbd unmap {}/testimg{}".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    execute_command(
        "rbd unmap {}/testimg{}@snapmapimg".format(
            parameters["pool_name"]["pool1"]["val"], ITERATOR
        )
    )
    print "Execution time for Unmapping Images : " + str(
        datetime.datetime.now() - timer
    )

    if "version 12" in ceph_version:
        # Moving Image to trash
        timer = datetime.datetime.now()
        for _ in range(0, 11):
            execute_command(
                "rbd trash mv {}/testimg{}".format(
                    parameters["pool_name"]["pool1"]["val"], ITERATOR
                )
            )
            ITERATOR -= 1
        execute_command(
            "rbd trash mv {}/cpsnapimg".format(parameters["pool_name"]["pool2"]["val"])
        )
        print "Execution time for moving image to trash : " + str(
            datetime.datetime.now() - timer
        )

        # Listing trash entries
        timer = datetime.datetime.now()
        execute_command(
            "rbd trash ls {}".format(parameters["pool_name"]["pool1"]["val"])
        )
        print "Execution time for listing trash entries : " + str(
            datetime.datetime.now() - timer
        )

        #  Restoring image from trash
        timer = datetime.datetime.now()
        json_output = json.loads(
            execute_command(
                "rbd trash ls {} --format=json".format(
                    parameters["pool_name"]["pool1"]["val"]
                ),
                return_output=True,
            )
        )
        for num in range(0, 18, 2):
            execute_command(
                "rbd trash restore {}/{}".format(
                    parameters["pool_name"]["pool1"]["val"], json_output[num]
                )
            )
        print "Execution time for restoring trash entry : " + str(
            datetime.datetime.now() - timer
        )

        #  Removing image from trash
        timer = datetime.datetime.now()
        json_output = json.loads(
            execute_command(
                "rbd trash ls {} --format=json".format(
                    parameters["pool_name"]["pool2"]["val"]
                ),
                return_output=True,
            )
        )
        execute_command(
            "rbd trash rm {}/{}".format(
                parameters["pool_name"]["pool2"]["val"], json_output[0]
            )
        )
        print "Execution time for removing image from trash : " + str(
            datetime.datetime.now() - timer
        )

    # Deletion Of Pools
    timer = datetime.datetime.now()
    for k, v in parameters["pool_name"].iteritems():
        execute_command(
            "ceph osd pool delete {pool} {pool} --yes-i-really-really-mean-it".format(
                pool=v["val"]
            )
        )
    print "Execution time for Pool Deletion : " + str(datetime.datetime.now() - timer)

    print "Execution time for the script : " + str(datetime.datetime.now() - START)

    if FAILED_COUNT == 0:
        exit(0)
    else:
        print "Total Failed Commands: ", FAILED_COUNT
        print "{:-^21}".format("FAILED COMMANDS")
        for values in failed_commands:
            print values
        exit(1)
