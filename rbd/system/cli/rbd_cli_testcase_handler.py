import argparse
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import utils.log as log
import utils.utils

rbd_util = utils.utils.RbdUtils()


def mirror_image_enable():
    """
    CEPH-10247 - CLI Validation (+ve cases): rbd mirror image enable
    """
    log.info(
        "Executing CEPH-10247 - CLI Validation (+ve cases): rbd mirror image enable"
    )

    poolname = "mirror_image_enable"
    image_name = [f"ceph_10247_{i}" for i in range(3)]
    rbd_util.create_pool(poolname=poolname)
    for image in image_name:
        rbd_util.create_image(
            image_name=poolname + "/" + image, features="exclusive-lock,journaling"
        )

    rbd_util.exec_cmd(f"rbd mirror pool enable {poolname} image")
    base_cmd = "rbd mirror image enable "

    step_cmds = []
    step_cmds.append(base_cmd + f"{poolname}/{image_name[0]}")
    step_cmds.append(base_cmd + f"--pool {poolname} --image {image_name[1]}")
    step_cmds.append(base_cmd + f"-p {poolname} --image {image_name[2]}")

    for image, step in zip(image_name, step_cmds):
        if rbd_util.exec_cmd(step) == False:
            log.error(f"Test case failed executing: {step}")
            exit(1)
        if not rbd_util.exec_cmd(
            f'rbd info {poolname}/{image}|grep \\"mirroring state: enabled\\"'
        ):
            log.error(f"command not worked: {step}")
            exit(1)

    log.info("Test case Passed")


def mirror_pool_enable():
    """
    CEPH-10249 - CLI Validation (+ve cases): rbd mirror pool enable
    """
    log.info(
        "Executing CEPH-10249 - CLI Validation (+ve cases): rbd mirror pool enable"
    )
    poolname = "mirror_pool_enable"
    base_cmd = "rbd mirror pool enable"
    rbd_util.create_pool(poolname=poolname)

    step_cmds = []
    step_cmds.append(base_cmd + f" {poolname}")
    step_cmds.append(base_cmd + f" -p {poolname}")
    step_cmds.append(base_cmd + f" --pool {poolname}")

    for step in step_cmds:
        for mode in [" image", " pool"]:
            rbd_util.exec_cmd("rbd mirror pool disable {poolname}")
            if rbd_util.exec_cmd(step + mode) == False:
                log.error(f"Test case Failed executing: {step}{mode}")
                exit(1)
            if not rbd_util.exec_cmd(
                f'rbd mirror pool info {poolname}|grep \\"Mode:{mode}\\"'
            ):
                log.error(f"command not worked: {step}{mode}")
                exit(1)

    log.info("Test Case Passed")


def mirror_pool_disable():
    """
    CEPH-10250 - CLI Validation (+ve cases): rbd mirror pool disable
    """
    log.info(
        "Executing CEPH-10250 - CLI Validation (+ve cases): rbd mirror pool disable"
    )
    poolname = "mirror_pool_disable"
    base_cmd = "rbd mirror pool disable"
    rbd_util.create_pool(poolname=poolname)

    step_cmds = []
    step_cmds.append(base_cmd + f" {poolname}")
    step_cmds.append(base_cmd + f" -p {poolname}")
    step_cmds.append(base_cmd + f" --pool {poolname}")

    for step in step_cmds:
        rbd_util.exec_cmd(f"rbd mirror pool enable {poolname} pool")
        if rbd_util.exec_cmd(step) == False:
            log.error(f"Test case Failed executing: {step}")
            exit(1)
        if not rbd_util.exec_cmd(
            f'rbd mirror pool info {poolname}|grep \\"Mode: disabled\\"'
        ):
            log.error(f"command not worked: {step}")
            exit(1)

    log.info("Test Case Passed")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="RBD CLI Test")
    parser.add_argument("-e", "--ec-pool-k-m", required=False)
    parser.add_argument("--test-case", required=True)

    args = parser.parse_args()

    try:
        globals()[args.test_case]()
        rbd_util.delete_pool(poolname=args.test_case)
    except KeyError:
        log.error(f"{args.test_case} not yet implemented")
