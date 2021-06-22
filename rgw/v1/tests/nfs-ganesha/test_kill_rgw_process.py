import os
import sys
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import time

import v1.utils.log as log
from v1.lib.io_info import AddIOInfo
from v1.lib.nfs_ganesha.manage_data import BaseDir, SubdirAndObjects
from v1.lib.process_manage import Process
from v1.lib.s3.rgw import Authenticate
from v1.utils.test_desc import AddTestInfo

from .initialize import PrepNFSGanesha


def test(yaml_file_path):

    ganesha_test_config = {
        "mount_point": "ganesha-mount",
        "rgw_user_info": yaml_file_path,
    }

    verification = {"bucket": False, "key": False}

    log.info("ganesha_test_config :%s\n" % ganesha_test_config)

    io_config = {
        "base_dir_count": 2,
        "sub_dir_count": 2,
        "Files": {"files_in_dir": 2, "size": 10},
    }

    add_io_info = AddIOInfo()
    add_io_info.initialize()

    log.info("io_config: %s\n" % io_config)

    log.info("initiating nfs ganesha")

    nfs_ganesha = PrepNFSGanesha(
        mount_point=ganesha_test_config["mount_point"],
        yaml_fname=ganesha_test_config["rgw_user_info"],
    )

    nfs_ganesha.initialize()

    log.info("authenticating rgw user")

    rgw_auth = Authenticate(
        user_id=nfs_ganesha.user_id,
        access_key=nfs_ganesha.access_key,
        secret_key=nfs_ganesha.secret_key,
    )

    auth = rgw_auth.do_auth()

    log.info("begin IO")

    bdir = BaseDir(
        int(io_config["base_dir_count"]),
        rgw_auth.json_file_upload,
        ganesha_test_config["mount_point"],
        auth["conn"],
    )

    bdirs = bdir.create(uname=str(rgw_auth.user_id))

    subdir = SubdirAndObjects(bdirs, io_config, rgw_auth.json_file_upload, auth["conn"])

    sub_dir_creation = threading.Thread(target=subdir.create)  # adding this to thread

    sub_dir_creation.start()

    # kill RGW process

    log.info("killing rgw process")

    p = Process(name="radosgw")
    p.find()

    if p.process is None:
        log.info("process not running")
    else:
        log.info("killing the process")
        p.process.kill()

    sub_dir_creation.join()

    log.info("verification starts")

    time.sleep(15)

    bstatus = bdir.verify_s3()

    log.info("bucket verification complete")

    kstatus = subdir.verify_s3()

    log.info("key verification complete")

    verification = {}

    for bs in bstatus:

        if not bs["exists"]:
            verification["bucket"] = False
            break
        else:
            verification["bucket"] = True

    for ks in kstatus:

        if not ks["exists"]:
            verification["key"] = False

        if ks["type"] == "file":

            if not ks["md5_matched"]:
                verification["key"] = False
                break

            if not ks["size_matched"]:
                verification["key"] = False
                break
        else:
            verification["key"] = True

    return verification


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NFS Ganesha Automation")

    test_info = AddTestInfo("nfs ganesha basic IO test and verification on rgw")

    parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")

    args = parser.parse_args()

    yaml_file = args.config

    verified = test(yaml_file_path=yaml_file)
    log.info("verified status: %s" % verified)

    if not verified["bucket"] or not verified["key"]:
        test_info.failed_status("test failed")
        exit(1)

    else:
        test_info.success_status("bucket and keys consistency verifed")

    test_info.completed_info()
