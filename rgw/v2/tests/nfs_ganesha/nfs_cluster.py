"""
nfs_cluster - Test the new NFS cluster arch applicable from RHCS 5.1

Usage: nfs_cluster.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    nfs_cluster.yaml

Polarion Tests:
CEPH-83574597
CEPH-83574601
CEPH-83574600

Operation:
    Create a NFS cluster
    Create an user
    Create a bucket with user credentials
    Create a RGW export at user and bucket level
    Delete the cluster
"""

import argparse
import json
import logging
import math
import os
import subprocess
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from time import sleep

import v2.lib.resource_op as s3lib
from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, S3CommandExecError, TestExecError
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import nfs
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_info = s3lib.create_users(config.user_count)

    if config.test_ops.get("create_mount", False):
        log.info("Creating mount point")
        cmd = "sudo mkdir /mnt/nfs1"
        utils.exec_shell_cmd(cmd)
        cmd = "ceph nfs cluster info rgw-nfs"
        out = json.loads(utils.exec_shell_cmd(cmd))
        ip = out["rgw-nfs"]["backend"][0]["ip"]
        log.info(ip)
        cmd = f"mount -t nfs -o nfsvers=4,noauto,soft,sync,proto=tcp {ip}:/ /mnt/nfs1"
        err = utils.exec_shell_cmd(cmd, return_err=True)
        if err:
            raise AssertionError("Mount creation failed")

    else:
        # Create a NFS cluster without ingress
        rgw_host, _ = utils.get_hostname_ip(ssh_con)
        cluster_id = "rgw-nfs"
        cluster_info = nfs.create_nfs_cluster(cluster_id, rgw_host)
        sleep(5)
        # check cluster details
        cluster_info = utils.exec_shell_cmd(f"ceph nfs cluster info {cluster_id}")

        # If multi cluster scenario is defined
        if config.test_ops.get("multi_cluster", False):
            cluster_id2 = "rgw-nfs2"
            nfs.create_nfs_cluster(cluster_id2)
            utils.exec_shell_cmd(f"ceph nfs cluster info {cluster_id2}")

        # create user export for each user and bucket export for each bucket under
        if config.test_ops["create_user_export"]:
            for each_user in user_info:
                auth = Auth(each_user, ssh_con, ssl=config.ssl)
                rgw_conn = auth.do_auth()
                uid = each_user["user_id"]
                pseudo = f"/{uid}"
                export_type = "user"
                user_exp = nfs.create_nfs_export(cluster_id, pseudo, export_type, uid)
                if config.test_ops["create_bucket_export"]:
                    for bc in range(config.bucket_count):
                        bucket_name = utils.gen_bucket_name_from_userid(
                            each_user["user_id"], rand_no=bc
                        )
                        buck = reusable.create_bucket(bucket_name, rgw_conn, each_user)
                        pseudo_buck = f"/{bucket_name}"
                        export_type = "bucket"
                        buck_exp = nfs.create_nfs_export(
                            cluster_id, pseudo_buck, export_type, uid, bucket_name
                        )

        if config.test_ops.get("remove_export", False):
            nfs.remove_nfs_export(cluster_id)

        if config.test_ops["delete_cluster"]:
            for cluster in cluster_id, cluster_id2:
                nfs.remove_nfs_cluster(cluster)


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket and user rate limits")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW NFS cluster and export creation"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW NFS cluster and export creation"
        )
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = resource_op.Config(yaml_file)
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
