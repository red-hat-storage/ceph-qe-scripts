"""
test_large_omap - Test large omap operation on cluster

Usage: test_large_omap.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_large_omap_clearance_green_field.yaml
    configs/test_large_omap_clearance_brown_field_pre_upgrade.yaml
    configs/test_large_omap_clearance_brown_field_post_upgrade.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload a file to bucket
    perform deep scrub of index pool
    check large omap warning observed in ceph status
    Delete all buckets in cluster
    perform deep scrub of index pool
    check large omap warning not observed in ceph status
"""

import argparse
import datetime
import json
import logging
import os
import socket
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()


def check_large_omap_in_cluster():
    log.info("check cluster health for large_omap warnings")
    health_detail = utils.exec_shell_cmd(["ceph health detail"])
    log.info(health_detail)
    large_omap_warn = False
    if "large omap" in health_detail or "LARGE_OMAP_OBJECTS" in health_detail:
        large_omap_warn = True
    return large_omap_warn


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_bucket_io_info = BucketIoInfo()
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    rgw_service_port = reusable.get_rgw_service_port()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    if config.haproxy and rgw_service_port != 443:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = 5000
        ip_and_port = f"{ip}:{port}"

    if config.test_ops.get("large_omap", False):
        log.info(
            f"create and clear omap in {config.test_ops['cluster_is']} environment"
        )
        out = utils.exec_shell_cmd("ceph df -f json")
        pools_data = json.loads(out)["pools"]
        pool_name = ""
        for pool in pools_data:
            if pool["name"].endswith("index"):
                pool_name = pool["name"]
                break
        if pool_name == "":
            raise AssertionError("Did not find index pool in the cluster")
        threshold = utils.exec_shell_cmd(
            "ceph config get osd osd_deep_scrub_large_omap_object_key_threshold"
        )
        log.info(
            f"cluster has osd_deep_scrub_large_omap_object_key_threshold as {threshold}"
        )
        osd_process = utils.exec_shell_cmd("ceph orch ls | grep osd")
        osd_process_name = osd_process.split()[0]

        if config.test_ops.get("create_omap", False):
            log.info(f"create omap in {config.test_ops['cluster_is']} environment")
            if int(threshold) != 10:
                utils.exec_shell_cmd(
                    "ceph config set osd osd_deep_scrub_large_omap_object_key_threshold 5"
                )
                # restart osd service
                utils.exec_shell_cmd(f"ceph orch restart {osd_process_name}")
                time.sleep(180)

            user_info = resource_op.create_users(
                no_of_users_to_create=config.user_count
            )
            s3_auth.do_auth(user_info[0], ip_and_port)
            auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
            rgw_conn = auth.do_auth()
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    user_info[0]["user_id"], rand_no=bc
                )
                s3cmd_reusable.create_bucket(bucket_name)
                log.info(f"Bucket {bucket_name} created")
                s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
                object_count = config.objects_count // 2

                log.info(f"uploading some large objects to bucket {bucket_name}")
                utils.exec_shell_cmd(f"fallocate -l 20m obj20m")
                for mobj in range(object_count):
                    utils.exec_shell_cmd(
                        f"{s3cmd_path} put obj20m s3://{bucket_name}/multipart-object-{mobj}"
                    )

                log.info(f"uploading some small objects to bucket {bucket_name}")
                utils.exec_shell_cmd(f"fallocate -l 4k obj4k")
                for sobj in range(object_count):
                    utils.exec_shell_cmd(
                        f"{s3cmd_path} put obj4k s3://{bucket_name}/small-object-{sobj}"
                    )

                bucket_stats_op = utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket={bucket_name}"
                )
                bucket_stats = json.loads(bucket_stats_op)
                if (
                    bucket_stats["usage"]["rgw.main"]["num_objects"]
                    != config.objects_count
                ):
                    raise AssertionError(
                        f"Expected object did not found in bucket {bucket_name}"
                    )

            large_omap_resp = check_large_omap_in_cluster()
            if not large_omap_resp:
                utils.exec_shell_cmd(f"ceph osd pool deep-scrub {pool_name}")
                time.sleep(30)
            log.info("check for large omap in cluster post deep scrub of index pool")
            large_omap_resp = check_large_omap_in_cluster()
            if not large_omap_resp:
                raise AssertionError(
                    "cluster health does not contain large omap warning"
                )
            log.info("cluster health has large omap warning")

        if config.test_ops.get("clear_omap", False):
            log.info(f"clear omap in {config.test_ops['cluster_is']} environment")
            large_omap_resp = check_large_omap_in_cluster()
            warn_large_omap = True
            if not large_omap_resp:
                log.info("perform deep scrub on index pool")
                utils.exec_shell_cmd(f"ceph osd pool deep-scrub {pool_name}")
                time.sleep(30)
                large_omap_resp = check_large_omap_in_cluster()
                if not large_omap_resp:
                    warn_large_omap = False
            if not warn_large_omap:
                raise AssertionError(
                    "cluster health does not contain large omap warning"
                )
            log.info("clear all buckets data from cluster")
            bucket_list = utils.exec_shell_cmd("radosgw-admin bucket list")
            bucket_list_json = json.loads(bucket_list)
            for bucket in bucket_list_json:
                log.info(f"removing bucket {bucket} and objects recides in it")
                cmd = f"radosgw-admin bucket rm --purge-data --bucket {bucket}"
                utils.exec_shell_cmd(cmd)
            list_bucket = utils.exec_shell_cmd("radosgw-admin bucket list")
            list_bucket_json = json.loads(list_bucket)
            if len(list_bucket_json) != 0:
                raise AssertionError(
                    f"buckets still exist in cluster {list_bucket_json}"
                )
            log.info("perform deep scrub on index pool to clear omap")
            utils.exec_shell_cmd(f"ceph osd pool deep-scrub {pool_name}")
            time.sleep(15)
            log.info("check cluster health for large_omap warnings")
            health_detail = utils.exec_shell_cmd(["ceph health detail"])
            log.info(health_detail)
            if "large omap" in health_detail or "LARGE_OMAP_OBJECTS" in health_detail:
                raise AssertionError("cluster health has large omap warning")

            utils.exec_shell_cmd(
                f"ceph config set osd osd_deep_scrub_large_omap_object_key_threshold 200000"
            )
            # restart osd service
            utils.exec_shell_cmd(f"ceph orch restart {osd_process_name}")
            time.sleep(180)
            utils.exec_shell_cmd(f"ceph osd pool deep-scrub {pool_name}")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("rgw test large omap")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW large omap")
        parser.add_argument("-c", dest="config", help="RGW Test large omap")
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
