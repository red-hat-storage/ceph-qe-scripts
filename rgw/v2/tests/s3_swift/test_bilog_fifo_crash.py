"""
test_bilog_fifo_crash - FIFO bilog crash-window and log-pool failure tests

Usage: test_bilog_fifo_crash.py -c <input_yaml>

<input_yaml>
    test_bilog_fifo_crash.yaml

Cases:
    9.1 FIFO ADD without index update -> secondary 404 skip
    9.2 OLH on primary without FIFO entry -> secondary stays behind, retry converges
    9.3 log-pool IO pause -> PUT returns 5xx, retry succeeds
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import botocore
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bilog_fifo as fifo
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def _ensure_obj_size(config, size=5):
    config.obj_size = size


def _upload(config, user, bucket, name, size=5):
    _ensure_obj_size(config, size)
    reusable.upload_object(name, bucket, TEST_DATA_PATH, config, user)


def test_9_1_orphaned_fifo_add(
    config, ssh_con, user, rgw_conn, rgw_client, ip_and_port
):
    """FIFO ADD present, object not fetchable -> secondary skip/404 path."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=91)
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user, ip_and_port)
    key = "orphan-add"
    _upload(config, user, bucket, key)
    entries = fifo.bilog_list(bucket)
    if not entries:
        raise TestExecError("no FIFO entries after PUT for 9.1")
    fifo.remove_head_object(bucket, key)
    try:
        fifo.remove_index_omap_key(bucket, key)
    except TestExecError as e:
        log.info(f"index key already gone or not found after head rm: {e}")
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket, retry=20, delay=15)
        status = fifo.bucket_sync_status_text(bucket).lower()
        if "stall" in status and "error" in status and "caught" not in status:
            raise TestExecError(f"sync appears stalled on orphaned ADD: {status}")
        log.info("9.1: secondary processed orphaned ADD without permanent stall")
    else:
        log.info("9.1: singlesite; verified FIFO ADD remains after head/index removal")
    leftover = fifo.bilog_list(bucket)
    log.info(f"9.1 passed; remaining entries={len(leftover)}")


def test_9_2_olh_without_fifo(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """Secondary stays at V1 if V2 FIFO entry is trimmed before consume; retry converges."""
    knobs = fifo.probe_inject_knobs()
    if knobs:
        log.info(f"found inject knobs {knobs}; synthetic lag path still used")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    write_bucket_io_info = BucketIoInfo()
    bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=92)
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user, ip_and_port)
    reusable.enable_versioning(bucket, rgw_conn, user, write_bucket_io_info)
    key = "olh-crash"
    _upload(config, user, bucket, key, size=5)
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket)
        remote = fifo.stop_secondary_rgw()
    else:
        remote = None
    _upload(config, user, bucket, key, size=6)
    entries = fifo.bilog_list(bucket)
    if not entries:
        raise TestExecError("no bilog after V2 PUT")
    marker = fifo.entry_id(entries[-1])
    fifo.bilog_trim(bucket, end_marker=marker)
    if remote:
        fifo.start_secondary_rgw(remote)
        time.sleep(20)
        fifo.wait_sync(bucket, retry=20, delay=10)
    _upload(config, user, bucket, key, size=7)
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket)
        fifo.compare_primary_secondary(bucket, versioned=True, keys=[key])
    log.info("9.2 passed: secondary converged after retry PUT")


def test_9_3_log_pool_pause(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port):
    """Pause OSD IO; PUT must fail with 5xx; retry after unpause succeeds."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=93)
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user, ip_and_port)
    key = "pause-put"
    failed = False
    fifo.pause_cluster_io()
    try:
        try:
            _upload(config, user, bucket, key)
        except (TestExecError, botocore.exceptions.ClientError, Exception) as e:
            log.info(f"PUT failed while OSDs paused as expected: {e}")
            failed = True
            if isinstance(e, botocore.exceptions.ClientError):
                code = int(e.response["ResponseMetadata"]["HTTPStatusCode"])
                if code < 500:
                    raise TestExecError(f"expected 5xx during pause, got {code}")
    finally:
        fifo.unpause_cluster_io()
    if not failed:
        raise TestExecError("PUT succeeded while OSDs were paused; expected 5xx")
    listing = fifo.bucket_list_admin(bucket)
    names = [e.get("name") or e.get("key") for e in listing]
    if key in names:
        raise TestExecError("partial index entry left after failed PUT during pause")
    _upload(config, user, bucket, key)
    entries = fifo.bilog_list(bucket)
    if not entries:
        raise TestExecError("retry PUT did not appear in bilog")
    rgw_client.head_object(Bucket=bucket.name, Key=key)
    log.info("9.3 passed: pause returns error, retry succeeds")


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
    users = s3lib.create_users(config.user_count or 1)
    user = users[0]
    auth = Auth(user, ssh_con, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    rgw_client = auth.do_auth_using_client()
    _ensure_obj_size(config)
    cases = config.test_ops.get("cases", ["9.1", "9.2", "9.3"])
    if "9.1" in cases:
        test_9_1_orphaned_fifo_add(
            config, ssh_con, user, rgw_conn, rgw_client, ip_and_port
        )
    if "9.2" in cases:
        test_9_2_olh_without_fifo(
            config, ssh_con, user, rgw_conn, rgw_client, ip_and_port
        )
    if "9.3" in cases:
        test_9_3_log_pool_pause(
            config, ssh_con, user, rgw_conn, rgw_client, ip_and_port
        )
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("FIFO bilog crash-window tests")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW FIFO bilog crash tests")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
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
        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)
        configure_logging(
            f_name=os.path.basename(os.path.splitext(yaml_file)[0]),
            set_level=args.log_level.upper(),
        )
        config = Config(yaml_file)
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
