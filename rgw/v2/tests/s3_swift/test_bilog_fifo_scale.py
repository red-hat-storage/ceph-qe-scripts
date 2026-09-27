"""
test_bilog_fifo_scale - FIFO bilog scale tests

Usage: test_bilog_fifo_scale.py -c <input_yaml>

<input_yaml>
    test_bilog_fifo_scale_throughput.yaml
    test_bilog_fifo_scale_sync.yaml
    test_bilog_fifo_scale_trim.yaml
    test_bilog_fifo_scale_reshard.yaml
    test_bilog_fifo_scale_multizone.yaml
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import threading
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bilog_fifo as fifo
from v2.tests.s3_swift.reusables import rgw_s3_elbencho as elbencho
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def _ensure_obj_size(config, size=5):
    config.obj_size = size


def _auth(config, ssh_con):
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
    users = s3lib.create_users(config.user_count or 1)
    user = users[0]
    auth = Auth(user, ssh_con, ssl=config.ssl)
    return user, auth.do_auth(), auth.do_auth_using_client(), ip_and_port, auth


def _create_bucket(config, user, rgw_conn, ip_and_port, suffix=0):
    name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=suffix)
    return reusable.create_bucket(name, rgw_conn, user, ip_and_port)


def _run_elbencho_or_puts(
    config,
    user,
    bucket,
    auth,
    num_objects,
    object_size="4k",
    threads=16,
):
    endpoint = auth.endpoint_url
    try:
        elbencho.run_elbencho(
            endpoint,
            "primary",
            num_objects,
            [bucket.name],
            user,
            threads,
            object_size,
        )
        return
    except Exception as e:
        log.info(f"elbencho unavailable or failed ({e}); falling back to boto PUTs")
    _ensure_obj_size(config, 5)
    for i in range(num_objects):
        reusable.upload_object(f"scale-{i}", bucket, TEST_DATA_PATH, config, user)


def _put_for_duration(config, user, bucket, duration_s, prefix, stop_event=None):
    """Upload objects until duration_s elapses. Returns count written."""
    _ensure_obj_size(config, 5)
    start = time.time()
    count = 0
    while time.time() - start < duration_s:
        if stop_event is not None and stop_event.is_set():
            break
        reusable.upload_object(
            f"{prefix}-{count}", bucket, TEST_DATA_PATH, config, user
        )
        count += 1
    log.info(f"wrote {count} objects in {duration_s}s prefix={prefix}")
    return count


def scenario_throughput(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port, auth):
    """S1 FIFO vs InIndex write load; record metrics, fail on FIFO push errors."""
    duration = config.test_ops.get("duration_seconds", 60)
    threads = config.test_ops.get("threads", 16)
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    fifo_bucket = _create_bucket(config, user, rgw_conn, ip_and_port, 1)
    t0 = time.time()
    fifo_count = _put_for_duration(config, user, fifo_bucket, duration, "fifo-load")
    fifo_elapsed = time.time() - t0
    fifo_ops = fifo_count / fifo_elapsed if fifo_elapsed else 0
    log.info(f"S1 FIFO throughput: {fifo_ops:.2f} ops/s over {fifo_elapsed:.1f}s")
    errors = fifo.scan_rgw_logs_for_fifo_errors()
    if errors:
        raise TestExecError(f"FIFO push errors in RGW logs: {errors}")

    fifo.set_bilog_type("inindex", ssh_con=ssh_con)
    inindex_bucket = _create_bucket(config, user, rgw_conn, ip_and_port, 2)
    t1 = time.time()
    in_count = _put_for_duration(config, user, inindex_bucket, duration, "inindex-load")
    in_elapsed = time.time() - t1
    in_ops = in_count / in_elapsed if in_elapsed else 0
    log.info(f"S1 InIndex throughput: {in_ops:.2f} ops/s over {in_elapsed:.1f}s")
    log.info(
        f"S1 measured FIFO={fifo_ops:.2f} ops/s vs InIndex={in_ops:.2f} ops/s "
        f"(threads={threads})"
    )


def scenario_large_sync(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port, auth):
    """S2.1 full sync of a large FIFO bucket; S2.2 incremental under writes."""
    if not utils.is_cluster_multisite():
        raise TestExecError("scale sync requires a 2-zone cluster")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_bucket(config, user, rgw_conn, ip_and_port, 1)
    n = int(config.test_ops.get("full_sync_objects", config.objects_count or 1000))
    t0 = time.time()
    _run_elbencho_or_puts(config, user, bucket, auth, n, object_size="4k")
    populate_s = time.time() - t0
    log.info(f"populated {n} objects in {populate_s:.1f}s")
    utils.exec_shell_cmd(f"radosgw-admin bucket sync init --bucket {bucket.name}")
    t1 = time.time()
    utils.exec_shell_cmd(f"radosgw-admin bucket sync run --bucket {bucket.name}")
    fifo.wait_sync(bucket, retry=80, delay=30)
    sync_s = time.time() - t1
    primary_n = fifo.object_count(bucket)
    log.info(f"S2.1 full sync of {primary_n} objects took {sync_s:.1f}s")

    stop = threading.Event()

    def writer():
        _put_for_duration(
            config,
            user,
            bucket,
            config.test_ops.get("incremental_seconds", 60),
            "incr",
            stop_event=stop,
        )

    thr = threading.Thread(target=writer)
    thr.start()
    thr.join()
    t2 = time.time()
    fifo.wait_sync(bucket, retry=80, delay=20)
    incr_s = time.time() - t2
    log.info(f"S2.2 incremental sync converged in {incr_s:.1f}s")


def scenario_trim_at_scale(
    config, ssh_con, user, rgw_conn, rgw_client, ip_and_port, auth
):
    """S3.1 log pool usage under write+autotrim; S3.2 lagging secondary."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_bucket(config, user, rgw_conn, ip_and_port, 1)
    duration = int(config.test_ops.get("trim_duration_seconds", 7200))
    sample_every = int(config.test_ops.get("sample_interval_seconds", 600))
    samples = []
    start = time.time()
    written = 0
    _ensure_obj_size(config, 5)
    next_sample = start
    while time.time() - start < duration:
        reusable.upload_object(f"trim-{written}", bucket, TEST_DATA_PATH, config, user)
        written += 1
        if written % 50 == 0:
            fifo.bilog_autotrim(bucket, times=1, delay=0)
        now = time.time()
        if now >= next_sample:
            used = fifo.get_log_pool_bytes_used()
            samples.append(used)
            log.info(f"log pool bytes_used={used} after {written} writes")
            next_sample = now + sample_every
    if (
        len(samples) >= 3
        and samples[-1] > samples[0] * 10
        and samples[-1] > samples[-2]
    ):
        log.info(f"log pool samples: {samples}")
        raise TestExecError("log pool usage grew monotonically; trim not catching up")
    log.info(f"S3.1 passed; samples={samples} writes={written}")

    if utils.is_cluster_multisite():
        for i in range(config.test_ops.get("pre_lag_objects", 100)):
            reusable.upload_object(f"prelag-{i}", bucket, TEST_DATA_PATH, config, user)
        fifo.wait_sync(bucket)
        remote = fifo.stop_secondary_rgw()
        for i in range(config.test_ops.get("lag_objects", 100)):
            reusable.upload_object(f"lag-{i}", bucket, TEST_DATA_PATH, config, user)
        fifo.bilog_autotrim(bucket, times=3, delay=2)
        fifo.start_secondary_rgw(remote)
        fifo.wait_sync(bucket, retry=60, delay=20)
        log.info("S3.2 passed: lagging secondary caught up after trim")


def scenario_reshard_at_scale(
    config, ssh_con, user, rgw_conn, rgw_client, ip_and_port, auth
):
    """S4.1 reshard  under writes; S4.2 fifo shard bounds across index sizes."""
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    n = int(config.test_ops.get("reshard_objects", config.objects_count or 1000))
    bucket = _create_bucket(config, user, rgw_conn, ip_and_port, 1)
    _run_elbencho_or_puts(config, user, bucket, auth, n, object_size="4k")
    stop = threading.Event()

    def bg():
        _put_for_duration(
            config,
            user,
            bucket,
            config.test_ops.get("reshard_write_seconds", 60),
            "during-reshard",
            stop_event=stop,
        )

    thr = threading.Thread(target=bg)
    thr.start()
    target = config.test_ops.get("reshard_shards", 128)
    try:
        fifo.reshard_bucket(bucket, target)
    finally:
        stop.set()
        thr.join()
    if utils.is_cluster_multisite():
        fifo.wait_sync(bucket, retry=60, delay=20)
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("crash during reshard-under-write")
    log.info("S4.1 passed: reshard under write completed")

    shard_counts = config.test_ops.get("index_shard_counts", [64, 256, 512, 1999])
    prev = None
    for idx, index_shards in enumerate(shard_counts):
        fifo.set_index_shard_count(index_shards, ssh_con=ssh_con)
        bkt = _create_bucket(config, user, rgw_conn, ip_and_port, 10 + idx)
        _ensure_obj_size(config, 5)
        reusable.upload_object("bound", bkt, TEST_DATA_PATH, config, user)
        layout = fifo.get_bucket_layout(bkt)
        fifo.assert_log_type(layout, "fifo")
        nshards = fifo.get_fifo_num_shards(layout)
        fifo.assert_fifo_shard_bounds(nshards)
        if index_shards >= 1999 and nshards > 21:
            raise TestExecError(f"fifo shards {nshards} > 21 for 1999 index shards")
        if prev is not None and nshards < prev:
            raise TestExecError(
                f"fifo shards shrank from {prev} to {nshards} as index grew"
            )
        prev = nshards
        log.info(f"S4.2 index={index_shards} fifo_shards={nshards}")
    log.info("S4.2 passed: fifo shard count bounded across index sizes")


def scenario_multizone(config, ssh_con, user, rgw_conn, rgw_client, ip_and_port, auth):
    """S5.1 concurrent writes both zones; S5.2 disconnect/reconnect under load."""
    if not utils.is_cluster_multisite():
        raise TestExecError("multizone stress requires active-active multisite")
    fifo.set_bilog_type("fifo", ssh_con=ssh_con)
    bucket = _create_bucket(config, user, rgw_conn, ip_and_port, 1)
    duration = int(config.test_ops.get("dual_write_seconds", 600))
    primary_n = {"n": 0}

    def primary_writer():
        primary_n["n"] = _put_for_duration(config, user, bucket, duration, "zone-a")

    secondary_ip = utils.get_rgw_ip(master_zone=False)
    sec_port = utils.get_radosgw_port_no()
    sec_auth = Auth(
        user,
        ssl=config.ssl,
        endpoint_ip=secondary_ip,
        endpoint_port=sec_port,
    )
    sec_conn = sec_auth.do_auth()
    sec_bucket = sec_conn.Bucket(bucket.name)
    sec_n = {"n": 0}

    def secondary_writer():
        _ensure_obj_size(config, 5)
        start = time.time()
        count = 0
        while time.time() - start < duration:
            reusable.upload_object(
                f"zone-b-{count}", sec_bucket, TEST_DATA_PATH, config, user
            )
            count += 1
        sec_n["n"] = count

    t_a = threading.Thread(target=primary_writer)
    t_b = threading.Thread(target=secondary_writer)
    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()
    fifo.wait_sync(bucket, retry=80, delay=20)
    total = primary_n["n"] + sec_n["n"]
    log.info(f"S5.1 wrote ~{total} objects from both zones; waiting to converge")
    fifo.compare_primary_secondary(bucket)
    log.info("S5.1 passed: both zones converged")

    stop = threading.Event()

    def load():
        _put_for_duration(
            config,
            user,
            bucket,
            config.test_ops.get("disconnect_window_seconds", 450),
            "disc",
            stop_event=stop,
        )

    thr = threading.Thread(target=load)
    thr.start()
    cycles = int(config.test_ops.get("disconnects", 5))
    down = int(config.test_ops.get("disconnect_seconds", 30))
    gap = int(config.test_ops.get("reconnect_seconds", 60))
    for i in range(cycles):
        log.info(f"S5.2 disconnect cycle {i + 1}/{cycles}")
        remote = fifo.stop_secondary_rgw()
        time.sleep(down)
        fifo.start_secondary_rgw(remote)
        time.sleep(gap)
    stop.set()
    thr.join()
    fifo.wait_sync(bucket, retry=80, delay=20)
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("RGW crash during disconnect stress")
    log.info("S5.2 passed: secondary recovered after repeated disconnects")


SCENARIOS = {
    "throughput": scenario_throughput,
    "large_sync": scenario_large_sync,
    "trim_at_scale": scenario_trim_at_scale,
    "reshard_at_scale": scenario_reshard_at_scale,
    "multizone": scenario_multizone,
}


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user, rgw_conn, rgw_client, ip_and_port, auth = _auth(config, ssh_con)
    scenario = config.test_ops.get("scenario")
    if scenario not in SCENARIOS:
        raise TestExecError(
            f"unknown test_ops.scenario={scenario}; expected {sorted(SCENARIOS)}"
        )
    log.info(f"running FIFO bilog scale scenario: {scenario}")
    SCENARIOS[scenario](config, ssh_con, user, rgw_conn, rgw_client, ip_and_port, auth)
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("FIFO bilog scale tests")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW FIFO bilog scale tests")
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
        if config.mapped_sizes is None and config.objects_count:
            config.mapped_sizes = utils.make_mapped_sizes(config)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
