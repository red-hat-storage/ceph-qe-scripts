import json
import logging
import os
import random
import re
import subprocess
import threading
import time

import boto3
import v2.utils.utils as utils
from v2.lib.exceptions import SyncFailedError, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_accounts as accounts

log = logging.getLogger()


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def get_endpoint_elbencho():
    """Determines the appropriate endpoint for Elbencho based on HAProxy availability."""
    log.info("Checking HAProxy status")
    try:
        haproxy_status = utils.exec_shell_cmd("systemctl is-active haproxy")
        if haproxy_status.strip() == "active":
            log.info("HAProxy is active, retrieving hostname")
            hostname = utils.exec_shell_cmd("hostname -s").strip()
            return f"http://{hostname}:5000"
    except Exception as e:
        log.error(f"Failed to determine HAProxy status: {e}")
    return None


def get_remote_endpoint_elbencho():
    """Fetches the HAProxy-enabled hostname on the remote site."""
    try:
        remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
        stdin, stdout, stderr = remote_site_ssh_con.exec_command(
            "sudo ceph orch host ls"
        )
        cmd_output = stdout.read().decode()

        log.info(f"Remote site host list:\n{cmd_output}")

        for line in cmd_output.split("\n"):
            if "ha_io" in line:
                remote_hostname = line.split()[0]
                remote_endpoint = f"http://{remote_hostname}:5000"
                log.info(f"Remote endpoint determined: {remote_endpoint}")
                return remote_endpoint

    except Exception as e:
        log.error(f"Error fetching remote endpoint: {e}")

    return None


def install_elbencho(node_conn=None):
    """Installs Elbencho if it is not already installed."""
    log.info("Checking if Elbencho is already installed")
    try:
        output = utils.exec_shell_cmd("/usr/local/bin/elbencho --version", node_conn)
        if output:
            log.info("Elbencho is already installed.")
            return
    except Exception as e:
        log.warning(f"Error checking Elbencho version: {e}")

    log.info("Installing Elbencho...")
    cmds = [
        "wget https://github.com/breuner/elbencho/releases/download/v3.0-25/elbencho-static-x86_64.tar.gz",
        "tar -xf elbencho-static-x86_64.tar.gz",
        "sudo mv elbencho /usr/local/bin/",
        "sudo chmod +x /usr/local/bin/elbencho",
        "rm elbencho-static-x86_64.tar.gz",
    ]
    for cmd in cmds:
        result = utils.exec_shell_cmd(cmd, node_conn)
        if result is False:
            log.error(f"Command failed: {cmd}")
            raise TestExecError(f"Failed to install Elbencho. Command '{cmd}' failed.")
    log.info("Elbencho installation complete.")


def elbench_install_configure():
    """Installs and configures Elbencho on the client and remote node if applicable."""
    install_elbencho()
    if utils.is_cluster_multisite():
        log.info("Cluster is multisite, installing Elbencho on remote node")
        try:
            remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
            install_elbencho(remote_site_ssh_con)
        except Exception as e:
            log.error(f"Failed to install Elbencho on remote site: {e}")


def run_elbencho(
    endpoint, zone_name, num_objects, buckets, each_user, threads, object_size
):
    """Runs Elbencho with specified parameters."""
    log.info(
        f"[{zone_name}] Running Elbencho workload for {num_objects} objects on buckets {buckets}"
    )
    bucket_prefix = "-".join(buckets[0].split("-")[:-1]) + "-"
    num_buckets = len(buckets)
    bucket_format = f"{bucket_prefix}{{0..{num_buckets-1}}}"
    elbencho_cmd = (
        f"time /usr/local/bin/elbencho --s3endpoints {endpoint} --s3key {each_user['access_key']} --s3secret {each_user['secret_key']} "
        f"-w -t {threads} -n0 -N {num_objects} -s {object_size} {bucket_format}"
    )
    output = utils.exec_shell_cmd(elbencho_cmd)
    if output is False:
        log.error(f"Elbencho execution failed on {zone_name}")
        return
    metrics = parse_elbencho_output(output)
    log.info(f"[{zone_name}] Performance metrics: {metrics}")


def parse_elbencho_output(output):
    """Parses Elbencho output and extracts performance metrics."""
    log.info("Parsing Elbencho output")
    if not isinstance(output, str):
        log.error("Invalid output received from Elbencho command.")
        return {}
    metrics = {}
    lines = output.split("\n")
    for line in lines:
        if "Throughput MiB/s" in line:
            metrics["Throughput"] = line.split()[-1]
        elif "IOPS" in line:
            metrics["IOPS"] = line.split()[-1]
        elif "Total MiB" in line:
            metrics["Total Data Written (MiB)"] = line.split()[-1]
    return metrics


def verify_bucket_sync(buckets):
    """Checks bucket stats on both local and remote sites to verify sync consistency."""
    max_retries = 480  # Retry up to 480 times (4 hours)
    sleep_interval = 30  # Sleep interval in seconds
    start_time = time.time()  # Track start time

    for bucket in buckets:
        if "tenant" in bucket:
            tenant_name, bucket_short_name = bucket.split(".", 1)
            bucket = f"{tenant_name}/{bucket}"

            for attempt in range(1, max_retries + 1):

                # Fetch local bucket stats
                local_stats_output = utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {bucket}"
                )
                log.info(f"Raw local stats output for {bucket}: {local_stats_output}")

                # Extract JSON part from local stats
                local_json_match = re.search(r"\{.*\}", local_stats_output, re.DOTALL)
                local_stats = (
                    json.loads(local_json_match.group(0)) if local_json_match else None
                )

                # Fetch remote bucket stats
                remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
                stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                    f"radosgw-admin bucket stats --bucket {bucket}"
                )
                remote_stats_output = stdout.read().decode().strip()
                log.info(f"Raw remote stats output for {bucket}: {remote_stats_output}")

                # Extract JSON part from remote stats
                remote_json_match = re.search(r"\{.*\}", remote_stats_output, re.DOTALL)
                remote_stats = (
                    json.loads(remote_json_match.group(0))
                    if remote_json_match
                    else None
                )

                if not local_stats or not remote_stats:
                    raise SyncFailedError(
                        f"Failed to fetch valid JSON stats for bucket: {bucket}"
                    )

                # Compare num_objects and size_actual across sites
                if (
                    local_stats["usage"]["rgw.main"]["num_objects"]
                    != remote_stats["usage"]["rgw.main"]["num_objects"]
                ):
                    log.info(
                        f"Waiting for bucket sync for {bucket} in {attempt}, sleep for {sleep_interval} secs and retry"
                    )
                    time.sleep(sleep_interval)
                else:
                    log.info(
                        f"sync got consistent for {bucket} in {attempt} attempts with a sleep of {sleep_interval} secs ."
                    )
                    break  # No need to check further, already a mismatch
            if (attempt > max_retries) and (mismatched_buckets):
                raise SyncFailedError(
                    f"sync status is not consistent across sites for the bucket {bucket}"
                )
            else:
                log.info(f"sync is consistent for {bucket}")


def elbencho_run_put_workload(each_user, user_buckets, config):
    """Runs an Elbencho PUT workload on an RGW S3 user with parallel execution."""
    log.info("Starting Elbencho PUT workload")
    elbench_install_configure()
    objects_per_bucket = config.test_ops.get("objects_per_bucket")
    object_size = config.test_ops.get("object_size")
    threads = config.test_ops.get("threads")
    is_multisite = utils.is_cluster_multisite()
    local_endpoint = get_endpoint_elbencho()
    remote_endpoint = get_remote_endpoint_elbencho() if is_multisite else None
    log.info(
        f"the local endpoint is {local_endpoint} and the remote endpoint is {remote_endpoint}"
    )
    objects_per_site = objects_per_bucket // 2 if is_multisite else objects_per_bucket

    for version in range(config.test_ops.get("version_count", 1)):
        log.info(f"Running workload version {version + 1}")
        threads_list = []
        threads_list.append(
            threading.Thread(
                target=run_elbencho,
                args=(
                    local_endpoint,
                    "primary",
                    objects_per_site,
                    user_buckets,
                    each_user,
                    threads,
                    object_size,
                ),
            )
        )
        if is_multisite and remote_endpoint:
            threads_list.append(
                threading.Thread(
                    target=run_elbencho,
                    args=(
                        remote_endpoint,
                        "secondary",
                        objects_per_site,
                        user_buckets,
                        each_user,
                        threads,
                        object_size,
                    ),
                )
            )

        for t in threads_list:
            t.start()
        for t in threads_list:
            t.join()

    if config.test_ops.get("test_bucket_sync", False) is True:
        verify_bucket_sync(user_buckets)

    log.info("PUT workload completed.")
