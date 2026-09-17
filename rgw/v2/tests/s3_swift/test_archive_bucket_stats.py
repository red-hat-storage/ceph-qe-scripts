"""
test_archive_bucket_stats.py - Archive zone bucket stats after primary bucket delete

Usage: test_archive_bucket_stats.py -c <input_yaml>

<input_yaml>
    multisite_configs/test_archive_bucket_stats.yaml
    multisite_configs/test_archive_deleted_bucket_stats.yaml

Operation:
    Create an RGW user
    Create a bucket and upload objects from the primary site
    Verify object count via radosgw-admin bucket stats on primary
    If verify_remote_sites is set:
        Verify the bucket and object count on secondary and archive sites
    If delete_bucket is set:
        Delete the bucket from primary with radosgw-admin bucket rm --purge-objects
        Verify the bucket is removed on secondary
    If verify_archive_deleted_bucket is set:
        Verify a <bucket>-deleted-* bucket is created on archive
        Verify archive bucket stats contain archive_instance_mtime
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import subprocess
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None
SYNC_RETRY = 20
SYNC_DELAY = 30


def get_zone_ssh_con(zone_name, ssh_con=None):
    """
    Return an SSH connection to the given zone.
    Reuse ssh_con when the current cluster is that zone.
    """
    if zone_name == "primary" and utils.is_cluster_primary():
        log.info("Running on primary site")
        return ssh_con

    rgw_ip = utils.get_rgw_ip_zone(zone_name)
    if not rgw_ip:
        raise TestExecError(
            f"Could not resolve RGW IP for zone '{zone_name}'. "
            "This test requires primary, secondary, and archive sites."
        )
    log.info(f"Connecting to {zone_name} site at {rgw_ip}")
    return utils.connect_remote(rgw_ip)


def exec_on_site(ssh_con, cmd):
    """
    Run a command locally or over SSH. Return (stdout, stderr, returncode).
    """
    log.info(f"executing cmd: {cmd}")
    if ssh_con is None:
        pr = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
        )
        out, err = pr.communicate()
        log.info(out)
        if err:
            log.info(err)
        return out, err, pr.returncode

    stdin, stdout, stderr = ssh_con.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    rc = stdout.channel.recv_exit_status()
    log.info(out)
    if err:
        log.info(err)
    return out, err, rc


def parse_json_output(output, context):
    """Parse JSON from radosgw-admin output, skipping any leading log lines."""
    if not output or not str(output).strip():
        return None
    text = str(output).strip()
    for idx, char in enumerate(text):
        if char in ("{", "["):
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                break
    raise TestExecError(f"Failed to parse JSON for {context}: {text}")


def get_bucket_list(ssh_con):
    out, err, rc = exec_on_site(ssh_con, "radosgw-admin bucket list")
    if rc != 0:
        raise TestExecError(f"bucket list failed: {err or out}")
    bucket_list = parse_json_output(out, "bucket list")
    if bucket_list is None:
        raise TestExecError(f"bucket list failed: {err}")
    return bucket_list


def get_bucket_stats(ssh_con, bucket_name):
    out, err, rc = exec_on_site(
        ssh_con, f"radosgw-admin bucket stats --bucket {bucket_name}"
    )
    if rc != 0 or not out or not str(out).strip():
        log.info(f"bucket stats for {bucket_name} failed or empty. rc={rc} err={err}")
        return None
    try:
        return parse_json_output(out, f"bucket stats {bucket_name}")
    except TestExecError:
        log.info(f"bucket stats for {bucket_name} is not JSON: {out} {err}")
        return None


def get_num_objects(bucket_stats):
    return int(bucket_stats.get("usage", {}).get("rgw.main", {}).get("num_objects", 0))


def wait_for_condition(description, check_fn, retry=SYNC_RETRY, delay=SYNC_DELAY):
    """Retry check_fn until it returns a truthy value or raise TestExecError."""
    last_error = None
    for attempt in range(1, retry + 1):
        try:
            result = check_fn()
            if result:
                log.info(f"{description} succeeded on attempt {attempt}")
                return result
        except Exception as e:
            last_error = e
            log.info(f"{description} raised on attempt {attempt}: {e}")
        log.info(
            f"{description} not ready on attempt {attempt}/{retry}, "
            f"waiting {delay} seconds"
        )
        time.sleep(delay)
    if last_error:
        raise TestExecError(
            f"{description} failed after {retry} attempts: {last_error}"
        )
    raise TestExecError(f"{description} failed after {retry} attempts")


def verify_bucket_stats_on_site(ssh_con, zone_name, bucket_name, expected_objects):
    """
    Wait until bucket stats on the given site reports the expected object count.
    """

    def _check():
        stats = get_bucket_stats(ssh_con, bucket_name)
        if not stats:
            return False
        num_objects = get_num_objects(stats)
        log.info(
            f"{zone_name} site num_objects for {bucket_name}: {num_objects}, "
            f"expected: {expected_objects}"
        )
        if int(num_objects) != int(expected_objects):
            return False
        log.info(f"{zone_name} site bucket stats for {bucket_name}: {stats}")
        return stats

    return wait_for_condition(
        f"verify bucket {bucket_name} on {zone_name} with {expected_objects} objects",
        _check,
    )


def verify_bucket_absent_on_site(ssh_con, zone_name, bucket_name):
    """Wait until the bucket is no longer listed on the given site."""

    def _check():
        bucket_list = get_bucket_list(ssh_con)
        log.info(f"{zone_name} bucket list: {bucket_list}")
        if bucket_name in bucket_list:
            log.info(f"Bucket {bucket_name} still present on {zone_name}")
            return False
        stats = get_bucket_stats(ssh_con, bucket_name)
        if stats:
            log.info(f"Bucket stats still available for {bucket_name} on {zone_name}")
            return False
        log.info(f"Bucket {bucket_name} is removed on {zone_name}")
        return True

    wait_for_condition(
        f"verify bucket {bucket_name} is removed on {zone_name}",
        _check,
    )


def find_deleted_archive_bucket(ssh_con, bucket_name):
    """
    Archive zone renames a deleted bucket to <bucket>-deleted-<id>.
    Return the renamed bucket name when it appears.
    """
    deleted_prefix = f"{bucket_name}-deleted-"

    def _check():
        bucket_list = get_bucket_list(ssh_con)
        log.info(f"Archive site bucket list: {bucket_list}")
        deleted_buckets = [
            name for name in bucket_list if str(name).startswith(deleted_prefix)
        ]
        if not deleted_buckets:
            log.info(f"No archive bucket with prefix {deleted_prefix} found yet")
            return False
        log.info(f"Found archive deleted buckets: {deleted_buckets}")
        return deleted_buckets[0]

    return wait_for_condition(
        f"verify archive bucket with prefix {deleted_prefix}",
        _check,
    )


def verify_archive_instance_mtime(ssh_con, deleted_bucket_name):
    """
    Verify radosgw-admin bucket stats for the archive -deleted bucket
    contains the archive_instance_mtime key.
    """
    stats = get_bucket_stats(ssh_con, deleted_bucket_name)
    if not stats:
        raise TestExecError(
            f"bucket stats failed for archive deleted bucket {deleted_bucket_name}"
        )
    log.info(f"Archive site bucket stats for {deleted_bucket_name}: {stats}")
    if "archive_instance_mtime" not in stats:
        raise TestExecError(
            f"archive_instance_mtime key missing in bucket stats for "
            f"{deleted_bucket_name}. Stats keys: {list(stats.keys())}"
        )
    archive_instance_mtime = stats["archive_instance_mtime"]
    log.info(f"archive_instance_mtime: {archive_instance_mtime}")
    if archive_instance_mtime in (None, "", "0.000000", 0):
        raise TestExecError(
            f"archive_instance_mtime is empty or unset for {deleted_bucket_name}: "
            f"{archive_instance_mtime}"
        )
    log.info(
        f"Verified archive_instance_mtime on {deleted_bucket_name}: "
        f"{archive_instance_mtime}"
    )
    return archive_instance_mtime


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    if not utils.is_cluster_multisite():
        raise TestExecError(
            "This test requires a multisite cluster. Set up primary, secondary, "
            "and archive sites first."
        )

    if not utils.is_cluster_primary():
        raise TestExecError(
            "This test must run from the primary site to create a bucket and upload objects."
        )

    verify_remote_sites = config.test_ops.get("verify_remote_sites", False)
    delete_bucket = config.test_ops.get("delete_bucket", False)
    verify_archive_deleted_bucket = config.test_ops.get(
        "verify_archive_deleted_bucket", False
    )

    primary_ssh_con = get_zone_ssh_con("primary", ssh_con)
    secondary_ssh_con = None
    archive_ssh_con = None
    if verify_remote_sites or delete_bucket or verify_archive_deleted_bucket:
        secondary_ssh_con = get_zone_ssh_con("secondary")
        archive_ssh_con = get_zone_ssh_con("archive")
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(primary_ssh_con, config.ssl)

    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        auth = reusable.get_auth(each_user, primary_ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()

        log.info("no of buckets to create: %s" % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            log.info(f"Creating bucket {bucket_name_to_create} from primary site")
            bucket = reusable.create_bucket(
                bucket_name_to_create, rgw_conn, each_user, ip_and_port
            )

            log.info(
                f"Uploading {config.objects_count} objects to {bucket_name_to_create} from primary site"
            )
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info(f"Uploading object {s3_object_name} from primary site")
                reusable.upload_object(
                    s3_object_name, bucket, TEST_DATA_PATH, config, each_user
                )
                if config.local_file_delete is True:
                    utils.exec_shell_cmd("rm -rf %s" % s3_object_path)

            log.info("Verify bucket stats on primary after uploads")
            verify_bucket_stats_on_site(
                primary_ssh_con,
                "primary",
                bucket_name_to_create,
                config.objects_count,
            )

            if verify_remote_sites:
                log.info("Wait for multisite sync after object uploads")
                reusable.check_sync_status()

                log.info(f"Verify bucket {bucket_name_to_create} from secondary site")
                verify_bucket_stats_on_site(
                    secondary_ssh_con,
                    "secondary",
                    bucket_name_to_create,
                    config.objects_count,
                )

                log.info(f"Verify bucket {bucket_name_to_create} from archive site")
                verify_bucket_stats_on_site(
                    archive_ssh_con,
                    "archive",
                    bucket_name_to_create,
                    config.objects_count,
                )

            if delete_bucket:
                log.info(
                    f"Delete bucket {bucket_name_to_create} from primary with "
                    "radosgw-admin bucket rm --purge-objects"
                )
                rm_out, rm_err, rm_rc = exec_on_site(
                    primary_ssh_con,
                    f"radosgw-admin bucket rm --bucket={bucket_name_to_create} --purge-objects",
                )
                if rm_rc != 0:
                    raise TestExecError(
                        f"Failed to delete bucket {bucket_name_to_create} from primary: "
                        f"{rm_err or rm_out}"
                    )
                log.info(f"bucket rm output: {rm_out}")

                log.info("Wait for multisite sync after bucket delete")
                reusable.check_sync_status()

                log.info(
                    f"Verify bucket {bucket_name_to_create} is removed on secondary"
                )
                verify_bucket_absent_on_site(
                    secondary_ssh_con, "secondary", bucket_name_to_create
                )

            if verify_archive_deleted_bucket:
                log.info(
                    f"Verify {bucket_name_to_create}-deleted-* bucket is generated on archive"
                )
                deleted_bucket = find_deleted_archive_bucket(
                    archive_ssh_con, bucket_name_to_create
                )
                log.info(f"Archive deleted bucket name: {deleted_bucket}")

                log.info(
                    f"Verify archive_instance_mtime in bucket stats for {deleted_bucket}"
                )
                verify_archive_instance_mtime(archive_ssh_con, deleted_bucket)

        if config.user_remove:
            reusable.remove_user(each_user)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "archive bucket stats after primary bucket delete with archive_instance_mtime"
    )
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 Automation")
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
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
