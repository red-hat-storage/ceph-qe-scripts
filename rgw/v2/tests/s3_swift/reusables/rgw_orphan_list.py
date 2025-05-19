import json
import logging
import sys

import v2.utils.utils as utils

log = logging.getLogger()


def check_gc():
    """Checks RGW garbage collection and exits if orphans are found."""
    log.info("Running radosgw-admin gc process...")
    utils.exec_shell_cmd("radosgw-admin gc process --include-all")

    log.info("Running radosgw-admin gc list...")
    gc_list_output = utils.exec_shell_cmd("radosgw-admin gc list")
    try:
        gc_list = json.loads(gc_list_output)
        log.info(f"GC list: {gc_list}")
    except json.JSONDecodeError:
        log.error("Error decoding radosgw-admin gc list output. Invalid JSON.")
        sys.exit(1)
    if gc_list:
        log.error(
            "Error: RGW garbage collection list is not empty. Potential orphans found."
        )
        sys.exit(1)
    log.info("GC list is empty. No orphans found in GC.")


def check_orphan_data():
    """Checks for orphans in default.rgw.buckets.data and passes if no orphans or empty output."""
    log.info("Running rgw-orphan-list on default.rgw.buckets.data...")
    orphan_data_output = utils.exec_shell_cmd(
        "rgw-orphan-list default.rgw.buckets.data", return_err=True
    )
    log.info(
        f"Orphan data output: {orphan_data_output!r}"
    )  # Use !r for raw representation

    if orphan_data_output is not False:
        if (
            "0 potential orphans found" in orphan_data_output
            or "Empty file detected" in orphan_data_output
            or orphan_data_output.strip() == ""
        ):
            log.info("No orphans found in default.rgw.buckets.data.")
        else:
            log.error("Error: Potential orphans found in default.rgw.buckets.data.")
            log.error(f"Output: {orphan_data_output}")
            sys.exit(1)
    else:
        # Check stderr for "Empty file detected" even if command failed
        stderr_output = utils.exec_shell_cmd(
            "rgw-orphan-list default.rgw.buckets.data", return_err=True
        )
        if "Empty file detected" in stderr_output:
            log.info(
                "No orphans found in default.rgw.buckets.data (empty file reported)."
            )
        else:
            log.error(
                "Error running rgw-orphan-list on default.rgw.buckets.data. Check logs for details."
            )
            sys.exit(1)


def check_orphan_index():
    """Checks for orphans in default.rgw.buckets.index and validates bucket indexes."""
    log.info("Running rgw-orphan-list on default.rgw.buckets.index...")
    orphan_index_output = utils.exec_shell_cmd(
        "rgw-orphan-list default.rgw.buckets.index", return_err=True
    )
    log.info(
        f"Orphan index output: {orphan_index_output!r}"
    )  # Use !r for raw representation

    if orphan_index_output is not False:
        orphan_found = False
        if (
            "0 potential orphans found" not in orphan_index_output
            and "Empty file detected" not in orphan_index_output
            and orphan_index_output.strip() != ""
        ):
            log.warning(
                "Potential orphans found in default.rgw.buckets.index. Validating bucket indexes..."
            )
    else:
        log.info("No orphan indexes found.")
        return

    rados_ls_output = utils.exec_shell_cmd("rados ls --pool default.rgw.buckets.index")
    rados_ls_lines = rados_ls_output.splitlines()
    log.info(f"Rados ls output: {rados_ls_lines}")

    bucket_list_output = utils.exec_shell_cmd("radosgw-admin bucket list")
    try:
        bucket_list = json.loads(bucket_list_output)
        log.info(f"Bucket list: {bucket_list}")
    except json.JSONDecodeError:
        log.error("Error decoding radosgw-admin bucket list output. Invalid JSON.")
        sys.exit(1)

    for bucket_name in bucket_list:
        log.info(f"Checking bucket: {bucket_name}")
        bucket_stats_output = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket={bucket_name}"
        )
        try:
            bucket_stats = json.loads(bucket_stats_output)
            log.info(f"Bucket stats: {bucket_stats}")
        except json.JSONDecodeError:
            log.error(
                f"Error decoding radosgw-admin bucket stats output for bucket {bucket_name}. Invalid JSON."
            )
            continue

        try:
            num_shards = int(bucket_stats["num_shards"])
        except (ValueError, KeyError):
            log.error(
                f"Error: Could not determine num_shards for bucket {bucket_name}. Skipping validation."
            )
            continue

        bucket_id = bucket_stats["id"]
        actual_indexes = 0
        prefix = f".dir.{bucket_id}."
        found_indexes = []

        for line in rados_ls_lines:
            if line.startswith(prefix):
                actual_indexes += 1
                found_indexes.append(line)

        if num_shards == actual_indexes:
            log.info(
                f"Bucket {bucket_name} has the correct number of indexes ({actual_indexes})."
            )
        else:
            log.error(
                f"Error: Bucket {bucket_name} has an incorrect number of indexes. Expected {num_shards}, found {actual_indexes}."
            )
            log.error(f"Please check RGW configuration and logs for potential issues.")
            log.error(f"Found indexes: {found_indexes}")
            sys.exit(1)  # fail the test

    log.info("Bucket index validation completed.")
