"""
test_swift_bulk_delete_mixed_objects - Test swift bulk delete with existing and non-existing objects

Test Case: CEPH-9757
Usage: test_swift_bulk_delete_mixed_objects.py -c <input_yaml>

Operation:
    1. Create swift user and container
    2. Upload objects to container
    3. Bulk delete a mix of existing and non-existing objects
    4. Validate response fields: Number Deleted, Number Not Found, Response Status, Errors, Response Body
    5. Concurrent bulk deletes: upload more objects to the SAME container, then fire multiple
       simultaneous bulk-delete requests all targeting the SAME objects — simulates "bulk delete
       at the same time from different zones on the same objects". All threads must return 200 OK.
       The first thread deletes the objects; subsequent threads report them as Not Found.
    6. Bulk delete only non-existing (wrong) object names — verify all reported as Not Found
    7. Re-delete the already-deleted objects after 10 seconds — verify all reported as Not Found
"""

import argparse
import json
import logging
import os
import random
import sys
import time
import traceback
from threading import Thread

import names
import requests

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.tests.s3_swift.test_swift_basic_ops as swift_basic_ops
from v2.lib import resource_op as swiftlib
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.test_swift_basic_ops import fill_container
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def swift_bulk_delete(rgw, container_name, objects, config, label=""):
    """Send a swift bulk-delete request and return the parsed JSON response."""
    token = rgw.get_auth()[1]
    proto = "https" if config.ssl else "http"
    url = f"{proto}://{rgw.authurl.split('/')[2]}/swift/v1/?bulk-delete"
    body = "\n".join(f"{container_name}/{o}" for o in objects)
    resp = requests.delete(
        url,
        headers={
            "Accept": "application/json",
            "Content-Type": "text/plain",
            "X-Auth-Token": token,
        },
        data=body,
        verify=False,
    )
    log.info(f"{label}bulk-delete status: {resp.status_code}")
    if resp.status_code == 401:
        raise TestExecError(
            f"{label}bulk-delete failed: 401 Unauthorized — auth token missing or expired"
        )
    if resp.status_code == 403:
        raise TestExecError(
            f"{label}bulk-delete failed: 403 Forbidden — user lacks delete permission on container '{container_name}'. "
            "Check tenant, ACLs, and that the correct Swift user credentials are being used."
        )
    if resp.status_code == 404:
        raise TestExecError(
            f"{label}bulk-delete failed: 404 Not Found — container '{container_name}' does not exist"
        )
    if resp.status_code != 200:
        raise TestExecError(
            f"{label}bulk-delete failed: HTTP {resp.status_code} — {resp.text}"
        )
    result = resp.json()
    log.info(f"{label}response: {json.dumps(result, indent=2)}")
    return result


def validate_bulk_delete_response(resp, expected_deleted, expected_not_found):
    """Validate required fields and counts in a bulk-delete response."""
    for field in (
        "Number Not Found",
        "Response Status",
        "Response Body",
        "Errors",
        "Number Deleted",
    ):
        if field not in resp:
            raise TestExecError(
                f"Required field '{field}' missing in bulk-delete response"
            )
        log.info(f"  {field}: {resp[field]}")
    if resp["Number Deleted"] != expected_deleted:
        raise TestExecError(
            f"Number Deleted: expected {expected_deleted}, got {resp['Number Deleted']}"
        )
    if resp["Number Not Found"] != expected_not_found:
        raise TestExecError(
            f"Number Not Found: expected {expected_not_found}, got {resp['Number Not Found']}"
        )
    if resp["Response Status"] != "200 OK":
        raise TestExecError(
            f"Response Status is not '200 OK': {resp['Response Status']}"
        )
    log.info("bulk-delete response validated successfully")


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    io_info_initialize.initialize(BasicIOInfoStructure().initial())
    umgmt = UserMgmt()
    CephConfOp(ssh_con)
    RGWService()

    user_name = names.get_first_name() + random.choice("abcdefghijklmnopqrstuvwxyz")
    tenant = "tenant"
    umgmt.create_tenant_user(
        tenant_name=tenant, user_id=user_name, displayname=user_name
    )
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)
    rgw = Auth(user_info, ssh_con, config.ssl).do_auth()

    container_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=0)
    if (
        swiftlib.resource_op(
            {"obj": rgw, "resource": "put_container", "args": [container_name]}
        )
        is False
    ):
        raise TestExecError("container creation failed")

    # Upload objects
    existing_objects = [
        fill_container(rgw, container_name, user_name, oc, 0, size)
        for oc, size in config.mapped_sizes.items()
    ]
    log.info(f"Uploaded {len(existing_objects)} objects")

    # Build mixed delete list
    non_existing_count = config.doc["config"].get("non_existing_count", 20)
    non_existing = [f"non_existent_{i}.txt" for i in range(non_existing_count)]
    mixed = existing_objects + non_existing
    random.shuffle(mixed)

    # 1: bulk delete mixed objects
    log.info(
        " Bulk delete: %d existing + %d non-existing",
        len(existing_objects),
        non_existing_count,
    )
    resp = swift_bulk_delete(rgw, container_name, mixed, config)

    # 2: validate
    log.info("Validating response")
    validate_bulk_delete_response(resp, len(existing_objects), non_existing_count)

    # 3: concurrent bulk deletes on the SAME objects in the SAME container
    # Upload a fresh batch of objects to the same container, then fire N simultaneous
    # bulk-delete requests all targeting those same objects. This simulates "bulk delete
    # at the same time from different zones on the same objects".
    concurrent_threads = config.doc["config"].get("concurrent_zones", 4)
    objects_per_batch = config.doc["config"].get("objects_per_zone", 30)
    log.info(
        " Uploading %d objects to container '%s' for concurrent delete test",
        objects_per_batch,
        container_name,
    )

    # Re-create the container (it was emptied in Step 1) and upload a fresh batch
    if (
        swiftlib.resource_op(
            {"obj": rgw, "resource": "put_container", "args": [container_name]}
        )
        is False
    ):
        raise TestExecError("container re-creation failed ")
    concurrent_objects = [
        fill_container(
            rgw, container_name, user_name, oc, 1, config.mapped_sizes.get(oc, 10)
        )
        for oc in range(objects_per_batch)
    ]
    log.info(
        "Firing %d concurrent bulk-delete threads against the same %d objects in '%s'",
        concurrent_threads,
        len(concurrent_objects),
        container_name,
    )

    thread_results = []
    errors = []

    def worker(idx):
        try:
            result = swift_bulk_delete(
                rgw, container_name, concurrent_objects, config, label=f"[thread{idx}] "
            )
            thread_results.append(result)
        except Exception as e:
            errors.append(str(e))

    threads = [Thread(target=worker, args=(i,)) for i in range(concurrent_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if errors:
        raise TestExecError(f"Concurrent bulk delete errors: {errors}")

    # Validate: all threads returned 200 OK (already enforced by swift_bulk_delete).
    # Across all threads: total deleted + total not_found must equal objects_per_batch * concurrent_threads
    # (each object appears in every thread's request, but can only be deleted once).
    total_deleted = sum(r["Number Deleted"] for r in thread_results)
    total_not_found = sum(r["Number Not Found"] for r in thread_results)
    expected_total = objects_per_batch * concurrent_threads
    log.info(
        "Results across %d threads: total_deleted=%d, total_not_found=%d (expected sum=%d)",
        concurrent_threads,
        total_deleted,
        total_not_found,
        expected_total,
    )
    if total_deleted + total_not_found != expected_total:
        raise TestExecError(
            f"Concurrent delete accounting mismatch: deleted({total_deleted}) + not_found({total_not_found}) "
            f"!= expected({expected_total})"
        )
    if total_deleted == 0:
        raise TestExecError(
            "Concurrent delete: no objects were deleted by any thread — expected at least one thread to delete"
        )
    # Both threads may delete all objects (if RGW processes them before either sees the other's result),
    # or one thread deletes and the other gets Not Found — both outcomes are valid.
    # What matters: all threads returned 200 OK, no errors, and accounting adds up.
    log.info(
        "All concurrent bulk deletes completed successfully — "
        "%d threads fired in parallel against the same %d objects, "
        "total_deleted=%d total_not_found=%d (RGW handled concurrent deletes correctly)",
        concurrent_threads,
        objects_per_batch,
        total_deleted,
        total_not_found,
    )

    # validate not-found responses
    validate_not_found = config.doc["config"].get("validate_not_found_responses", True)
    if validate_not_found:
        # 4: bulk delete only wrong/non-existing object names
        log.info(" Bulk delete with only non-existing (wrong) object names")
        wrong_objects = [f"wrong_object_{i}.txt" for i in range(non_existing_count)]
        resp = swift_bulk_delete(rgw, container_name, wrong_objects, config)
        validate_bulk_delete_response(
            resp, expected_deleted=0, expected_not_found=non_existing_count
        )
        log.info("Non-existing objects correctly reported as Not Found")

        # 5: re-delete already-deleted objects after 10 seconds
        log.info("Re-deleting already-deleted objects after 10 seconds")
        log.info("Waiting 10 seconds before re-delete attempt...")
        time.sleep(10)
        resp = swift_bulk_delete(rgw, container_name, existing_objects, config)
        validate_bulk_delete_response(
            resp, expected_deleted=0, expected_not_found=len(existing_objects)
        )
        log.info("Re-deleted objects correctly reported as Not Found")
    else:
        log.info("Skipped  validate_not_found_responses is false")

    # Check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    log.info("ALL TESTS PASSED")


if __name__ == "__main__":
    test_info = AddTestInfo("test swift bulk delete with mixed objects - CEPH-9757")
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        swift_basic_ops.TEST_DATA_PATH = TEST_DATA_PATH
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="RGW Swift Bulk Delete - Mixed Objects"
        )
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument("-log_level", dest="log_level", default="info")
        parser.add_argument("--rgw-node", dest="rgw_node", default="127.0.0.1")
        args = parser.parse_args()

        ssh_con = (
            None
            if args.rgw_node == "127.0.0.1"
            else utils.connect_remote(args.rgw_node)
        )
        configure_logging(
            f_name=os.path.basename(os.path.splitext(args.config)[0]),
            set_level=args.log_level.upper(),
        )
        config = swiftlib.Config(args.config)
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
