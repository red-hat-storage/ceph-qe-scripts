"""
test_user_reset_stats_paged.py

``radosgw-admin user stats --reset-stats`` rebuilds the user header from the
bucket entries in the user's omap. Each ``reset_user_stats2`` cls call reads
at most 1000 entries. The client passes the stats accumulated so far, but
unfixed OSDs ignore them and write only the last page into the header.

Tracker: https://tracker.ceph.com/issues/81896
Fix: https://github.com/ceph/ceph/pull/72828

Usage: test_user_reset_stats_paged.py -c <input_yaml>

<input_yaml>
    configs/test_user_reset_stats_paged.yaml

Operation:
    1. Create a user and raise max-buckets (the default cap is 1000).
    2. Create 2500 buckets with one object in each.
    3. ``radosgw-admin user stats --uid=<user> --sync-stats``
       num_objects must be 2500.
    4. ``radosgw-admin user stats --uid=<user> --reset-stats``
       num_objects must be 2500.
       An unfixed build reports 500, the last page only.

Pass:
    Both commands report num_objects equal to the number of objects created.
"""

import argparse
import json
import logging
import os
import random
import shlex
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError, EndpointConnectionError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()

# cls_user.cc MAX_ENTRIES. reset_user_stats2 never returns more than this.
PAGE_SIZE = 1000
STATS_KEYS = ("num_objects", "size", "size_actual")
RETRYABLE_S3_CODES = {
    "SlowDown",
    "ServiceUnavailable",
    "RequestTimeout",
    "InternalError",
    "RequestTimeTooSkewed",
}


def _positive_int(value, name):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise TestExecError(f"{name} must be an integer, got {value!r}")
    if number < 1:
        raise TestExecError(f"{name} must be >= 1, got {number}")
    return number


def _last_page_objects(bucket_count, objects_per_bucket):
    """Object count an unfixed reset-stats keeps: the last cls page only."""
    last_buckets = bucket_count % PAGE_SIZE
    if last_buckets == 0:
        last_buckets = PAGE_SIZE
    return last_buckets * objects_per_bucket


def _exec_json(cmd):
    output = utils.exec_shell_cmd(cmd)
    if output is False:
        raise TestExecError(f"command failed: {cmd}")
    text = str(output).strip()
    if not text:
        raise TestExecError(f"command returned no output: {cmd}")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
        raise TestExecError(f"command did not return JSON: {cmd}\n{text[:1000]}")


def _stats_from_doc(doc):
    stats = doc.get("stats") if isinstance(doc, dict) else None
    if not isinstance(stats, dict):
        raise TestExecError(f"user stats output has no stats object: {doc}")
    picked = {}
    for key in STATS_KEYS:
        if key not in stats:
            raise TestExecError(f"user stats missing {key}: {stats}")
        picked[key] = int(stats[key])
    return picked


def _user_stats(uid, flag):
    cmd = f"radosgw-admin user stats --uid={shlex.quote(uid)} --{flag}"
    return _stats_from_doc(_exec_json(cmd))


def _set_max_buckets(uid, limit):
    """The default user cap is 1000, which is exactly one reset-stats page."""
    doc = _exec_json(
        f"radosgw-admin user modify --uid={shlex.quote(uid)} --max-buckets {limit}"
    )
    got = int(doc.get("max_buckets", -1))
    log.info("user %s max_buckets=%s", uid, got)
    # 0 means unlimited. A negative value disables bucket creation.
    if got < 0 or (got != 0 and got < limit):
        raise TestExecError(
            f"max-buckets for {uid} is {got}, need at least {limit} "
            f"to pass the {PAGE_SIZE}-bucket reset page"
        )


def _location_constraint():
    try:
        multisite = utils.is_cluster_multisite()
    except Exception as exc:
        log.info("could not tell if the cluster is multisite (%s)", exc)
        return None
    if not multisite:
        return None
    raw = utils.exec_shell_cmd("radosgw-admin zonegroup get")
    if raw is False:
        raise TestExecError("failed to read zonegroup for bucket location")
    name = json.loads(raw).get("name")
    if not name:
        raise TestExecError("zonegroup name missing from zonegroup get")
    log.info("multisite location constraint: %s", name)
    return name


def _s3_call(desc, fn):
    delay = 2
    last_error = None
    for attempt in range(1, 4):
        try:
            return fn()
        except (ClientError, EndpointConnectionError) as exc:
            last_error = exc
            code = ""
            status = 0
            if isinstance(exc, ClientError):
                code = exc.response.get("Error", {}).get("Code", "")
                status = exc.response.get("ResponseMetadata", {}).get(
                    "HTTPStatusCode", 0
                )
            retryable = (
                isinstance(exc, EndpointConnectionError)
                or status >= 500
                or code in RETRYABLE_S3_CODES
            )
            if not retryable or attempt == 3:
                raise TestExecError(f"{desc} failed: {code or exc}") from exc
            log.warning("%s failed (%s), retry %s/3", desc, code or exc, attempt)
            time.sleep(delay)
            delay *= 2
    raise TestExecError(f"{desc} failed: {last_error}")


def _fill(client, uid, bucket_count, objects_per_bucket, body, location):
    token = random.randint(1000, 9999)
    safe = "".join(ch for ch in uid.lower() if ch.isalnum())[:8] or "user"
    prefix = f"t81896-{safe}-{token}"
    started = time.time()
    for index in range(bucket_count):
        bucket_name = f"{prefix}-{index:04d}"
        kwargs = {"Bucket": bucket_name}
        if location:
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": location}

        def _create(kwargs=kwargs):
            return client.create_bucket(**kwargs)

        _s3_call(f"create bucket {bucket_name} ({index + 1}/{bucket_count})", _create)
        for obj_index in range(objects_per_bucket):
            key = f"obj-{obj_index}"

            def _put(bucket_name=bucket_name, key=key):
                return client.put_object(Bucket=bucket_name, Key=key, Body=body)

            _s3_call(f"put object {bucket_name}/{key}", _put)
        done = index + 1
        if done % 100 == 0 or done == bucket_count:
            log.info("created %s/%s buckets for %s", done, bucket_count, uid)
    log.info("created %s buckets in %.1f seconds", bucket_count, time.time() - started)


def _sync_until(uid, expected_objects, expected_size, attempts, delay):
    last = None
    for attempt in range(1, attempts + 1):
        last = _user_stats(uid, "sync-stats")
        log.info(
            "sync-stats attempt %s/%s num_objects=%s size=%s size_actual=%s",
            attempt,
            attempts,
            last["num_objects"],
            last["size"],
            last["size_actual"],
        )
        if last["num_objects"] == expected_objects and last["size"] == expected_size:
            log.info("PASS sync-stats num_objects=%s", expected_objects)
            return last
        if last["num_objects"] > expected_objects:
            break
        if attempt < attempts:
            time.sleep(delay)
    raise TestExecError(
        f"sync-stats num_objects={last['num_objects']} size={last['size']}, "
        f"expected num_objects={expected_objects} size={expected_size}. "
        "The buckets were not all visible before reset-stats."
    )


def _check_reset(got, expected_objects, baseline, bucket_count, objects_per_bucket):
    last_page = _last_page_objects(bucket_count, objects_per_bucket)
    problems = []
    if got["num_objects"] != expected_objects:
        problems.append(f"num_objects={got['num_objects']} expected {expected_objects}")
    for key in ("size", "size_actual"):
        if got[key] != baseline[key]:
            problems.append(f"{key}={got[key]} expected {baseline[key]}")
    if not problems:
        log.info("PASS reset-stats num_objects=%s", expected_objects)
        return
    detail = "; ".join(problems)
    if got["num_objects"] == last_page and last_page != expected_objects:
        detail += (
            f"; this is the last page only "
            f"({last_page} objects, page size {PAGE_SIZE}). "
            "cls_user_reset_stats2 ignored the accumulated stats"
        )
    raise TestExecError(
        f"reset-stats failed: {detail}. " "https://tracker.ceph.com/issues/81896"
    )


def _remove_user(user):
    out = reusable.remove_user(user)
    if out is False:
        raise TestExecError(f"failed to remove user {user['user_id']}")
    log.info("removed user %s", user["user_id"])


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    bucket_count = _positive_int(
        config.test_ops.get("bucket_count", config.bucket_count), "bucket_count"
    )
    objects_per_bucket = _positive_int(
        config.test_ops.get("objects_per_bucket", config.objects_count or 1),
        "objects_per_bucket",
    )
    object_size = int(config.test_ops.get("object_size", 1))
    if object_size < 0:
        raise TestExecError(f"object_size must be >= 0, got {object_size}")
    if bucket_count <= PAGE_SIZE:
        raise TestExecError(
            f"bucket_count must be greater than {PAGE_SIZE} so reset-stats "
            f"spans more than one cls call, got {bucket_count}"
        )

    expected_objects = bucket_count * objects_per_bucket
    expected_size = expected_objects * object_size
    last_page = _last_page_objects(bucket_count, objects_per_bucket)
    log.info(
        "creating %s buckets with %s object(s) each; "
        "sync-stats and reset-stats must report num_objects=%s "
        "(unfixed reset-stats reports %s)",
        bucket_count,
        objects_per_bucket,
        expected_objects,
        last_page,
    )

    user = None
    error = None
    try:
        created = s3lib.create_users(1)
        if not created or not created[0]:
            raise TestExecError("failed to create user")
        user = created[0]
        uid = user["user_id"]
        log.info("user: %s", uid)
        _set_max_buckets(uid, bucket_count)

        auth = reusable.get_auth(user, ssh_con, config.ssl, config.haproxy)
        client = auth.do_auth_using_client()
        _fill(
            client,
            uid,
            bucket_count,
            objects_per_bucket,
            b"x" * object_size,
            _location_constraint(),
        )

        attempts = _positive_int(
            config.test_ops.get("sync_attempts", 6), "sync_attempts"
        )
        delay = int(config.test_ops.get("sync_delay", 5))
        if delay < 0:
            raise TestExecError(f"sync_delay must be >= 0, got {delay}")
        baseline = _sync_until(uid, expected_objects, expected_size, attempts, delay)
        reset = _user_stats(uid, "reset-stats")
        log.info(
            "reset-stats num_objects=%s size=%s size_actual=%s",
            reset["num_objects"],
            reset["size"],
            reset["size_actual"],
        )
        _check_reset(
            reset,
            expected_objects,
            baseline,
            bucket_count,
            objects_per_bucket,
        )
    except Exception as exc:
        error = exc
        raise
    finally:
        if user and config.user_remove:
            try:
                _remove_user(user)
            except Exception as cleanup_error:
                log.error("cleanup failed: %s", cleanup_error)
                if error is None:
                    raise


if __name__ == "__main__":
    test_info = AddTestInfo("RGW user reset-stats keeps every bucket page")
    test_info.started_info()
    try:
        parser = argparse.ArgumentParser(
            description="RGW user stats --reset-stats across more than 1000 buckets"
        )
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
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
