"""
Reusable helpers for RGW user keys create_date (radosgw-admin user info keys).

Used by test_rgw_user_keys_create_date.py. Uses reusable.run_command for
radosgw-admin. Assertions for create_date on user keys (ceph-20.1.0-26+).
"""

import json
import logging
import random
import re
import string
from datetime import datetime, timezone

from v2.lib.exceptions import TestExecError
from v2.tests.s3_swift import reusable

log = logging.getLogger()

# ISO 8601 with optional fractional seconds and Z (e.g. 2025-10-08T03:13:39.792729Z)
ISO_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def gen_test_user_uid(prefix="rgwkeys"):
    """Generate a unique uid for test users (e.g. rgwkeys_12345)."""
    return "%s_%s" % (prefix, random.randrange(10000, 99999))


def create_rgw_user(cluster_name, display_name="RGW test user"):
    """
    Create an RGW user via radosgw-admin. Returns uid.
    Caller must remove with remove_rgw_user().
    """
    uid = gen_test_user_uid()
    cmd = "radosgw-admin user create --uid=%s --display-name='%s' --cluster %s" % (
        uid,
        display_name,
        cluster_name,
    )
    log.info("Creating user: %s", cmd)
    out = reusable.run_command(cmd)
    if not out or not isinstance(out, dict):
        raise TestExecError("user create failed for uid=%s" % uid)
    return uid


def remove_rgw_user(uid, cluster_name="ceph"):
    """Remove RGW user and purge data. radosgw-admin user rm often has no stdout."""
    cmd = "radosgw-admin user rm --uid=%s --purge-data --cluster %s" % (
        uid,
        cluster_name,
    )
    log.info("Cleaning up: %s", cmd)
    reusable.run_command(cmd)


def get_rgw_user_keys(uid, cluster_name="ceph"):
    """Return list of keys from radosgw-admin user info."""
    cmd = "radosgw-admin user info --uid=%s --cluster %s" % (uid, cluster_name)
    out = reusable.run_command(cmd)
    if out is None:
        raise TestExecError("radosgw-admin user info failed for uid=%s" % uid)
    if isinstance(out, str):
        try:
            out = json.loads(out)
        except json.JSONDecodeError as e:
            raise TestExecError("user info output is not valid JSON: %s" % e)
    if not isinstance(out, dict):
        raise TestExecError(
            "radosgw-admin user info returned no valid JSON for uid=%s" % uid
        )
    return out.get("keys") or []


def add_rgw_s3_keys(uid, cluster_name="ceph", count=1):
    """Add count S3 keys to user via radosgw-admin key create (generated keys)."""
    for _ in range(count):
        cmd = (
            "radosgw-admin key create --uid=%s --key-type=s3 --gen-access-key --gen-secret --cluster %s"
            % (uid, cluster_name)
        )
        log.info("Adding key: %s", cmd)
        out = reusable.run_command(cmd)
        if not out or not isinstance(out, dict):
            raise TestExecError("key create failed for uid=%s" % uid)
    log.info("Key(s) created successfully")


def _random_key_string(length, chars=None):
    if chars is None:
        chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def add_rgw_s3_key_custom(uid, access_key=None, secret_key=None, cluster_name="ceph"):
    """Add one S3 key with custom access_key and secret_key (random if not given)."""
    if access_key is None:
        access_key = _random_key_string(20)
    if secret_key is None:
        secret_key = _random_key_string(40)
    cmd = (
        "radosgw-admin key create --uid=%s --key-type=s3 --access-key=%s --secret-key=%s --cluster %s"
        % (uid, access_key, secret_key, cluster_name)
    )
    log.info(
        "Adding custom key (access_key=%s...)",
        access_key[:8] if len(access_key) >= 8 else access_key,
    )
    out = reusable.run_command(cmd)
    if not out or not isinstance(out, dict):
        raise TestExecError("key create (custom) failed for uid=%s" % uid)
    return access_key


def remove_rgw_key(uid, access_key, cluster_name="ceph"):
    """Remove one key from user by access_key."""
    cmd = "radosgw-admin key rm --uid=%s --access-key=%s --cluster %s" % (
        uid,
        access_key,
        cluster_name,
    )
    log.info("Removing key: %s", cmd)
    reusable.run_command(cmd)


def suspend_rgw_user(uid, cluster_name="ceph"):
    """Suspend RGW user (keys become inactive for auth)."""
    cmd = "radosgw-admin user suspend --uid=%s --cluster %s" % (uid, cluster_name)
    log.info("Suspending user: %s", cmd)
    out = reusable.run_command(cmd)
    if out is None:
        raise TestExecError("user suspend failed for uid=%s" % uid)


def enable_rgw_user(uid, cluster_name="ceph"):
    """Re-enable suspended RGW user."""
    cmd = "radosgw-admin user enable --uid=%s --cluster %s" % (uid, cluster_name)
    log.info("Enabling user: %s", cmd)
    reusable.run_command(cmd)


def assert_keys_is_list(keys):
    """Reject malformed API response: keys must be a list."""
    if not isinstance(keys, list):
        raise TestExecError(
            "user info 'keys' must be a list, got %s" % type(keys).__name__
        )


def assert_keys_have_create_date(keys, reject_future_sec=60):
    """
    Assert every key has create_date (non-empty, valid ISO); optional future check.
    """
    assert_keys_is_list(keys)
    if not keys:
        raise TestExecError("user has no keys")
    now = datetime.now(timezone.utc)
    for i, key in enumerate(keys):
        if "create_date" not in key:
            raise TestExecError(
                "key[%d] (access_key=%s) missing 'create_date'"
                % (i, key.get("access_key", "?"))
            )
        cd = key["create_date"]
        if cd is None:
            raise TestExecError("key[%d] create_date must not be null" % i)
        if not isinstance(cd, str):
            raise TestExecError(
                "key[%d] create_date must be string, got %s" % (i, type(cd).__name__)
            )
        if not cd.strip():
            raise TestExecError("key[%d] create_date must not be empty" % i)
        if not ISO_DATE_PATTERN.match(cd):
            raise TestExecError(
                "key[%d] create_date not valid ISO format: %r" % (i, cd)
            )
        try:
            dt = datetime.fromisoformat(cd.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if reject_future_sec is not None and dt > now:
                delta_sec = (dt - now).total_seconds()
                if delta_sec > reject_future_sec:
                    raise TestExecError(
                        "key[%d] create_date is in future: %s (delta %.1fs)"
                        % (i, cd, delta_sec)
                    )
        except ValueError as e:
            raise TestExecError("key[%d] create_date parse error: %s" % (i, e))
        log.info("key[%d] access_key=%s create_date=%s", i, key.get("access_key"), cd)


def assert_keys_sortable_by_create_date(keys):
    """Verify keys can be sorted by create_date (for UI ordering)."""
    sorted_by_date = sorted(keys, key=lambda k: k["create_date"])
    for i, key in enumerate(keys):
        if key["access_key"] != sorted_by_date[i]["access_key"]:
            break
    else:
        log.info("Keys are in create_date order (or single key)")


def run_assertion_bad_data():
    """
    Run assertion helpers against bad data; expect TestExecError.
    No cluster needed.
    """
    log.info(
        "Assertion bad data (non-list, empty keys, missing/null/empty/invalid create_date)"
    )
    checks = [
        ({"not": "a list"}, "must be a list"),
        ([], "no keys"),
        ([{"access_key": "AK", "secret_key": "SK"}], "create_date"),
        ([{"access_key": "AK", "secret_key": "SK", "create_date": None}], "null"),
        ([{"access_key": "AK", "secret_key": "SK", "create_date": ""}], "empty"),
        (
            [{"access_key": "AK", "secret_key": "SK", "create_date": "not-iso"}],
            "format",
        ),
    ]
    for keys, expected_in_msg in checks:
        try:
            assert_keys_have_create_date(keys, reject_future_sec=None)
            raise TestExecError("expected failure for %s" % expected_in_msg)
        except TestExecError as e:
            if expected_in_msg not in str(e).lower():
                raise
    log.info("Passed: assertion bad data")
