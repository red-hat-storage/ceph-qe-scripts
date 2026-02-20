"""RFE: RGW User Keys creation date info (BZ/RFE verification).

Verifies that radosgw-admin user info returns create_date for each key,
so UIs can sort keys by creation time and display when each was created.

Fixed In: ceph-20.1.0-26 (create_date in keys[] when listing user info)

Usage:
    test_rgw_user_keys_create_date.py -c <input_yaml>
    test_rgw_user_keys_create_date.py -c configs/test_rgw_user_keys_create_date.yaml

Operation:
    1. Create an RGW user (gets one S3 key by default).
    2. Add two more S3 keys via radosgw-admin key create.
    3. Run radosgw-admin user info --uid=<user> and parse JSON.
    4. Assert every key has "create_date", valid ISO timestamp, and can be sorted by it.
    5. Remove the test user.

Covered:
    - Single-key user (only default key from user create).
    - Many keys (configurable extra keys; all must have create_date).
    - Key created with custom access_key and secret_key (random).
    - Key deletion and recreation (key rm then key create; verify create_date on remaining/new keys).
    - Key rotation (remove key, add new key; all keys have create_date).
    - Disabled/inactive keys (suspended user; keys still list with create_date).
    - User with many keys 100+ (configurable many_keys_large_count).
    - Assertion bad data (empty/null/invalid create_date rejected).
"""
import argparse
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.lib.resource_op import Config
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.tests.s3_swift.reusables import rgw_user_keys_create_date as user_keys_reusable

log = logging.getLogger()


def test_exec(config, ssh_con):
    """User with 3 keys (1 default + 2 added)."""
    log.info("3 keys (1 default + 2 added)")
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(cluster_name)
    try:
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=2)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys) < 3:
            raise TestExecError(
                "Expected at least 3 keys (1 initial + 2 added), got %d" % len(keys)
            )
        user_keys_reusable.assert_keys_have_create_date(keys)
        user_keys_reusable.assert_keys_sortable_by_create_date(keys)
        log.info("Passed: all %d keys have create_date", len(keys))
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_single_key_user(config, ssh_con):
    """User with only the default key (no extra keys)."""
    log.info("Single-key user (only default key)")
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW single-key test"
    )
    try:
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys) != 1:
            raise TestExecError(
                "Expected exactly 1 key for new user, got %d" % len(keys)
            )
        user_keys_reusable.assert_keys_have_create_date(keys)
        user_keys_reusable.assert_keys_sortable_by_create_date(keys)
        log.info("Passed: single-key user")
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_many_keys_user(config, ssh_con):
    """User with many keys (default + extra); all must have create_date."""
    extra_keys = 5
    if getattr(config, "doc", None) and isinstance(config.doc.get("config"), dict):
        extra_keys = config.doc["config"].get("extra_keys_count", 5)
    if extra_keys < 1 or extra_keys > 20:
        extra_keys = 5
    log.info("Many-key user (1 default + %d extra keys)", extra_keys)
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW many-keys test"
    )
    try:
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=extra_keys)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        expected = 1 + extra_keys
        if len(keys) != expected:
            raise TestExecError(
                "Expected %d keys (1 + %d extra), got %d"
                % (expected, extra_keys, len(keys))
            )
        user_keys_reusable.assert_keys_have_create_date(keys)
        user_keys_reusable.assert_keys_sortable_by_create_date(keys)
        log.info("Passed: many-key user (%d keys)", len(keys))
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_custom_access_key(config, ssh_con):
    """Key created with custom (random) access_key and secret_key."""
    log.info("Key with custom access_key and secret_key")
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW custom-key test"
    )
    try:
        user_keys_reusable.add_rgw_s3_key_custom(uid, cluster_name=cluster_name)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys) != 2:
            raise TestExecError("Expected 2 keys (1 default + 1 custom), got %d" % len(keys))
        user_keys_reusable.assert_keys_have_create_date(keys)
        user_keys_reusable.assert_keys_sortable_by_create_date(keys)
        log.info("Passed: custom access_key and secret_key")
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_key_deletion_recreation(config, ssh_con):
    """Key deletion and recreation; verify create_date on remaining and new keys."""
    log.info("Key deletion and recreation")
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW key del-recreate test"
    )
    try:
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=2)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys) < 3:
            raise TestExecError("Expected at least 3 keys, got %d" % len(keys))
        access_key_to_remove = keys[1]["access_key"]
        user_keys_reusable.remove_rgw_key(uid, access_key_to_remove, cluster_name)
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=1)
        keys_after = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys_after) != 3:
            raise TestExecError("After rm+create expected 3 keys, got %d" % len(keys_after))
        user_keys_reusable.assert_keys_have_create_date(keys_after)
        log.info("Passed: key deletion and recreation")
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_key_rotation(config, ssh_con):
    """Key rotation (remove one key, add new key); all keys have create_date."""
    log.info("Key rotation")
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW key rotation test"
    )
    try:
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=1)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys) != 2:
            raise TestExecError("Expected 2 keys, got %d" % len(keys))
        old_access_key = keys[0]["access_key"]
        user_keys_reusable.remove_rgw_key(uid, old_access_key, cluster_name)
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=1)
        keys_after = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys_after) != 2:
            raise TestExecError("After rotation expected 2 keys, got %d" % len(keys_after))
        user_keys_reusable.assert_keys_have_create_date(keys_after)
        log.info("Passed: key rotation")
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_suspended_user_keys(config, ssh_con):
    """Disabled/inactive keys (suspended user); keys still list with create_date."""
    log.info("Suspended user (inactive keys) still have create_date")
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW suspended-user test"
    )
    try:
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=1)
        user_keys_reusable.suspend_rgw_user(uid, cluster_name)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        if len(keys) != 2:
            raise TestExecError("Expected 2 keys for suspended user, got %d" % len(keys))
        user_keys_reusable.assert_keys_have_create_date(keys)
        user_keys_reusable.enable_rgw_user(uid, cluster_name)
        log.info("Passed: suspended user keys have create_date")
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


def test_many_keys_100(config, ssh_con):
    """User with many keys 100+ (configurable many_keys_large_count)."""
    large_count = 100
    if getattr(config, "doc", None) and isinstance(config.doc.get("config"), dict):
        large_count = config.doc["config"].get("many_keys_large_count", 100)
    if large_count < 10 or large_count > 200:
        large_count = 100
    log.info("Many-key user 100+ (1 default + %d extra keys)", large_count)
    cluster_name = getattr(config, "cluster_name", "ceph") or "ceph"
    uid = user_keys_reusable.create_rgw_user(
        cluster_name, display_name="RGW many-keys-100 test"
    )
    try:
        user_keys_reusable.add_rgw_s3_keys(uid, cluster_name, count=large_count)
        keys = user_keys_reusable.get_rgw_user_keys(uid, cluster_name)
        expected = 1 + large_count
        if len(keys) != expected:
            raise TestExecError(
                "Expected %d keys (1 + %d extra), got %d" % (expected, large_count, len(keys))
            )
        user_keys_reusable.assert_keys_have_create_date(keys)
        user_keys_reusable.assert_keys_sortable_by_create_date(keys)
        log.info("Passed: many-key user 100+ (%d keys)", len(keys))
    finally:
        user_keys_reusable.remove_rgw_user(uid, cluster_name)


if __name__ == "__main__":
    test_info = AddTestInfo("RGW user keys create_date (RFE)")
    test_info.started_info()
    try:
        parser = argparse.ArgumentParser(description="RGW user keys create_date RFE test")
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
        if not yaml_file or not os.path.isfile(yaml_file):
            log.error("Config file required: -c <yaml>")
            test_info.failed_status("Missing or invalid config file")
            sys.exit(1)
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read(ssh_con)
        user_keys_reusable.run_assertion_bad_data()
        test_exec(config, ssh_con)
        test_single_key_user(config, ssh_con)
        test_many_keys_user(config, ssh_con)
        test_custom_access_key(config, ssh_con)
        test_key_deletion_recreation(config, ssh_con)
        test_key_rotation(config, ssh_con)
        test_suspended_user_keys(config, ssh_con)
        test_many_keys_100(config, ssh_con)
        test_info.success_status("User keys create_date verified")
        sys.exit(0)
    except (TestExecError, Exception) as e:
        log.error("%s", e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)
