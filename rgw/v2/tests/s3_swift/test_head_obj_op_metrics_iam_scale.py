"""Scale validation of HEAD Object op metrics with RGW account IAM users.

Usage: test_head_obj_op_metrics_iam_scale.py -c <input_yaml>

<input_yaml>
        test_head_obj_op_metrics_iam_scale.yaml
        test_head_obj_op_metrics_iam_scale_smoke.yaml

Operation:
        Enable user/bucket counter caches
        Create one RGW account and account-root user
        Create N IAM users (default 500) with S3FullAccess
        Create one bucket per IAM user and upload M objects (default 10)
        Issue HEAD Object on every uploaded object
        Assert head_obj_ops / head_obj_lat via counter dump for
        gateway, every user, and every bucket
        Optionally verify metrics appear via ceph-exporter / Prometheus
"""

import json
import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables.scale_sync_test import create_bucket_skip_sync
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def _enable_counter_caches(config, ceph_conf, rgw_service, ssh_con):
    """Enable per-user / per-bucket op metric caches and restart RGW if needed."""
    restart_needed = False
    if config.test_ops.get("enable_user_counters_cache", True):
        log.info("Enabling rgw_user_counters_cache")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_user_counters_cache,
            True,
            ssh_con,
            set_to_all=True,
        )
        restart_needed = True
    if config.test_ops.get("enable_bucket_counters_cache", True):
        log.info("Enabling rgw_bucket_counters_cache")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_bucket_counters_cache,
            True,
            ssh_con,
            set_to_all=True,
        )
        restart_needed = True
    if restart_needed:
        log.info("Restarting RGW after counter cache config changes")
        if rgw_service.restart(None) is False:
            raise TestExecError("RGW service restart failed")
        time.sleep(30)


def _exec_json(cmd):
    """Run a shell command and parse JSON output."""
    output = utils.exec_shell_cmd(cmd)
    if not output:
        return None
    try:
        return json.loads(output)
    except (json.JSONDecodeError, TypeError) as e:
        raise TestExecError(f"Failed to parse JSON from '{cmd}': {e}\noutput={output}")


def _create_rgw_account(config):
    """Create an RGW account with raised user/bucket limits.

    Returns:
        tuple: (account_id, account_name)
    """
    base_name = config.test_ops.get("account_name", "head-metrics-scale")
    account_name = f"{base_name}-{random.randint(10000, 99999)}"
    account_email = f"{account_name}@example.com"
    account_id = f"RGW{random.randint(10**16, 10**17 - 1)}"
    max_users = int(config.test_ops.get("max_users", 1000))
    max_buckets = int(config.test_ops.get("max_buckets", 1000))

    log.info(f"Creating RGW account name={account_name} id={account_id}")
    created = _exec_json(
        f"radosgw-admin account create --account-name {account_name} "
        f"--email {account_email} --account-id {account_id}"
    )
    if not created or not created.get("id"):
        raise TestExecError(f"Failed to create RGW account {account_name}")
    account_id = created["id"]

    log.info(f"Raising account limits: max_users={max_users} max_buckets={max_buckets}")
    utils.exec_shell_cmd(
        f"radosgw-admin account modify --account-id {account_id} "
        f"--max-users {max_users} --max-buckets {max_buckets}"
    )
    return account_id, account_name


def _create_account_root(account_id, config):
    """Create account-root user and return Auth-compatible user dict."""
    root_user_name = config.test_ops.get(
        "root_user_name", f"root-{random.randint(1000, 9999)}"
    )
    log.info(f"Creating account-root user: {root_user_name}")
    root_info = _exec_json(
        f"radosgw-admin user create --uid {root_user_name} "
        f"--display-name {root_user_name} --account-id {account_id} "
        f"--account-root --gen-secret --gen-access-key"
    )
    if not root_info or "keys" not in root_info:
        raise TestExecError(f"Failed to create account-root user {root_user_name}")
    return {
        "user_id": root_info["user_id"],
        "access_key": root_info["keys"][0]["access_key"],
        "secret_key": root_info["keys"][0]["secret_key"],
        "user_name": root_user_name,
    }


def _resolve_rgw_user_id(access_key):
    """Resolve RGW user_id for counter labels via access key."""
    info = _exec_json(f"radosgw-admin user info --access-key {access_key}")
    if not info or "user_id" not in info:
        raise TestExecError(
            f"Could not resolve RGW user_id for access_key={access_key}"
        )
    return info["user_id"]


def _create_iam_users(iam_client, account_id, num_users, config):
    """Create N IAM users with keys and AmazonS3FullAccess.

    Returns:
        list[dict]: user_info dicts with user_id (RGW), iam_user_name, keys
    """
    policy_arn = config.test_ops.get(
        "policy_arn", "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    )
    iam_users = []
    write_user_info = AddUserInfo()
    basic_io_structure = BasicIOInfoStructure()
    log.info(f"Creating {num_users} IAM users under account {account_id}")

    for i in range(1, num_users + 1):
        iam_user_name = f"iam-user-{i}"
        if i == 1 or i % 50 == 0 or i == num_users:
            log.info(f"Creating IAM user {i}/{num_users}: {iam_user_name}")

        try:
            iam_client.create_user(UserName=iam_user_name)
        except iam_client.exceptions.EntityAlreadyExistsException:
            log.info(f"IAM user {iam_user_name} already exists")

        try:
            key_resp = iam_client.create_access_key(UserName=iam_user_name)
            access_key = key_resp["AccessKey"]["AccessKeyId"]
            secret_key = key_resp["AccessKey"]["SecretAccessKey"]
        except Exception as e:
            raise TestExecError(f"Failed to create access key for {iam_user_name}: {e}")

        try:
            iam_client.attach_user_policy(UserName=iam_user_name, PolicyArn=policy_arn)
        except Exception as e:
            raise TestExecError(
                f"Failed to attach {policy_arn} to {iam_user_name}: {e}"
            )

        rgw_user_id = _resolve_rgw_user_id(access_key)
        user_info = {
            "user_id": rgw_user_id,
            "iam_user_name": iam_user_name,
            "access_key": access_key,
            "secret_key": secret_key,
            "display_name": iam_user_name,
        }
        write_user_info.add_user_info(
            basic_io_structure.user(
                user_id=rgw_user_id,
                access_key=access_key,
                secret_key=secret_key,
            )
        )
        iam_users.append(user_info)

    log.info(f"Created {len(iam_users)} IAM users")
    return iam_users


def _assert_scope_counters(before, after, expected_ops, scope_desc):
    """Assert head_obj counters; return error string or None."""
    try:
        if not after:
            raise TestExecError(f"counters missing for {scope_desc}")
        reusable.assert_head_obj_counters(before, after, expected_ops)
        return None
    except TestExecError as e:
        return f"{scope_desc}: {e}"


def test_exec(config, ssh_con):
    if not config.test_ops.get("test_head_obj_metrics_iam_scale", False):
        raise TestExecError("test_head_obj_metrics_iam_scale is not enabled in config")

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    _enable_counter_caches(config, ceph_conf, rgw_service, ssh_con)

    num_iam_users = int(config.test_ops.get("num_iam_users", 500))
    objects_per_bucket = int(config.objects_count)
    buckets_per_user = int(config.bucket_count)
    expected_heads_per_bucket = objects_per_bucket
    total_expected_heads = num_iam_users * buckets_per_user * expected_heads_per_bucket

    account_id, account_name = _create_rgw_account(config)
    root_user = _create_account_root(account_id, config)

    root_auth = Auth(root_user, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
    iam_client = root_auth.do_auth_iam_client()

    iam_users = _create_iam_users(iam_client, account_id, num_iam_users, config)

    # Per-user: create buckets and upload objects
    user_resources = []
    log.info(
        f"Creating {buckets_per_user} bucket(s) and uploading "
        f"{objects_per_bucket} object(s) per IAM user"
    )
    for idx, each_user in enumerate(iam_users, start=1):
        if idx == 1 or idx % 50 == 0 or idx == num_iam_users:
            log.info(f"Provisioning data for user {idx}/{num_iam_users}")

        auth = reusable.get_auth(each_user, ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        s3_client = auth.do_auth_using_client()

        buckets = []
        for bc in range(buckets_per_user):
            bucket_name = utils.gen_bucket_name_from_userid(
                each_user["iam_user_name"], rand_no=bc
            )
            bucket_name = bucket_name.lower()
            log.debug(f"Creating bucket {bucket_name} for {each_user['iam_user_name']}")
            bucket = create_bucket_skip_sync(
                bucket_name, rgw_conn, each_user, ip_and_port
            )

            object_names = []
            for oc in range(objects_per_bucket):
                config.obj_size = utils.get_file_size(
                    config.objects_size_range.get("min"),
                    config.objects_size_range.get("max"),
                )
                s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                reusable.upload_object(
                    s3_object_name, bucket, TEST_DATA_PATH, config, each_user
                )
                object_names.append(s3_object_name)

            buckets.append(
                {
                    "bucket": bucket,
                    "bucket_name": bucket_name,
                    "object_names": object_names,
                }
            )

        user_resources.append(
            {
                "user": each_user,
                "s3_client": s3_client,
                "buckets": buckets,
            }
        )

    log.info("Taking counter dump snapshot before HEAD Object traffic")
    before_dump = reusable.get_counter_dump(ssh_con=ssh_con)
    before_gw = reusable.get_rgw_op_counters(before_dump, section="rgw_op")

    before_users = {}
    before_buckets = {}
    for resource in user_resources:
        user_id = resource["user"]["user_id"]
        before_users[user_id] = reusable.get_rgw_op_counters(
            before_dump,
            section="rgw_op_per_user",
            labels={"User": user_id},
        )
        for binfo in resource["buckets"]:
            bname = binfo["bucket_name"]
            before_buckets[bname] = reusable.get_rgw_op_counters(
                before_dump,
                section="rgw_op_per_bucket",
                labels={"Bucket": bname},
            )

    log.info(f"Issuing HEAD Object on {total_expected_heads} objects")
    heads_done = 0
    for resource in user_resources:
        s3_client = resource["s3_client"]
        for binfo in resource["buckets"]:
            for obj_name in binfo["object_names"]:
                s3_client.head_object(Bucket=binfo["bucket_name"], Key=obj_name)
                heads_done += 1
        if heads_done % 500 == 0 or heads_done == total_expected_heads:
            log.info(f"HEAD progress: {heads_done}/{total_expected_heads}")

    log.info("Taking counter dump snapshot after HEAD Object traffic")
    after_dump = reusable.get_counter_dump(ssh_con=ssh_con)
    after_gw = reusable.get_rgw_op_counters(after_dump, section="rgw_op")

    failures = []
    log.info(f"Asserting gateway-scope head_obj_* (expected>={total_expected_heads})")
    err = _assert_scope_counters(before_gw, after_gw, total_expected_heads, "gateway")
    if err:
        failures.append(err)

    log.info(
        f"Asserting user-scope head_obj_* for {num_iam_users} users "
        f"(expected>={expected_heads_per_bucket * buckets_per_user} each)"
    )
    expected_per_user = expected_heads_per_bucket * buckets_per_user
    for resource in user_resources:
        user_id = resource["user"]["user_id"]
        iam_name = resource["user"]["iam_user_name"]
        after_user = reusable.get_rgw_op_counters(
            after_dump,
            section="rgw_op_per_user",
            labels={"User": user_id},
        )
        err = _assert_scope_counters(
            before_users.get(user_id, {}),
            after_user,
            expected_per_user,
            f"user User={user_id} iam={iam_name}",
        )
        if err:
            failures.append(err)

    log.info(
        f"Asserting bucket-scope head_obj_* for "
        f"{num_iam_users * buckets_per_user} buckets "
        f"(expected>={expected_heads_per_bucket} each)"
    )
    for resource in user_resources:
        for binfo in resource["buckets"]:
            bname = binfo["bucket_name"]
            after_bucket = reusable.get_rgw_op_counters(
                after_dump,
                section="rgw_op_per_bucket",
                labels={"Bucket": bname},
            )
            err = _assert_scope_counters(
                before_buckets.get(bname, {}),
                after_bucket,
                expected_heads_per_bucket,
                f"bucket Bucket={bname}",
            )
            if err:
                failures.append(err)

    if failures:
        preview = "\n".join(failures[:20])
        more = f"\n... and {len(failures) - 20} more" if len(failures) > 20 else ""
        raise TestExecError(
            f"{len(failures)} head_obj metric assertion(s) failed:\n" f"{preview}{more}"
        )

    log.info(
        f"All head_obj_* assertions passed for gateway, "
        f"{num_iam_users} users, and "
        f"{num_iam_users * buckets_per_user} buckets"
    )

    if config.test_ops.get("verify_prometheus", True):
        log.info("Verifying head_obj_* via ceph-exporter and Prometheus")
        rgw_host = (
            str(ip_and_port)
            .replace("https://", "")
            .replace("http://", "")
            .split(":")[0]
        )
        reusable.wait_for_head_obj_prometheus_metrics(
            rgw_host=rgw_host, ssh_con=ssh_con
        )

    if config.test_ops.get("delete_bucket_object", False):
        log.info("Cleaning up buckets and objects")
        for idx, resource in enumerate(user_resources, start=1):
            if idx == 1 or idx % 50 == 0 or idx == num_iam_users:
                log.info(f"Cleanup progress: user {idx}/{num_iam_users}")
            for binfo in resource["buckets"]:
                reusable.delete_objects(binfo["bucket"])
                reusable.delete_bucket(binfo["bucket"])

    log.info(
        f"IAM scale HEAD Object metrics test complete "
        f"(account={account_name} id={account_id})"
    )


if __name__ == "__main__":
    test_info = AddTestInfo("Testing HEAD Object op metrics at IAM account scale")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Testing HEAD Object op metrics IAM scale"
        )
        parser.add_argument(
            "-c",
            dest="config",
            help="YAML config for HEAD Object op metrics IAM scale test",
        )
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
