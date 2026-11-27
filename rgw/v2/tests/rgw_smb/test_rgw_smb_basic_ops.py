"""
test_rgw_smb_basic_ops - Basic SMB share create/list/delete with RGW backend

Usage: test_rgw_smb_basic_ops.py -c <input_yaml>

<input_yaml>
    configs/test_rgw_smb_basic_ops.yaml
    configs/test_rgw_smb_cluster_with_placement.yaml
    configs/test_rgw_smb_mount.yaml
    configs/test_rgw_smb_mount_tenanted_user.yaml
    configs/test_rgw_smb_share_user_validation.yaml

Operation:
    Create a regular RGW user with create_users, the same call used by
    test_Mbuckets_with_Nobjects.py. A tenanted run still creates
    tenant$user1.
    Create bucket (test1)
    Optionally upload objects to the bucket
    Optionally create SMB cluster (placement label:smb)
    Apply SMB RGW credential + share resources via ceph smb apply
    List SMB shares and verify share is present
    Optionally mount/access share from client using samba-client (smbclient)
    Optionally delete one file from the share via smbclient and re-validate
    Delete SMB share (and credential)
    List SMB shares and verify share is removed

    configs/test_rgw_smb_mount_tenanted_user.yaml creates tenant1$user1,
    a bucket, and objects, deploys the SMB cluster and share, runs the
    smbclient mount checks, then deletes the share, cluster, and user.

    configs/test_rgw_smb_share_user_validation.yaml runs both negative
    share scenarios and does not mount a share. The test passes only
    when every scenario passes: unassociated_user rejects a real user
    who does not own the bucket, and nonexistent_user rejects a spec
    whose RGW access credentials do not exist. Share creation must fail
    and the share must not be created.
"""

import argparse
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    IOInfoInitialize,
    TenantInfo,
)
from v2.tests.rgw_smb import reusable as smb_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None

# Failures that mean ceph smb apply never reached user/bucket validation.
_UNEXPECTED_APPLY_FAILURES = (
    "command not found",
    "no such file or directory",
    "invalid choice",
    "module 'smb' is not enabled",
    "cluster does not exist",
)


def _record_tenant_user(user_info, tenant_name):
    """
    Add the tenanted RGW user to io_info.yaml.

    Bucket and object operations look the user up by access key. Users
    created with radosgw-admin are not recorded unless this is called.
    The yaml stores the short uid plus the tenant, matching other
    tenanted-user tests. SMB credentials keep tenant$uid on user_info.
    """
    short_id = str(user_info["user_id"]).split("$", 1)[-1]
    user_record = BasicIOInfoStructure().user(
        user_id=short_id,
        access_key=user_info["access_key"],
        secret_key=user_info["secret_key"],
    )
    user_record = dict(user_record, **TenantInfo().tenant(tenant_name))
    log.info(
        f"Recording tenanted user {tenant_name}${short_id} in io_info.yaml "
        f"for access_key {user_info['access_key']}"
    )
    AddUserInfo().add_user_info(user_record)


def _configured_tenant(config):
    """
    Return the RGW tenant for this run.

    test_ops.tenant_name selects the tenant. user_type tenanted without
    a tenant name uses tenant1.
    """
    tenant = config.test_ops.get("tenant_name")
    if tenant:
        return str(tenant)
    if getattr(config, "user_type", None) == "tenanted":
        return "tenant1"
    return None


def _remove_one_user(user_info, label):
    """
    Remove an RGW user. Tenanted ids are quoted so '$' is not expanded.
    """
    try:
        uid = str(user_info.get("user_id", ""))
        tenant = user_info.get("tenant")
        if tenant or "$" in uid:
            smb_reusable.remove_rgw_user(uid, tenant=tenant)
            try:
                AddUserInfo().set_user_deleted(user_info["access_key"])
            except Exception as exc:
                log.error(f"Failed to mark {label} deleted in io_info: {exc}")
        else:
            s3_reusable.remove_user(user_info)
    except Exception as exc:
        log.error(f"Failed to remove {label}: {exc}")


def _remove_test_users(owner_user, other_user):
    """
    Remove the bucket owner and the unassociated RGW user.
    """
    if owner_user:
        _remove_one_user(owner_user, "bucket owner")
    if other_user:
        _remove_one_user(other_user, "unassociated RGW user")


def _cleanup_rejected_share(cluster_id, share_id, credential_id, other_user):
    """
    Remove a share created for a non-owner, or a credential stored before
    that share was rejected.
    """
    try:
        share_list = smb_reusable.list_smb_shares(cluster_id)
        if smb_reusable.share_in_list(share_list, share_id):
            log.info(
                "Removing SMB share created for a user that is not "
                f"associated with the bucket: {share_id}"
            )
            smb_reusable.apply_smb_resources(
                smb_reusable.build_remove_rgw_share_resources(
                    cluster_id=cluster_id,
                    share_id=share_id,
                    credential_id=credential_id,
                    user_id=other_user["user_id"],
                    access_key=other_user["access_key"],
                    secret_key=other_user["secret_key"],
                )
            )
            return
        log.info("Removing RGW SMB credential if the rejected apply stored it")
        smb_reusable.apply_smb_resources(
            [
                {
                    "resource_type": "ceph.smb.rgw.credential",
                    "rgw_credential_id": credential_id,
                    "intent": "removed",
                    "user_id": other_user["user_id"],
                    "access_key_id": other_user["access_key"],
                    "secret_access_key": other_user["secret_key"],
                }
            ]
        )
    except Exception as exc:
        log.error(f"SMB resource cleanup did not complete: {exc}")


def _create_unassociated_user(ops, owner_user, bucket_name):
    """
    Create the second RGW user after confirming the bucket owner.

    The caller checks that this user does not own bucket_name.
    """
    other_user_name = ops.get("unassociated_user_name", "user2")
    other_secret = str(ops.get("unassociated_secret_key", "12345"))
    owner_name = ops.get("user_name", "user1")
    if other_user_name in (owner_name, owner_user["user_id"]):
        raise TestExecError(
            "unassociated_user_name must be a different RGW user than user_name"
        )
    if not smb_reusable.user_associated_with_bucket(owner_user["user_id"], bucket_name):
        raise TestExecError(
            f"Bucket {bucket_name} is not associated with owner "
            f"{owner_user['user_id']}"
        )

    log.info(f"Creating RGW user {other_user_name} with secret_key {other_secret}")
    return smb_reusable.create_rgw_user(other_user_name, secret_key=other_secret)


def _nonexistent_credential(ops, owner_user):
    """
    Return RGW access credentials for a user that is not on the cluster.
    """
    user_id = ops.get("nonexistent_user_name", "nosuch-smb-user")
    access_key = ops.get("nonexistent_access_key", "NOSUCHACCESSKEY1234")
    secret_key = str(ops.get("nonexistent_secret_key", "nosuchsecret"))
    owner_name = ops.get("user_name", "user1")
    if user_id in (owner_name, owner_user["user_id"]):
        raise TestExecError("nonexistent_user_name must not be the bucket owner")
    if access_key == owner_user["access_key"]:
        raise TestExecError(
            "nonexistent_access_key must not be the bucket owner's access key"
        )
    if secret_key == str(owner_user.get("secret_key")):
        raise TestExecError(
            "nonexistent_secret_key must not be the bucket owner's secret key"
        )
    if smb_reusable.rgw_user_exists(user_id):
        raise TestExecError(
            f"RGW user {user_id} exists. Set nonexistent_user_name to a user "
            "that is not on the cluster."
        )
    log.info(
        f"Share spec will use RGW user {user_id}, which does not exist, "
        f"access_key={access_key}"
    )
    return {
        "user_id": user_id,
        "access_key": access_key,
        "secret_key": secret_key,
    }


def _assert_share_spec_rejected(
    cluster_id,
    share_id,
    share_name,
    bucket_name,
    credential_id,
    credential,
    reason,
    expected_result=None,
):
    """
    Apply an RGW-backed SMB share spec that must be rejected.

    reason describes why the credentials are invalid. expected_result is
    the pass condition logged for this scenario. The share must not be
    created.
    """
    cluster_list = smb_reusable.list_smb_clusters()
    if not smb_reusable.cluster_in_list(cluster_list, cluster_id):
        raise TestExecError(
            f"SMB cluster {cluster_id} is not present. Set create_smb_cluster: "
            "true or create the cluster before running this test."
        )

    if expected_result:
        log.info(f"Expected result: {expected_result}")
    log.info(
        "Creating RGW-backed SMB share from a spec file for bucket "
        f"{bucket_name} with user {credential['user_id']} "
        f"access_key={credential['access_key']}. "
        f"Share creation must fail before the share is created {reason}."
    )
    resources = smb_reusable.build_rgw_share_resources(
        cluster_id=cluster_id,
        share_id=share_id,
        share_name=share_name,
        bucket_name=bucket_name,
        credential_id=credential_id,
        user_id=credential["user_id"],
        access_key=credential["access_key"],
        secret_key=credential["secret_key"],
    )
    apply_error = None
    try:
        apply_output = smb_reusable.apply_smb_resources(resources, expect_failure=True)
    except TestExecError as exc:
        apply_output = str(exc)
        apply_error = exc

    log.info("Confirming the rejected share was not created")
    share_created = False
    try:
        share_list = smb_reusable.list_smb_shares(cluster_id)
        share_created = smb_reusable.share_in_list(share_list, share_id)
    except TestExecError:
        if apply_error is None:
            raise
        log.info("Share list failed after SMB apply was accepted")

    if share_created or apply_error is not None:
        _cleanup_rejected_share(cluster_id, share_id, credential_id, credential)
        detail = expected_result or (
            "SMB share creation from the spec file must fail before the share "
            f"is created {reason}."
        )
        raise TestExecError(
            f"{detail} share_created={share_created}. output: {apply_output}"
        ) from apply_error

    lowered = apply_output.lower()
    for marker in _UNEXPECTED_APPLY_FAILURES:
        if marker in lowered:
            _cleanup_rejected_share(cluster_id, share_id, credential_id, credential)
            raise TestExecError(
                "ceph smb apply failed before user/bucket validation "
                f"({marker}). output: {apply_output}"
            )
    _cleanup_rejected_share(cluster_id, share_id, credential_id, credential)
    if expected_result:
        log.info(f"Expected result met: {expected_result}")
    log.info(
        f"SMB share creation was rejected for user {credential['user_id']} "
        f"and bucket {bucket_name} {reason}"
    )


_REQUIRED_SHARE_SCENARIOS = ("unassociated_user", "nonexistent_user")


def _scenario_name(scenario):
    """
    Return the canonical name for a negative share scenario.
    """
    name = scenario.get("name")
    if name in ("non_existent", "nonexistent", "nonexistent_user"):
        return "nonexistent_user"
    if name in ("unassociated", "unassociated_user"):
        return "unassociated_user"
    raise TestExecError(
        f"Unknown scenario {name}. Use unassociated_user or nonexistent_user."
    )


def _scenario_ops(test_ops, scenario):
    """
    Merge a scenario over the shared test_ops. Scenario keys win.
    """
    merged = dict(test_ops)
    merged.update(scenario)
    return merged


def _run_one_negative_scenario(
    ops, name, user_info, bucket_name, cluster_id, created_users
):
    """
    Run one share-spec rejection scenario.

    A user created for the scenario is appended to created_users before
    the share apply, so cleanup can remove that user if the apply fails.
    """
    share_id = ops.get("share_id")
    share_name = ops.get("share_name")
    credential_id = ops.get("credential_id")
    if not share_id or not share_name or not credential_id:
        raise TestExecError(
            f"scenario {name} requires share_id, share_name, and credential_id"
        )
    expected_result = None
    if name == "unassociated_user":
        other_user = _create_unassociated_user(ops, user_info, bucket_name)
        created_users.append(other_user)
        if smb_reusable.user_associated_with_bucket(other_user["user_id"], bucket_name):
            raise TestExecError(
                f"User {other_user['user_id']} is associated with bucket "
                f"{bucket_name}. This test requires a user that does not "
                "own the bucket."
            )
        log.info(
            f"User {other_user['user_id']} is not associated with bucket "
            f"{bucket_name} (owner={user_info['user_id']})"
        )
        credential = other_user
        reason = (
            f"when user {other_user['user_id']} is not associated with "
            f"bucket {bucket_name}"
        )
    else:
        if not smb_reusable.user_associated_with_bucket(
            user_info["user_id"], bucket_name
        ):
            raise TestExecError(
                f"Bucket {bucket_name} is not associated with owner "
                f"{user_info['user_id']}"
            )
        credential = _nonexistent_credential(ops, user_info)
        reason = (
            "because the RGW access credentials "
            f"user_id={credential['user_id']} "
            f"access_key={credential['access_key']} are non-existent"
        )
        expected_result = (
            "Creating an RGW-backed SMB share using a spec file should fail "
            "if the provided RGW access credentials are non-existent"
        )
    _assert_share_spec_rejected(
        cluster_id,
        share_id,
        share_name,
        bucket_name,
        credential_id,
        credential,
        reason,
        expected_result=expected_result,
    )


def _run_negative_scenarios(config, user_info, bucket_name, cluster_id):
    """
    Run every configured negative share scenario.

    Returns (created_users, results). A later failure does not skip the
    remaining scenarios. The caller passes only when every result is PASS.
    """
    scenarios = config.test_ops.get("scenarios") or []
    names = [_scenario_name(scenario) for scenario in scenarios]
    missing = [name for name in _REQUIRED_SHARE_SCENARIOS if name not in names]
    if missing:
        raise TestExecError(
            "scenarios must include unassociated_user and nonexistent_user. "
            f"Missing: {', '.join(missing)}"
        )

    created_users = []
    results = []
    for index, scenario in enumerate(scenarios, start=1):
        name = _scenario_name(scenario)
        label = f"scenario {index} {name}"
        ops = _scenario_ops(config.test_ops, scenario)
        log.info(f"starting {label}")
        try:
            _run_one_negative_scenario(
                ops, name, user_info, bucket_name, cluster_id, created_users
            )
        except Exception as exc:
            log.error(f"{label} failed: {exc}")
            log.error(traceback.format_exc())
            results.append((label, "FAIL"))
            log.info(f"RESULT {label}: FAIL")
            continue
        results.append((label, "PASS"))
        log.info(f"RESULT {label}: PASS")
    return created_users, results


def _require_scenarios_passed(results):
    """
    Pass only when every scenario result is PASS.
    """
    log.info("Scenario results:")
    for label, status in results:
        log.info(f"  {label}: {status}")
    failed = [label for label, status in results if status != "PASS"]
    if failed or len(results) < len(_REQUIRED_SHARE_SCENARIOS):
        detail = ", ".join(failed) if failed else "no scenario completed"
        raise TestExecError(
            "FINAL RESULT: FAIL. The test passes only when both scenarios "
            f"pass. Failed scenarios: {detail}"
        )
    log.info("FINAL RESULT: PASS. Both share credential scenarios passed.")


def test_exec(config, ssh_con):
    """
    Executes RGW SMB basic share operations based on configuration.
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Ensure smb mgr module is enabled before starting test operations
    log.info("Checking smb mgr module status before starting test")
    smb_reusable.ensure_smb_mgr_module_enabled()

    user_name = config.test_ops.get("user_name", "user1")
    bucket_name = config.test_ops.get("bucket_name", "test1")
    cluster_id = config.test_ops.get("cluster_id", "rgw-smb")
    share_id = config.test_ops.get("share_id", "rgw-share1")
    share_name = config.test_ops.get("share_name", "rshare1")
    credential_id = config.test_ops.get("credential_id", "external-rgw-creds")
    define_user_pass = config.test_ops.get("define_user_pass", "smbuser%smbpass")

    tenant_name = _configured_tenant(config)
    if tenant_name:
        log.info(f"Creating tenanted RGW user: {tenant_name}${user_name}")
        user_info = smb_reusable.create_rgw_user(user_name, tenant=tenant_name)
        expected_id = f"{tenant_name}${user_name}"
        if user_info["user_id"] != expected_id:
            raise TestExecError(
                f"Tenanted RGW user id must be {expected_id}, "
                f"got {user_info['user_id']}"
            )
        _record_tenant_user(user_info, tenant_name)
    else:
        # Same regular-user creation path as test_Mbuckets_with_Nobjects.py.
        # A generated uid avoids radosgw-admin user info returning empty
        # output for a fixed name such as user1.
        log.info("Creating RGW user")
        all_users_info = s3lib.create_users(config.user_count)
        if not all_users_info or not isinstance(all_users_info[0], dict):
            raise TestExecError("RGW user creation failed")
        user_info = all_users_info[0]
    log.info(
        f"User created: user_id={user_info['user_id']}, "
        f"access_key={user_info['access_key']}"
    )

    auth = s3_reusable.get_auth(user_info, ssh_con, config.ssl, config.haproxy)
    rgw_conn = auth.do_auth()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    bucket = None
    created_objects = []
    if config.test_ops.get("create_bucket", True):
        log.info(f"Creating bucket: {bucket_name}")
        if config.haproxy:
            bucket = s3_reusable.create_bucket(bucket_name, rgw_conn, user_info)
        else:
            bucket = s3_reusable.create_bucket(
                bucket_name, rgw_conn, user_info, ip_and_port
            )
        log.info(f"Bucket {bucket_name} created successfully")

    if config.test_ops.get("create_object", False):
        if bucket is None:
            bucket = s3lib.resource_op(
                {"obj": rgw_conn, "resource": "Bucket", "args": [bucket_name]}
            )
        log.info(f"s3 objects to create: {config.objects_count}")
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
            log.info(f"Uploading s3 object: {s3_object_name}")
            s3_reusable.upload_object(
                s3_object_name, bucket, TEST_DATA_PATH, config, user_info
            )
            created_objects.append(s3_object_name)
        log.info(
            f"Uploaded {len(created_objects)} object(s) to bucket {bucket_name}: "
            f"{created_objects}"
        )

    if config.test_ops.get("create_smb_cluster", False):
        # 1. Create SMB cluster if it is not already present
        cluster_list = smb_reusable.list_smb_clusters()
        if smb_reusable.cluster_in_list(cluster_list, cluster_id):
            log.info(f"SMB cluster {cluster_id} already exists, skipping create")
        else:
            smb_reusable.create_smb_cluster(
                cluster_id,
                auth_mode=config.test_ops.get("smb_auth_mode", "user"),
                define_user_pass=define_user_pass,
                placement=config.test_ops.get("placement"),
            )
        # 2. Validate cluster is listed in ceph smb cluster ls
        log.info("Validating SMB cluster is listed in ceph smb cluster ls")
        cluster_list = smb_reusable.list_smb_clusters()
        smb_reusable.verify_cluster_in_list(
            cluster_list, cluster_id, expect_present=True
        )

    scenarios = config.test_ops.get("scenarios")
    # Negative scenarios use their own share ids. The owner share and
    # smbclient mount run only when this config asks for them.
    run_owner_share = (
        not scenarios
        or config.test_ops.get("mount_smb_share", False)
        or config.test_ops.get("create_smb_share", False)
    )
    created_users = []
    results = None
    mount_error = None
    try:
        if scenarios:
            created_users, results = _run_negative_scenarios(
                config, user_info, bucket_name, cluster_id
            )

        if run_owner_share:
            try:
                if config.test_ops.get("create_smb_share", True):
                    # 1. Create SMB share
                    log.info("Creating RGW-backed SMB share via declarative apply")
                    resources = smb_reusable.build_rgw_share_resources(
                        cluster_id=cluster_id,
                        share_id=share_id,
                        share_name=share_name,
                        bucket_name=bucket_name,
                        credential_id=credential_id,
                        user_id=user_info["user_id"],
                        access_key=user_info["access_key"],
                        secret_key=user_info["secret_key"],
                    )
                    smb_reusable.apply_smb_resources(resources)
                    # 2. Validate SMB services are available
                    log.info("Validating SMB services are available in ceph")
                    smb_reusable.verify_smb_service_available(
                        cluster_id, expect_present=True
                    )

                if config.test_ops.get("list_smb_share", True):
                    log.info("Listing SMB shares after creation")
                    share_list = smb_reusable.list_smb_shares(cluster_id)
                    smb_reusable.verify_share_in_list(
                        share_list, share_id, expect_present=True
                    )
                    share_info = smb_reusable.show_smb_share(cluster_id, share_id)
                    log.info(f"Share details: {share_info}")

                if config.test_ops.get("mount_smb_share", False):
                    log.info(
                        "Mounting RGW-backed SMB share from client node "
                        "using samba-client"
                    )
                    log.info(
                        f"smbclient will use share_name '{share_name}' from "
                        f"config, not share_id '{share_id}'"
                    )
                    test_file_path = None
                    if TEST_DATA_PATH:
                        test_file_path = os.path.join(
                            TEST_DATA_PATH, "rgw_smb_mount_test.txt"
                        )
                    smb_reusable.mount_smb_share_with_smbclient(
                        cluster_id=cluster_id,
                        share_name=share_name,
                        define_user_pass=define_user_pass,
                        smb_endpoint=config.test_ops.get("smb_endpoint"),
                        smbclient_io=config.test_ops.get("smbclient_io", False),
                        test_file_path=test_file_path,
                        expected_names=created_objects,
                        delete_one_file=config.test_ops.get("smbclient_delete", False),
                    )
                    log.info(
                        f"SMB share {share_name} accessed successfully via "
                        f"smbclient on the client node"
                    )

                if config.test_ops.get("delete_smb_share", True):
                    log.info("Deleting SMB share and RGW credential")
                    if config.test_ops.get("delete_via_apply", True):
                        remove_resources = (
                            smb_reusable.build_remove_rgw_share_resources(
                                cluster_id=cluster_id,
                                share_id=share_id,
                                credential_id=credential_id,
                                user_id=user_info["user_id"],
                                access_key=user_info["access_key"],
                                secret_key=user_info["secret_key"],
                            )
                        )
                        smb_reusable.apply_smb_resources(remove_resources)
                    else:
                        smb_reusable.remove_smb_share(cluster_id, share_id)
                        remove_cred = [
                            {
                                "resource_type": "ceph.smb.rgw.credential",
                                "rgw_credential_id": credential_id,
                                "intent": "removed",
                                "user_id": user_info["user_id"],
                                "access_key_id": user_info["access_key"],
                                "secret_access_key": user_info["secret_key"],
                            }
                        ]
                        smb_reusable.apply_smb_resources(remove_cred)

                    log.info("Listing SMB shares after deletion")
                    share_list = smb_reusable.list_smb_shares(cluster_id)
                    smb_reusable.verify_share_in_list(
                        share_list, share_id, expect_present=False
                    )
            except Exception as exc:
                if not scenarios:
                    raise
                log.error(f"smbclient mount validation failed: {exc}")
                log.error(traceback.format_exc())
                mount_error = exc

        if results is not None:
            try:
                _require_scenarios_passed(results)
            except TestExecError as exc:
                if mount_error is None:
                    raise
                raise TestExecError(
                    f"{exc} smbclient mount validation failed: {mount_error}"
                ) from mount_error
        if mount_error is not None:
            raise TestExecError(
                f"smbclient mount validation failed: {mount_error}"
            ) from mount_error
    finally:
        if scenarios and config.user_remove is True:
            other_user = created_users[-1] if created_users else None
            _remove_test_users(user_info, other_user)

    if config.test_ops.get("delete_smb_cluster", False):
        # Delete the cluster only after its shares are gone. Ceph returns
        # EAGAIN "cluster in use by shares" if any share still references it.
        smb_reusable.remove_smb_cluster(cluster_id)
        # 2. Validating SMB cluster is not listed in ceph smb cluster ls
        log.info("Validating SMB cluster is not listed in ceph smb cluster ls")
        cluster_list = smb_reusable.list_smb_clusters()
        smb_reusable.verify_cluster_in_list(
            cluster_list, cluster_id, expect_present=False
        )
        # 3. Validating SMB services are not available in ceph
        log.info("Validating SMB services are not available in ceph")
        smb_reusable.verify_smb_service_available(cluster_id, expect_present=False)

    if config.user_remove is True and not scenarios:
        if tenant_name:
            smb_reusable.remove_rgw_user(user_info["user_id"], tenant=tenant_name)
            AddUserInfo().set_user_deleted(user_info["access_key"])
        else:
            s3_reusable.remove_user(user_info)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW SMB basic share create/list/delete")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW SMB basic share operations")
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

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
