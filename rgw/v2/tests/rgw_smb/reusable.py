"""
Reusable helpers for RGW-backed SMB share operations.
"""

import json
import logging
import os
import subprocess
import tempfile
import time

import yaml
from v2.lib.exceptions import TestExecError
from v2.utils import utils

log = logging.getLogger()


def is_smb_mgr_module_enabled():
    """
    Check whether the smb mgr module is enabled.
    Uses: ceph mgr module ls | grep smb
    Module is enabled when the matched line contains 'on'.
    """
    log.info("Checking if smb mgr module is enabled")
    out = utils.exec_shell_cmd("ceph mgr module ls | grep smb")
    if out is False or not str(out).strip():
        log.info("smb mgr module is not enabled")
        return False

    # Example: "smb                   on"
    enabled = "on" in str(out).lower()
    log.info(f"smb mgr module ls|grep smb output: {out.strip()}")
    log.info(f"smb mgr module enabled: {enabled}")
    return enabled


def enable_smb_mgr_module():
    """
    Enable the smb mgr module.
    """
    log.info("Enabling smb mgr module")
    out = utils.exec_shell_cmd("ceph mgr module enable smb")
    if out is False:
        raise TestExecError("Failed to enable smb mgr module")
    log.info(f"smb mgr module enable output: {out}")
    return out


def ensure_smb_mgr_module_enabled():
    """
    Ensure smb mgr module is enabled; enable it if needed.
    """
    if is_smb_mgr_module_enabled():
        log.info("smb mgr module already enabled")
        return True

    enable_smb_mgr_module()
    # Re-check after enable
    if not is_smb_mgr_module_enabled():
        raise TestExecError("smb mgr module is still not enabled after enable")
    log.info("smb mgr module enabled successfully")
    return True


def create_smb_cluster(
    cluster_id, auth_mode="user", define_user_pass=None, placement=None
):
    """
    Create an SMB cluster.
    Args:
        cluster_id(str): SMB cluster id
        auth_mode(str): Authentication mode (user|active-directory)
        define_user_pass(str): Optional user%password for user auth mode
        placement(str): Optional placement string
    """
    log.info(f"Creating SMB cluster: {cluster_id}")
    cmd = f"ceph smb cluster create {cluster_id} {auth_mode}"
    if define_user_pass:
        cmd += f" --define-user-pass={define_user_pass}"
    if placement:
        cmd += f" --placement={placement}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"Failed to create SMB cluster {cluster_id}")
    log.info(f"SMB cluster create output: {out}")
    return out


def _share_ids_from_list(share_list):
    """
    Return share ids from ceph smb share ls output.
    """
    if isinstance(share_list, list):
        share_ids = []
        for item in share_list:
            if isinstance(item, str):
                share_ids.append(item)
            elif isinstance(item, dict):
                share_id = item.get("share_id") or item.get("id")
                if share_id:
                    share_ids.append(str(share_id))
        return share_ids
    if isinstance(share_list, dict):
        nested = share_list.get("shares") or share_list.get("results")
        if isinstance(nested, list):
            return _share_ids_from_list(nested)
        return [str(key) for key in share_list.keys()]
    if isinstance(share_list, str):
        return [line.strip() for line in share_list.splitlines() if line.strip()]
    return []


def remove_shares_on_cluster(cluster_id):
    """
    Remove every share on cluster_id.

    Ceph rejects cluster removal with EAGAIN and "cluster in use by shares"
    while any share still references the cluster.
    """
    try:
        share_list = list_smb_shares(cluster_id)
    except TestExecError as exc:
        log.info(f"Could not list shares for cluster {cluster_id}: {exc}")
        return []

    share_ids = _share_ids_from_list(share_list)
    if not share_ids:
        log.info(f"No shares remain on SMB cluster {cluster_id}")
        return []

    log.info(
        f"SMB cluster {cluster_id} is still used by shares {share_ids}. "
        "Removing those shares before the cluster is deleted."
    )
    removed = []
    for share_id in share_ids:
        returncode, out, err = _run_shell_cmd(
            f"ceph smb share rm {cluster_id} {share_id}"
        )
        combined = "\n".join(part for part in (out, err) if part).strip()
        if returncode != 0:
            log.warning(
                f"Failed to remove share {share_id} from cluster "
                f"{cluster_id}: {combined}"
            )
            continue
        log.info(f"Removed share {share_id} from cluster {cluster_id}")
        removed.append(share_id)
    return removed


def remove_smb_cluster(cluster_id, retry_count=6, retry_interval=5):
    """
    Remove an SMB cluster.

    Shares that still reference the cluster are removed first. Cluster
    removal is retried when Ceph returns EAGAIN / "cluster in use by shares".
    Args:
        cluster_id(str): SMB cluster id
        retry_count(int): Attempts to remove the cluster
        retry_interval(int): Seconds to wait between attempts
    """
    log.info(f"Removing SMB cluster: {cluster_id}")
    last_output = ""
    for attempt in range(1, retry_count + 1):
        remove_shares_on_cluster(cluster_id)
        returncode, out, err = _run_shell_cmd(f"ceph smb cluster rm {cluster_id}")
        combined = "\n".join(part for part in (out, err) if part).strip()
        last_output = combined
        if returncode == 0:
            log.info(f"SMB cluster remove output: {combined}")
            return combined

        in_use = "cluster in use by shares" in combined.lower()
        if not in_use and "eagain" not in combined.lower():
            raise TestExecError(
                f"Failed to remove SMB cluster {cluster_id}: {combined}"
            )
        log.warning(
            f"SMB cluster {cluster_id} is still in use by shares "
            f"(attempt {attempt}/{retry_count}): {combined}"
        )
        if attempt < retry_count:
            time.sleep(retry_interval)

    raise TestExecError(
        f"Failed to remove SMB cluster {cluster_id}: cluster in use by "
        f"shares. Last output: {last_output}"
    )


def list_smb_clusters(fmt="json"):
    """
    List SMB clusters.
    Args:
        fmt(str): Output format (json|yaml)
    Returns:
        Parsed JSON (list/dict) or raw string for non-json formats
    """
    log.info("Listing SMB clusters")
    cmd = f"ceph smb cluster ls --format={fmt}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("Failed to list SMB clusters")
    log.info(f"SMB cluster list output: {out}")
    if fmt == "json":
        try:
            return json.loads(out)
        except (TypeError, json.JSONDecodeError):
            return out
    return out


def cluster_in_list(cluster_list, cluster_id):
    """
    Return True if cluster_id is present in cluster list output.
    """
    cluster_ids = []
    if isinstance(cluster_list, list):
        for item in cluster_list:
            if isinstance(item, str):
                cluster_ids.append(item)
            elif isinstance(item, dict):
                cluster_ids.append(
                    item.get("cluster_id") or item.get("id") or str(item)
                )
    elif isinstance(cluster_list, dict):
        cluster_ids = list(cluster_list.keys())
    elif isinstance(cluster_list, str):
        cluster_ids = [
            line.strip() for line in cluster_list.splitlines() if line.strip()
        ]

    present = cluster_id in cluster_ids or any(
        cluster_id in str(c) for c in cluster_ids
    )
    log.info(
        f"Cluster ids found: {cluster_ids}; looking for {cluster_id}; "
        f"present={present}"
    )
    return present


def verify_cluster_in_list(cluster_list, cluster_id, expect_present=True):
    """
    Verify whether cluster_id is present in cluster list output.
    """
    present = cluster_in_list(cluster_list, cluster_id)
    if expect_present and not present:
        raise TestExecError(
            f"Expected cluster {cluster_id} in list, but it was not found"
        )
    if not expect_present and present:
        raise TestExecError(
            f"Cluster {cluster_id} still present in list after deletion"
        )
    return present


def list_smb_orch_services(fmt="json"):
    """
    List SMB services from ceph orch.
    """
    log.info("Listing SMB services via ceph orch ls")
    cmd = f"ceph orch ls --service-type smb --format {fmt}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("Failed to list SMB services via ceph orch ls")
    log.info(f"SMB orch ls output: {out}")
    if fmt == "json":
        if not out or not str(out).strip():
            return []
        try:
            parsed = json.loads(out)
            return parsed if parsed else []
        except (TypeError, json.JSONDecodeError):
            return out
    return out


def list_smb_orch_daemons(fmt="json"):
    """
    List SMB daemons from ceph orch ps.
    """
    log.info("Listing SMB daemons via ceph orch ps")
    cmd = f"ceph orch ps --daemon-type smb --format {fmt}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        # Empty/no matching daemons can still be a valid post-delete state.
        log.warning("ceph orch ps for smb returned failure/empty output")
        return []
    log.info(f"SMB orch ps output: {out}")
    if fmt == "json":
        if not out or not str(out).strip():
            return []
        try:
            parsed = json.loads(out)
            return parsed if parsed else []
        except (TypeError, json.JSONDecodeError):
            return out
    return out


def _smb_service_matches_cluster(entry, cluster_id):
    """
    Return True if orch service/daemon entry belongs to cluster_id.
    Typical service_name: smb.<cluster_id>
    """
    if isinstance(entry, str):
        return cluster_id in entry
    if not isinstance(entry, dict):
        return cluster_id in str(entry)

    service_name = entry.get("service_name") or entry.get("service_id") or ""
    daemon_name = entry.get("daemon_name") or entry.get("daemon_id") or ""
    service_id = entry.get("service_id") or ""
    candidates = [service_name, daemon_name, service_id, str(entry)]
    expected = f"smb.{cluster_id}"
    return any(
        expected == c
        or c.endswith(f".{cluster_id}")
        or cluster_id == c
        or cluster_id in c
        for c in candidates
        if c
    )


def get_smb_service_daemon_status(cluster_id):
    """
    Return (service_available, daemon_available) for cluster_id.
    """
    services = list_smb_orch_services()
    daemons = list_smb_orch_daemons()
    service_available = False
    daemon_available = False

    if isinstance(services, list):
        service_available = any(
            _smb_service_matches_cluster(svc, cluster_id) for svc in services
        )
    elif isinstance(services, str):
        service_available = cluster_id in services

    if isinstance(daemons, list):
        daemon_available = any(
            _smb_service_matches_cluster(dmn, cluster_id) for dmn in daemons
        )
    elif isinstance(daemons, str):
        daemon_available = cluster_id in daemons

    log.info(
        f"SMB orch status for cluster {cluster_id}: "
        f"service_available={service_available}, "
        f"daemon_available={daemon_available}"
    )
    return service_available, daemon_available


def is_smb_service_available(cluster_id):
    """
    Available only when both service and daemon are present.
    """
    service_available, daemon_available = get_smb_service_daemon_status(cluster_id)
    available = service_available and daemon_available
    log.info(
        f"SMB availability for cluster {cluster_id}: available={available} "
        f"(service AND daemon)"
    )
    return available


def is_smb_service_unavailable(cluster_id):
    """
    Not available only when both service and daemon are absent.
    """
    service_available, daemon_available = get_smb_service_daemon_status(cluster_id)
    unavailable = (not service_available) and (not daemon_available)
    log.info(
        f"SMB unavailability for cluster {cluster_id}: unavailable={unavailable} "
        f"(service AND daemon absent)"
    )
    return unavailable


def verify_smb_service_available(
    cluster_id, expect_present=True, retry_count=12, retry_interval=10
):
    """
    Verify SMB service availability for a cluster via ceph orch.

    available = service available AND daemon available
    not available = service not available AND daemon not available

    Args:
        cluster_id(str): SMB cluster id
        expect_present(bool): True if service should exist, False if removed
        retry_count(int): Number of retries while waiting for orch state
        retry_interval(int): Seconds between retries
    """
    for attempt in range(1, retry_count + 1):
        service_available, daemon_available = get_smb_service_daemon_status(cluster_id)
        available = service_available and daemon_available
        unavailable = (not service_available) and (not daemon_available)
        log.info(
            f"Attempt {attempt}/{retry_count}: cluster={cluster_id}, "
            f"service_available={service_available}, "
            f"daemon_available={daemon_available}, "
            f"available={available}, unavailable={unavailable}, "
            f"expect_present={expect_present}"
        )
        if expect_present and available:
            log.info(f"SMB service and daemon for cluster {cluster_id} are available")
            return True
        if not expect_present and unavailable:
            log.info(
                f"SMB service and daemon for cluster {cluster_id} are not available"
            )
            return True
        if attempt < retry_count:
            time.sleep(retry_interval)

    service_available, daemon_available = get_smb_service_daemon_status(cluster_id)
    if expect_present:
        raise TestExecError(
            f"SMB service/daemon for cluster {cluster_id} not fully available "
            f"(service_available={service_available}, "
            f"daemon_available={daemon_available})"
        )
    raise TestExecError(
        f"SMB service/daemon for cluster {cluster_id} still present after "
        f"deletion (service_available={service_available}, "
        f"daemon_available={daemon_available})"
    )


def _radosgw_admin_json(cmd, action):
    """
    Run a radosgw-admin command and return parsed JSON.
    """
    out = utils.exec_shell_cmd(cmd)
    if out is False or not str(out).strip():
        raise TestExecError(f"{action} failed")
    try:
        return json.loads(out)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TestExecError(f"{action} output is not JSON: {exc}") from exc


def rgw_user_exists(user_id):
    """
    Return True when user_id is present in radosgw-admin user list.
    """
    log.info(f"Checking whether RGW user {user_id} exists")
    existing = _radosgw_admin_json("radosgw-admin user list", "radosgw-admin user list")
    exists = isinstance(existing, list) and user_id in existing
    log.info(f"RGW user {user_id} exists: {exists}")
    return exists


def qualified_rgw_user_id(user_id, tenant=None):
    """
    Return the RGW user id used by SMB credentials.

    A tenanted user is tenant$uid. The short uid is unchanged when tenant
    is not set.
    """
    if not tenant:
        return user_id
    short_id = str(user_id).split("$", 1)[-1]
    return f"{tenant}${short_id}"


def create_rgw_user(
    user_id, secret_key=None, access_key=None, display_name=None, tenant=None
):
    """
    Create an RGW user, optionally with a fixed access key and secret key.

    When the uid already exists, an S3 key is added instead of replacing
    the user. The returned key is the one that matches secret_key when
    secret_key is set.

    tenant creates the user in that RGW tenant. The returned user_id is
    tenant$uid, which is the id SMB stores on the RGW credential.
    """
    short_id = str(user_id).split("$", 1)[-1] if tenant else user_id
    full_id = qualified_rgw_user_id(short_id, tenant)
    display_name = display_name or short_id
    log.info(f"Creating RGW user: {full_id}")
    prefix = "radosgw-admin"
    if tenant:
        prefix += f" --tenant='{tenant}'"
    if rgw_user_exists(full_id):
        log.info(f"RGW user {full_id} already exists, adding an S3 key")
        cmd = f"{prefix} key create --uid='{short_id}' --key-type=s3"
    else:
        cmd = (
            f"{prefix} user create --uid='{short_id}' "
            f"--display-name='{display_name}'"
        )
    if access_key:
        cmd += f" --access-key='{access_key}'"
    else:
        cmd += " --gen-access-key"
    if secret_key is not None:
        cmd += f" --secret-key='{secret_key}'"
    else:
        cmd += " --gen-secret"

    user_json = _radosgw_admin_json(cmd, f"create RGW user {full_id}")
    if user_json.get("keys"):
        keys = user_json["keys"]
    elif user_json.get("access_key"):
        keys = [user_json]
        user_json = {
            "user_id": user_json.get("user") or full_id,
            "display_name": display_name,
        }
    else:
        keys = []
    if not keys:
        raise TestExecError(f"RGW user {full_id} was created without S3 keys")

    chosen = None
    if secret_key is not None:
        for key in keys:
            if key.get("secret_key") == str(secret_key):
                chosen = key
                break
        if chosen is None:
            raise TestExecError(
                f"RGW user {user_id} has no key with secret_key {secret_key!r}"
            )
    elif access_key:
        for key in keys:
            if key.get("access_key") == access_key:
                chosen = key
                break
        if chosen is None:
            raise TestExecError(
                f"RGW user {user_id} has no key with access_key {access_key!r}"
            )
    else:
        chosen = keys[-1]

    resolved_id = user_json.get("user_id") or full_id
    if tenant and "$" not in str(resolved_id):
        resolved_id = full_id
    user_details = {
        "user_id": resolved_id,
        "display_name": user_json.get("display_name"),
        "access_key": chosen["access_key"],
        "secret_key": chosen["secret_key"],
    }
    if tenant:
        user_details["tenant"] = tenant
    log.info(
        f"RGW user created: user_id={user_details['user_id']}, "
        f"access_key={user_details['access_key']}"
    )
    return user_details


def remove_rgw_user(user_id, tenant=None):
    """
    Remove an RGW user and purge that user's keys and data.

    tenant is added to user_id when the id is not already tenant$uid.
    The uid is quoted so the shell does not expand '$'.
    """
    uid = qualified_rgw_user_id(user_id, tenant)
    log.info(f"Removing RGW user: {uid}")
    out = utils.exec_shell_cmd(
        f"radosgw-admin user rm --uid='{uid}' --purge-keys --purge-data"
    )
    if out is False:
        raise TestExecError(f"Failed to remove RGW user {uid}")
    log.info(f"RGW user remove output: {out}")
    return out


def get_bucket_owner(bucket_name, tenant=None):
    """
    Return the owning user id for a bucket.

    tenant looks up tenant/bucket. A tenanted bucket is not visible as
    the bare bucket name.
    """
    bucket_ref = bucket_name
    if tenant and "/" not in str(bucket_name):
        bucket_ref = f"{tenant}/{bucket_name}"
    log.info(f"Fetching owner of bucket {bucket_ref}")
    stats = _radosgw_admin_json(
        f"radosgw-admin bucket stats --bucket '{bucket_ref}'",
        f"bucket stats for {bucket_ref}",
    )
    owner = stats.get("owner")
    if isinstance(owner, dict):
        owner = owner.get("id") or owner.get("user_id")
    if not owner:
        raise TestExecError(f"bucket {bucket_name} stats did not include an owner")
    log.info(f"Bucket {bucket_name} owner: {owner}")
    return owner


def list_buckets_for_user(user_id):
    """
    Return the bucket names owned by user_id.
    """
    log.info(f"Listing buckets owned by user {user_id}")
    out = utils.exec_shell_cmd(f"radosgw-admin bucket list --uid='{user_id}'")
    if out is False:
        raise TestExecError(f"Failed to list buckets for user {user_id}")
    if not str(out).strip():
        return []
    try:
        buckets = json.loads(out)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TestExecError(f"bucket list output is not JSON: {exc}") from exc
    if not isinstance(buckets, list):
        raise TestExecError(f"bucket list for user {user_id} was not a list: {buckets}")
    log.info(f"Buckets for user {user_id}: {buckets}")
    return buckets


def user_associated_with_bucket(user_id, bucket_name):
    """
    Return True when user_id is associated with bucket_name.

    Association means the user owns the bucket: the bucket owner is user_id,
    or the bucket is listed for that user. A user id of tenant$uid is
    compared against that tenant's bucket.
    """
    tenant = None
    short_id = user_id
    if "$" in str(user_id):
        tenant, short_id = str(user_id).split("$", 1)
    owner = None
    try:
        owner = get_bucket_owner(bucket_name, tenant=tenant)
    except TestExecError as exc:
        if tenant:
            raise
        log.info(f"Bucket stats for {bucket_name} did not return an owner: {exc}")
    buckets = list_buckets_for_user(user_id)
    bucket_names = {bucket_name}
    if tenant:
        bucket_names.add(f"{tenant}/{bucket_name}")
        owner_matches = owner in (user_id, short_id, f"{tenant}${short_id}")
    else:
        owner_matches = owner == user_id
    associated = bool(owner_matches or any(name in buckets for name in bucket_names))
    log.info(
        f"User {user_id} associated with bucket {bucket_name}: {associated} "
        f"(owner={owner}, tenant={tenant})"
    )
    return associated


def build_rgw_share_resources(
    cluster_id,
    share_id,
    share_name,
    bucket_name,
    credential_id,
    user_id,
    access_key,
    secret_key,
):
    """
    Build declarative SMB resource list for RGW-backed share + credential.
    """
    return [
        {
            "resource_type": "ceph.smb.rgw.credential",
            "rgw_credential_id": credential_id,
            "user_id": user_id,
            "access_key_id": access_key,
            "secret_access_key": secret_key,
        },
        {
            "resource_type": "ceph.smb.share",
            "cluster_id": cluster_id,
            "share_id": share_id,
            "name": share_name,
            "rgw": {
                "bucket": bucket_name,
                "credential_ref": credential_id,
            },
        },
    ]


def build_remove_rgw_share_resources(
    cluster_id, share_id, credential_id, user_id, access_key, secret_key
):
    """
    Build declarative SMB resource list to remove share and credential.

    Credential specification must include the user_id, access_key and
    secret_key associated with the RGW credential.
    """
    return [
        {
            "resource_type": "ceph.smb.share",
            "cluster_id": cluster_id,
            "share_id": share_id,
            "intent": "removed",
        },
        {
            "resource_type": "ceph.smb.rgw.credential",
            "rgw_credential_id": credential_id,
            "intent": "removed",
            "user_id": user_id,
            "access_key_id": access_key,
            "secret_access_key": secret_key,
        },
    ]


def write_smb_resources_file(resources, file_path=None):
    """
    Write SMB resource list to a YAML file.
    Args:
        resources(list): List of SMB resource dicts
        file_path(str): Optional path; tempfile used if not provided
    Returns:
        str: Path to written YAML file
    """
    if file_path is None:
        fd, file_path = tempfile.mkstemp(prefix="smb_resources_", suffix=".yaml")
        os.close(fd)
    with open(file_path, "w") as fout:
        yaml.safe_dump(resources, fout, default_flow_style=False, sort_keys=False)
    log.info(f"SMB resources written to: {file_path}")
    log.info(f"SMB resources content:\n{yaml.safe_dump(resources, sort_keys=False)}")
    return file_path


def _run_shell_cmd(cmd):
    """
    Run a shell command and return (returncode, stdout, stderr).

    A non-zero exit is returned to the caller. It is not treated as a crash.
    """
    log.info("executing cmd: %s" % cmd)
    pr = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=False,
        shell=True,
    )
    out, err = pr.communicate()
    out = out.decode("utf-8", errors="ignore") if out else ""
    err = err.decode("utf-8", errors="ignore") if err else ""
    log.info(f"cmd returncode: {pr.returncode}")
    if out:
        log.info(out)
    if err:
        log.info(err)
    return pr.returncode, out, err


def apply_smb_resources(
    resources, file_path=None, cleanup_file=True, expect_failure=False
):
    """
    Apply SMB resources using declarative ceph smb apply.
    Args:
        resources(list): List of SMB resource dicts
        file_path(str): Optional YAML path to write/use
        cleanup_file(bool): Delete temp YAML after apply
        expect_failure(bool): When True, a non-zero exit is the expected
            result and a successful apply is a test failure. Use this for
            validation that must reject the spec before a share is created.
    """
    resource_file = write_smb_resources_file(resources, file_path=file_path)
    try:
        log.info(f"Applying SMB resources from {resource_file}")
        cmd = f"ceph smb apply -i {resource_file}"
        returncode, out, err = _run_shell_cmd(cmd)
        combined = "\n".join(part for part in (out, err) if part).strip()
        if expect_failure:
            if returncode == 0:
                raise TestExecError(
                    "ceph smb apply succeeded, but failure was required "
                    f"before the share is created. output: {combined}"
                )
            log.info(f"ceph smb apply failed as expected: {combined}")
            return combined
        if returncode != 0:
            raise TestExecError(f"ceph smb apply failed: {combined}")
        log.info(f"ceph smb apply output: {combined}")
        return combined
    finally:
        if cleanup_file and os.path.exists(resource_file):
            os.remove(resource_file)


def list_smb_shares(cluster_id, fmt="json"):
    """
    List SMB shares for a cluster.
    Args:
        cluster_id(str): SMB cluster id
        fmt(str): Output format (json|yaml)
    Returns:
        Parsed JSON (list/dict) or raw string for non-json formats
    """
    log.info(f"Listing SMB shares for cluster: {cluster_id}")
    cmd = f"ceph smb share ls {cluster_id} --format={fmt}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"Failed to list SMB shares for cluster {cluster_id}")
    log.info(f"SMB share list output: {out}")
    if fmt == "json":
        try:
            return json.loads(out)
        except (TypeError, json.JSONDecodeError):
            return out
    return out


def show_smb_share(cluster_id, share_id, fmt="json"):
    """
    Show a specific SMB share resource.
    """
    resource_name = f"ceph.smb.share.{cluster_id}.{share_id}"
    log.info(f"Showing SMB share resource: {resource_name}")
    cmd = f"ceph smb show {resource_name} --format={fmt}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"Failed to show SMB share {resource_name}")
    log.info(f"SMB share show output: {out}")
    if fmt == "json":
        try:
            return json.loads(out)
        except (TypeError, json.JSONDecodeError):
            return out
    return out


def remove_smb_share(cluster_id, share_id):
    """
    Remove an SMB share using imperative command.
    """
    log.info(f"Removing SMB share {share_id} from cluster {cluster_id}")
    cmd = f"ceph smb share rm {cluster_id} {share_id}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(
            f"Failed to remove SMB share {share_id} from cluster {cluster_id}"
        )
    log.info(f"SMB share remove output: {out}")
    return out


def share_in_list(share_list, share_id):
    """
    Return True if share_id is present in share list output.
    """
    share_ids = []
    if isinstance(share_list, list):
        for item in share_list:
            if isinstance(item, str):
                share_ids.append(item)
            elif isinstance(item, dict):
                share_ids.append(item.get("share_id") or item.get("id") or str(item))
    elif isinstance(share_list, dict):
        share_ids = list(share_list.keys())
    elif isinstance(share_list, str):
        share_ids = [line.strip() for line in share_list.splitlines() if line.strip()]

    present = share_id in share_ids or any(share_id in str(s) for s in share_ids)
    log.info(f"Share ids found: {share_ids}; looking for {share_id}; present={present}")
    return present


def verify_share_in_list(share_list, share_id, expect_present=True):
    """
    Verify whether share_id is present in share list output.
    """
    present = share_in_list(share_list, share_id)
    if expect_present and not present:
        raise TestExecError(f"Expected share {share_id} in list, but it was not found")
    if not expect_present and present:
        raise TestExecError(f"Share {share_id} still present in list after deletion")
    return present


SMBCLIENT_FAILURE_MARKERS = (
    "NT_STATUS_ACCESS_DENIED",
    "NT_STATUS_LOGON_FAILURE",
    "NT_STATUS_BAD_NETWORK_NAME",
    "NT_STATUS_OBJECT_NAME_NOT_FOUND",
    "NT_STATUS_UNSUCCESSFUL",
    "NT_STATUS_CONNECTION_REFUSED",
    "NT_STATUS_HOST_UNREACHABLE",
    "NT_STATUS_IO_TIMEOUT",
    "NT_STATUS_NETWORK_UNREACHABLE",
)


def parse_smb_user_pass(define_user_pass):
    """
    Parse SMB user%password string used by --define-user-pass.
    """
    if not define_user_pass or "%" not in str(define_user_pass):
        raise TestExecError(
            "define_user_pass must be in '<smbuser>%<smbpasswd>' format"
        )
    username, password = str(define_user_pass).split("%", 1)
    if not username or not password:
        raise TestExecError("define_user_pass must include both smb user and password")
    return username, password


def install_samba_client():
    """
    Install samba-client on the client node if smbclient is not present.
    """
    log.info("Installing samba-client on the client node if needed")
    out = utils.exec_shell_cmd(
        "rpm -q samba-client || sudo yum install -y samba-client"
    )
    if out is False:
        raise TestExecError("Failed to install samba-client")

    smbclient_path = utils.exec_shell_cmd("command -v smbclient")
    if not smbclient_path or not str(smbclient_path).strip():
        raise TestExecError("smbclient not found after installing samba-client")
    log.info(f"samba-client ready; smbclient path={smbclient_path.strip()}")
    return smbclient_path.strip()


def list_orch_hosts(fmt="json"):
    """
    List ceph orch hosts.
    """
    log.info("Listing ceph orch hosts")
    cmd = f"ceph orch host ls --format {fmt}"
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("Failed to list ceph orch hosts")
    log.info(f"ceph orch host ls output: {out}")
    if fmt == "json":
        if not out or not str(out).strip():
            return []
        try:
            parsed = json.loads(out)
            return parsed if parsed else []
        except (TypeError, json.JSONDecodeError):
            return out
    return out


def get_host_addr_map():
    """
    Return hostname -> IP mapping from ceph orch host ls.
    """
    hosts = list_orch_hosts()
    host_addrs = {}
    if not isinstance(hosts, list):
        log.warning(f"Unexpected orch host ls format: {type(hosts)}")
        return host_addrs
    for host in hosts:
        if not isinstance(host, dict):
            continue
        hostname = host.get("hostname")
        addr = host.get("addr")
        if hostname and addr:
            host_addrs[hostname] = str(addr).split("%")[0]
    log.info(f"Orch host address map: {host_addrs}")
    return host_addrs


def get_smb_endpoints(cluster_id):
    """
    Resolve SMB endpoints (IP and port) for a cluster from ceph orch.

    Returns:
        list of dicts: [{"hostname": ..., "ip": ..., "port": ...}, ...]
    """
    daemons = list_smb_orch_daemons()
    host_addrs = get_host_addr_map()
    endpoints = []

    daemon_entries = daemons if isinstance(daemons, list) else []
    for dmn in daemon_entries:
        if not _smb_service_matches_cluster(dmn, cluster_id):
            continue
        if not isinstance(dmn, dict):
            continue
        hostname = dmn.get("hostname")
        ip = dmn.get("ip") or host_addrs.get(hostname) or hostname
        ports = dmn.get("ports") or []
        port = ports[0] if ports else 445
        status_desc = dmn.get("status_desc") or ""
        log.info(
            f"SMB daemon for cluster {cluster_id}: hostname={hostname}, "
            f"ip={ip}, port={port}, status={status_desc}"
        )
        if ip:
            endpoints.append(
                {
                    "hostname": hostname,
                    "ip": ip,
                    "port": port,
                    "status": status_desc,
                }
            )

    if not endpoints:
        raise TestExecError(
            f"No SMB endpoint found for cluster {cluster_id} from ceph orch ps"
        )
    log.info(f"Resolved SMB endpoints for cluster {cluster_id}: {endpoints}")
    return endpoints


def get_smb_endpoint(cluster_id, smb_endpoint=None):
    """
    Return SMB host/IP.

    Uses explicit smb_endpoint when provided; otherwise discovers from orch.
    """
    if smb_endpoint:
        log.info(f"Using configured SMB endpoint {smb_endpoint}")
        return smb_endpoint

    endpoints = get_smb_endpoints(cluster_id)
    selected = endpoints[0]
    log.info(f"Using discovered SMB endpoint {selected['ip']}")
    return selected["ip"]


def build_smbclient_cmd(endpoint, share_name, username, password, commands="ls"):
    """
    Build smbclient command to access an SMB share non-interactively.
    """
    return (
        f"smbclient //{endpoint}/{share_name} "
        f"-U '{username}%{password}' -c '{commands}'"
    )


def smbclient_access_share(
    endpoint,
    share_name,
    username,
    password,
    commands="ls",
    retry_count=12,
    retry_interval=10,
):
    """
    Access an SMB share from the client node using samba-client.

    Command:
        smbclient //<smb-endpoint>/<sharename> -U <smbuser>%<smbpasswd>
    """
    cmd = build_smbclient_cmd(endpoint, share_name, username, password, commands)
    last_out = None
    for attempt in range(1, retry_count + 1):
        log.info(
            f"Accessing SMB share //{endpoint}/{share_name} "
            f"(attempt {attempt}/{retry_count})"
        )
        out = utils.exec_shell_cmd(cmd)
        last_out = out
        out_text = "" if out is False else str(out)
        failed_marker = next(
            (marker for marker in SMBCLIENT_FAILURE_MARKERS if marker in out_text),
            None,
        )
        if out is not False and not failed_marker:
            log.info(f"smbclient access succeeded for //{endpoint}/{share_name}: {out}")
            return out
        log.warning(
            f"smbclient attempt {attempt} failed for //{endpoint}/{share_name}; "
            f"marker={failed_marker}, output={out}"
        )
        if attempt < retry_count:
            time.sleep(retry_interval)

    raise TestExecError(
        f"Failed to access SMB share //{endpoint}/{share_name} using smbclient. "
        f"Last output: {last_out}"
    )


def mount_smb_share_with_smbclient(
    cluster_id,
    share_name,
    define_user_pass,
    smb_endpoint=None,
    smbclient_io=False,
    test_file_path=None,
    expected_names=None,
    delete_one_file=False,
):
    """
    Install samba-client and mount/access the RGW-backed SMB share.

    Args:
        cluster_id(str): SMB cluster id
        share_name(str): Samba share name (not share_id)
        define_user_pass(str): SMB credentials in user%password format
        smb_endpoint(str): Optional explicit SMB host/IP
        smbclient_io(bool): If True, put a test file and list it
        test_file_path(str): Local file used for optional put
        expected_names(list): Optional object/file names that must appear in ls
        delete_one_file(bool): If True, delete one listed file and re-validate
    """
    install_samba_client()
    username, password = parse_smb_user_pass(define_user_pass)
    endpoint = get_smb_endpoint(cluster_id, smb_endpoint=smb_endpoint)
    log.info(
        f"Mounting SMB share via samba-client: "
        f"//{endpoint}/{share_name} as user {username}"
    )
    ls_out = smbclient_access_share(
        endpoint, share_name, username, password, commands="ls"
    )
    if expected_names:
        missing = [name for name in expected_names if name not in str(ls_out)]
        if missing:
            raise TestExecError(
                f"smbclient ls did not list expected objects {missing}. "
                f"Output: {ls_out}"
            )
        log.info(f"smbclient ls listed expected objects: {expected_names}")

        if delete_one_file:
            file_to_delete = expected_names[0]
            log.info(
                f"Deleting file {file_to_delete} from SMB share {share_name} "
                f"using smbclient"
            )
            smbclient_access_share(
                endpoint,
                share_name,
                username,
                password,
                commands=f'del "{file_to_delete}"',
            )
            ls_after_delete = smbclient_access_share(
                endpoint, share_name, username, password, commands="ls"
            )
            if file_to_delete in str(ls_after_delete):
                raise TestExecError(
                    f"File {file_to_delete} still listed on SMB share after "
                    f"smbclient del. Output: {ls_after_delete}"
                )
            remaining = expected_names[1:]
            missing_remaining = [
                name for name in remaining if name not in str(ls_after_delete)
            ]
            if missing_remaining:
                raise TestExecError(
                    f"Unexpected missing files after deleting {file_to_delete}: "
                    f"{missing_remaining}. Output: {ls_after_delete}"
                )
            log.info(
                f"Verified {file_to_delete} is removed from SMB share {share_name}"
            )

    if smbclient_io:
        if not test_file_path:
            test_file_path = "/tmp/rgw_smb_mount_test.txt"
        remote_name = os.path.basename(test_file_path)
        if not os.path.exists(test_file_path):
            with open(test_file_path, "w") as fout:
                fout.write("rgw-smb-mount-test\n")
        log.info(f"Putting test file {test_file_path} onto SMB share {share_name}")
        io_out = smbclient_access_share(
            endpoint,
            share_name,
            username,
            password,
            commands=f"put {test_file_path} {remote_name}; ls",
        )
        if remote_name not in str(io_out):
            raise TestExecError(
                f"File {remote_name} not found in smbclient ls after put. "
                f"Output: {io_out}"
            )
        log.info(f"Verified {remote_name} is listed on SMB share {share_name}")
        return io_out

    return ls_out
