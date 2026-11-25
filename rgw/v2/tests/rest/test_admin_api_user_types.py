"""
test_admin_api_user_types - Config-driven AdminOps REST coverage

Usage: test_admin_api_user_types.py -c <input_yaml>

<input_yaml>
        configs/test_admin_api_user_types.yaml

Operation:
    Runs each enabled test_ops flag by calling reusable AdminOps helpers from
    v2.tests.rest.reusable (no inline AdminOps curl in this script).
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import re
import string
import traceback

import names
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.rest import reusable as rest_reusable
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def _rand_uid(prefix="u"):
    return (
        f"{prefix}-"
        + names.get_first_name().lower()
        + random.choice(string.ascii_lowercase)
        + str(random.randint(1, 9999))
    )


def _rand_account_id():
    return "RGW" + "".join(str(random.randint(0, 9)) for _ in range(17))


def _iam_display_name(preferred=None):
    """
    Account users require IAM-safe display names (Ceph validate_iam_user_name):
    [\\w+=,.@-]+ only — no spaces.
    """
    raw = preferred or names.get_full_name().lower()
    safe = re.sub(r"[^\w+=,.@-]", "-", str(raw)).strip("-")
    return (safe or "user")[:64]


def _seed_admin_creds(ssh_con):
    out = utils.exec_shell_cmd("radosgw-admin user info --uid=repuser")
    if (
        out
        and "NoSuchUser" not in str(out)
        and "could not fetch" not in str(out).lower()
    ):
        try:
            info = rest_reusable.parse_json_response(out, "repuser")
            return info["keys"][0]["access_key"], info["keys"][0]["secret_key"], info
        except Exception:
            pass

    uid = "adminops-rest-seed"
    display = "adminops rest seed"
    existing = utils.exec_shell_cmd(f"radosgw-admin user info --uid={uid}")
    if (
        not existing
        or "NoSuchUser" in str(existing)
        or "could not fetch" in str(existing).lower()
    ):
        # --system so AdminOps can create system users (REST rejects system=True
        # unless the caller itself is a system user).
        utils.exec_shell_cmd(
            f"radosgw-admin user create --uid={uid} "
            f"--display-name='{display}' --system"
        )
    utils.exec_shell_cmd(
        f"radosgw-admin caps add --uid={uid} "
        f'--caps="users=*;accounts=*;buckets=*;metadata=*;usage=*"'
    )
    # Ensure system flag if seed already existed without --system
    utils.exec_shell_cmd(f"radosgw-admin user modify --uid={uid} --system")
    info = rest_reusable.parse_json_response(
        utils.exec_shell_cmd(f"radosgw-admin user info --uid={uid}"), uid
    )
    return info["keys"][0]["access_key"], info["keys"][0]["secret_key"], info


class AdminOpsContext:
    """Shared state for config-driven AdminOps REST ops."""

    def __init__(self, endpoint, admin_key, admin_secret, admin_info):
        self.endpoint = endpoint
        self.admin_key = admin_key
        self.admin_secret = admin_secret
        self.admin_info = admin_info
        self.created_uids = []
        self.created_accounts = []
        self.tenant = None
        self.tenant_uid = None
        self.swift_uid = None
        self.swift_subuser = None
        self.swift_key_uid = None
        self.explicit_ak = None
        self.key_uid = None
        self.access_to_remove = None
        self.account_id = None
        self.account_tenant = None
        self.tenant_account_id = None
        self.quota_uid = None


def _ensure_tenant_parent(ctx):
    if ctx.tenant and ctx.tenant_uid:
        return
    ctx.tenant = "t" + rest_reusable.generate_random_string(6)
    ctx.tenant_uid = _rand_uid("ten")
    data = rest_reusable.create_tenant_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant,
        ctx.tenant_uid,
        names.get_full_name().lower(),
    )
    full_uid = data.get("full_user_id") or rest_reusable.resolve_tenanted_uid(
        ctx.tenant_uid, ctx.tenant
    )
    ctx.created_uids.append(full_uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        tenant=ctx.tenant,
    )
    if isinstance(info, dict) and info.get("Code"):
        raise TestExecError(f"tenant parent not readable after create: {info}")
    log.info(f"tenant parent ready: {full_uid}")


def _track_uid(ctx, uid, tenant=None):
    ctx.created_uids.append(rest_reusable.resolve_tenanted_uid(uid, tenant))


# --- config-driven operation handlers (YAML test_ops -> rest.reusable) ---


def op_list_users(ctx):
    listed = rest_reusable.list_users(ctx.endpoint, ctx.admin_key, ctx.admin_secret)
    keys = listed.get("keys") if isinstance(listed, dict) else listed
    if keys is None:
        raise TestExecError(f"list_users unexpected response: {listed}")
    log.info(f"list_users count={listed.get('count', len(keys))}")


def op_list_users_pagination(ctx):
    page = rest_reusable.list_users(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, max_entries=2
    )
    page_keys = page.get("keys") if isinstance(page, dict) else page
    if page_keys is None:
        raise TestExecError(f"list_users pagination unexpected: {page}")
    marker = None
    if isinstance(page, dict) and page.get("truncated") and page_keys:
        # RGW returns an opaque pool marker (e.g. "5:abc:users.uid::uid:head"),
        # not the last uid in keys — same as ceph qa radosgw_admin_rest.
        marker = page.get("marker")
        if not marker:
            raise TestExecError(f"list_users truncated without marker: {page}")
        nxt = rest_reusable.list_users(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            max_entries=2,
            marker=marker,
        )
        nxt_keys = nxt.get("keys") if isinstance(nxt, dict) else nxt
        if nxt_keys is None:
            raise TestExecError(f"list_users pagination next page unexpected: {nxt}")
    log.info(f"list_users pagination ok (marker={marker})")


def op_create_user_with_attrs(ctx):
    uid = _rand_uid("attrs")
    data = rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
        email=f"{uid}@example.com",
        max_buckets=50,
        op_mask="read,write,delete",
        generate_key=True,
    )
    _track_uid(ctx, uid)
    rest_reusable.modify_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        email=f"{uid}.mod@example.com",
        max_buckets=75,
        op_mask="read,write",
    )
    log.info(f"create/modify user attrs ok for {uid}: keys={bool(data.get('keys'))}")


def op_create_user_no_key(ctx):
    uid = _rand_uid("nokey")
    data = rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
        generate_key=False,
    )
    _track_uid(ctx, uid)
    if data.get("keys"):
        raise TestExecError(
            f"expected no keys on create with generate_key=False, got {data.get('keys')}"
        )
    k = rest_reusable.create_key(ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid)
    if not k.get("access_key"):
        raise TestExecError(f"create_key after no-key user failed: {k}")
    log.info(f"create_user_no_key ok: {uid}")


def op_create_user_exclusive(ctx):
    uid = _rand_uid("excl")
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
        exclusive=True,
    )
    _track_uid(ctx, uid)
    params = rest_reusable.build_query_params(
        {"uid": uid, "display-name": "dup", "format": "json", "exclusive": True}
    )
    resp = rest_reusable.admin_api_call(
        "PUT", ctx.endpoint, ctx.admin_key, ctx.admin_secret, params
    )
    resp_s = str(resp or "")
    if not resp_s or resp is False:
        raise TestExecError(f"exclusive recreate of {uid} returned empty response")
    if "UserExists" not in resp_s and "UserAlreadyExists" not in resp_s:
        if '"user_id"' in resp_s:
            raise TestExecError(
                f"exclusive recreate of {uid} unexpectedly succeeded: {resp}"
            )
        raise TestExecError(
            f"exclusive recreate of {uid} expected UserExists/UserAlreadyExists, got: {resp}"
        )
    log.info(f"create_user_exclusive ok: {uid}")


def op_create_user_explicit_keys(ctx):
    uid = _rand_uid("expl")
    ctx.explicit_ak = "AK" + rest_reusable.generate_random_string(18).upper()
    explicit_sk = rest_reusable.generate_random_string(40)
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
        access_key=ctx.explicit_ak,
        secret_key=explicit_sk,
        generate_key=False,
    )
    _track_uid(ctx, uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    aks = [k.get("access_key") for k in info.get("keys", [])]
    if ctx.explicit_ak not in aks:
        raise TestExecError(f"explicit key {ctx.explicit_ak} not in {aks}")
    log.info(f"create_user_explicit_keys ok: {uid}")


def op_get_user_by_access_key(ctx):
    if not ctx.explicit_ak:
        uid = _rand_uid("byak")
        data = rest_reusable.create_user(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            uid,
            names.get_full_name().lower(),
        )
        _track_uid(ctx, uid)
        ctx.explicit_ak = data["keys"][0]["access_key"]
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, access_key=ctx.explicit_ak
    )
    if not info.get("user_id"):
        raise TestExecError(f"get by access_key failed: {info}")
    log.info(f"get_user_by_access_key ok: {info.get('user_id')}")


def op_create_tenant_user(ctx):
    _ensure_tenant_parent(ctx)
    log.info(f"create_tenant_user ok: {ctx.tenant}${ctx.tenant_uid}")


def op_create_tenant_subuser(ctx):
    _ensure_tenant_parent(ctx)
    sub = "swift1"
    rest_reusable.create_tenant_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant,
        ctx.tenant_uid,
        sub,
        access="full",
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        tenant=ctx.tenant,
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    expected_forms = (
        f"{ctx.tenant}${ctx.tenant_uid}:{sub}",
        f"{ctx.tenant_uid}:{sub}",
        sub,
    )
    if not any(e in sub_ids for e in expected_forms) and not any(
        str(i).endswith(f":{sub}") for i in sub_ids
    ):
        raise TestExecError(
            f"tenanted subuser {sub} not found in {sub_ids} (expected {expected_forms})"
        )
    rest_reusable.modify_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        sub,
        access="read",
        key_type="swift",
        tenant=ctx.tenant,
    )
    rest_reusable.delete_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        sub,
        tenant=ctx.tenant,
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        tenant=ctx.tenant,
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    if any(str(i).endswith(f":{sub}") for i in sub_ids) or sub in sub_ids:
        raise TestExecError(f"tenanted subuser {sub} still present: {sub_ids}")
    log.info("create_tenant_subuser ok")


def op_create_tenant_s3_subuser(ctx):
    _ensure_tenant_parent(ctx)
    sub = "s3sub1"
    rest_reusable.create_tenant_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant,
        ctx.tenant_uid,
        sub,
        key_type="s3",
        access="full",
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        tenant=ctx.tenant,
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    if not any(str(i).endswith(f":{sub}") for i in sub_ids) and sub not in sub_ids:
        raise TestExecError(f"tenanted s3 subuser {sub} not in {sub_ids}")
    rest_reusable.delete_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        sub,
        tenant=ctx.tenant,
    )
    log.info("create_tenant_s3_subuser ok")


def op_tenanted_user_caps(ctx):
    _ensure_tenant_parent(ctx)
    caps = "usage=read"
    rest_reusable.add_user_capabilities(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        caps,
        tenant=ctx.tenant,
    )
    rest_reusable.verify_user_capabilities(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        expected_caps=[{"type": "usage", "perm": "read"}],
        tenant=ctx.tenant,
    )
    rest_reusable.remove_user_capabilities(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_uid,
        caps,
        tenant=ctx.tenant,
    )
    log.info("tenanted_user_caps ok")


def op_create_admin_ops_user(ctx):
    uid = _rand_uid("admops")
    data = rest_reusable.create_admin_ops_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    if not data.get("caps"):
        raise TestExecError(f"admin-ops user {uid} has no caps: {data}")
    log.info(f"admin-ops user ok: {uid}")


def op_create_system_user(ctx):
    if not ctx.admin_info.get("system"):
        # Soft-skip when suite reused an existing non-system admin (e.g. repuser)
        log.warning(
            "create_system_user skipped: admin caller is not system "
            f"(admin uid={ctx.admin_info.get('user_id')})"
        )
        return
    uid = _rand_uid("sys")
    rest_reusable.create_system_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    if not info.get("system"):
        raise TestExecError(f"system flag not set on {uid}: {info}")
    log.info(f"system user ok: {uid}")


def op_create_swift_user(ctx):
    ctx.swift_uid = _rand_uid("swift")
    ctx.swift_subuser = "swift"
    data = rest_reusable.create_swift_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.swift_uid,
        names.get_full_name().lower(),
        subuser=ctx.swift_subuser,
    )
    _track_uid(ctx, ctx.swift_uid)
    info = data or rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.swift_uid
    )
    if not info.get("swift_keys"):
        raise TestExecError(f"swift user missing swift_keys: {info}")
    log.info(f"swift user ok: {ctx.swift_uid}")


def op_create_swift_subuser(ctx):
    parent = ctx.swift_uid or _rand_uid("swparent")
    if parent not in ctx.created_uids:
        rest_reusable.create_user(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            parent,
            names.get_full_name().lower(),
        )
        _track_uid(ctx, parent)
    sub = "swift1"
    ctx.swift_subuser = sub
    rest_reusable.create_swift_subuser(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, parent, sub, access="full"
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, parent
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    if f"{parent}:{sub}" not in sub_ids and sub not in sub_ids:
        if not any(str(i).endswith(f":{sub}") for i in sub_ids):
            raise TestExecError(f"swift subuser not in {sub_ids}")
    log.info(f"swift subuser ok on {parent}")


def op_create_swift_key(ctx):
    uid = ctx.swift_uid or _rand_uid("swkey")
    sub = getattr(ctx, "swift_subuser", None) or "swift"
    if uid not in ctx.created_uids:
        rest_reusable.create_user(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            uid,
            names.get_full_name().lower(),
        )
        _track_uid(ctx, uid)
    # Swift keys require an existing subuser.
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    if not any(str(i).endswith(f":{sub}") for i in sub_ids) and sub not in sub_ids:
        rest_reusable.create_swift_subuser(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            uid,
            sub,
            access="full",
            generate_secret=False,
        )
        ctx.swift_subuser = sub
    key = rest_reusable.create_swift_key(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid, subuser=sub
    )
    if not (isinstance(key, dict) and (key.get("secret_key") or key.get("user"))):
        info = rest_reusable.get_user_info(
            ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
        )
        if not info.get("swift_keys"):
            raise TestExecError(f"create_swift_key failed: {key}")
    ctx.swift_key_uid = uid
    log.info(f"swift key ok for {uid}:{sub}")


def op_remove_swift_key(ctx):
    # Dedicated user so leftover keys from create_swift_user/subuser
    # (e.g. :swift) do not fail the assertion for this op.
    uid = _rand_uid("swrm")
    sub = "swift"
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    rest_reusable.create_swift_subuser(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid, sub, access="full"
    )
    rest_reusable.remove_key(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid=uid,
        subuser=sub,
        key_type="swift",
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    leftover = [
        k
        for k in (info.get("swift_keys") or [])
        if str(k.get("user", "")).endswith(f":{sub}") or k.get("user") == sub
    ]
    if leftover:
        raise TestExecError(f"swift key for {uid}:{sub} still present: {leftover}")
    log.info(f"remove_swift_key ok for {uid}:{sub}")


def op_gen_subuser(ctx):
    """
    AdminOps Create Subuser requires subuser=<name> (gen-subuser is not a
    documented REST param). Generate a name client-side and assert it lands.
    """
    uid = _rand_uid("gensub")
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    gen_name = "auto" + rest_reusable.generate_random_string(4)
    rest_reusable.create_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        subuser=gen_name,
        key_type="swift",
        access="full",
        generate_secret=True,
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    if f"{uid}:{gen_name}" not in sub_ids and gen_name not in sub_ids:
        if not any(str(i).endswith(f":{gen_name}") for i in sub_ids):
            raise TestExecError(f"generated subuser {gen_name} not in {sub_ids}")
    log.info(f"gen_subuser ok for {uid}:{gen_name}")


def op_suspend_enable_user(ctx):
    uid = _rand_uid("sus")
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    rest_reusable.suspend_user(ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    if not info.get("suspended"):
        raise TestExecError(f"user {uid} not suspended: {info}")
    rest_reusable.enable_user(ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    if info.get("suspended"):
        raise TestExecError(f"user {uid} still suspended: {info}")
    log.info(f"suspend/enable ok for {uid}")


def op_create_key_variants(ctx):
    ctx.key_uid = _rand_uid("key")
    created = rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.key_uid,
        names.get_full_name().lower(),
        generate_key=True,
    )
    _track_uid(ctx, ctx.key_uid)
    k1 = rest_reusable.create_key(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.key_uid, key_type="s3"
    )
    ctx.access_to_remove = k1.get("access_key")
    rest_reusable.create_key(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.key_uid,
        key_type="s3",
        generate_key=True,
    )
    if not ctx.access_to_remove and created.get("keys"):
        ctx.access_to_remove = created["keys"][0]["access_key"]
    log.info(f"create_key variants ok for {ctx.key_uid}")


def _key_is_inactive(key):
    return key.get("active") in (False, "false", 0, "False")


def op_create_key_active_false(ctx):
    """
    Create an S3 key with active=false.

    Older Ceph builds ignore active on *create* (ceph/ceph#73944) but honor it
    when *modifying* an existing key via the same create-key AdminOps path with
    access-key set. So: create, then modify if still active.
    """
    uid = _rand_uid("inact")
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    k = rest_reusable.create_key(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        key_type="s3",
        active=False,
    )
    ak = k.get("access_key")
    sk = k.get("secret_key")

    def _lookup():
        info = rest_reusable.get_user_info(
            ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
        )
        return next(
            (x for x in (info.get("keys") or []) if x.get("access_key") == ak),
            k,
        )

    match = _lookup()
    if not _key_is_inactive(match) and ak:
        log.info(
            f"create_key active=False ignored on create for {uid}; "
            "re-applying via create-key modify"
        )
        rest_reusable.create_key(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            uid,
            key_type="s3",
            access_key=ak,
            secret_key=sk,
            active=False,
        )
        match = _lookup()

    if not _key_is_inactive(match):
        log.warning(
            f"create_key_active_false soft-skipped: active=false not applied "
            f"for {uid} (Ceph may lack create-key active create/modify support): "
            f"{match}"
        )
        return
    log.info(f"create_key active=False ok for {uid}: {match}")


def op_remove_key(ctx):
    if not ctx.key_uid:
        op_create_key_variants(ctx)
    if not ctx.access_to_remove:
        info = rest_reusable.get_user_info(
            ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.key_uid
        )
        keys = info.get("keys") or []
        if not keys:
            raise TestExecError("no key available for remove_key")
        ctx.access_to_remove = keys[0]["access_key"]
    rest_reusable.remove_key(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        access_key=ctx.access_to_remove,
        uid=ctx.key_uid,
        key_type="s3",
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.key_uid
    )
    remaining = [k.get("access_key") for k in info.get("keys", [])]
    if ctx.access_to_remove in remaining:
        raise TestExecError(f"key {ctx.access_to_remove} still present after remove")
    log.info(f"remove_key ok for {ctx.key_uid}")


def op_purge_data_user_delete(ctx):
    uid = _rand_uid("purge")
    data = rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    ak = data["keys"][0]["access_key"]
    sk = data["keys"][0]["secret_key"]
    bkt = "bkt-" + rest_reusable.generate_random_string(6)
    rest_reusable.create_bucket_s3(ctx.endpoint, ak, sk, bkt)
    rest_reusable.delete_user_api(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid, purge_data=True
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        allow_missing=True,
    )
    if info is not None:
        raise TestExecError(f"user {uid} still exists after purge_data delete: {info}")
    log.info(f"purge_data user delete ok: {uid}")


def op_purge_keys_subuser_delete(ctx):
    uid = _rand_uid("purgk")
    rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    sub = "psub1"
    rest_reusable.create_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        sub,
        key_type="s3",
        access="full",
    )
    rest_reusable.delete_subuser(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        sub,
        purge_keys=True,
    )
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    sub_ids = [s.get("id") for s in info.get("subusers", [])]
    if any(str(i).endswith(f":{sub}") for i in sub_ids) or sub in sub_ids:
        raise TestExecError(f"subuser {sub} still present: {sub_ids}")
    log.info(f"purge_keys_subuser_delete ok for {uid}")


def _assert_quota_fields(got, expected, label):
    if not isinstance(got, dict):
        raise TestExecError(f"{label}: expected quota dict, got {got!r}")
    for key, exp in expected.items():
        actual = got.get(key)
        if actual != exp:
            raise TestExecError(f"{label}: {key}={actual!r} expected {exp!r} in {got}")


def op_set_user_quota(ctx):
    if not ctx.quota_uid:
        ctx.quota_uid = _rand_uid("quota")
        rest_reusable.create_user(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            ctx.quota_uid,
            names.get_full_name().lower(),
        )
        _track_uid(ctx, ctx.quota_uid)
    user_q = {
        "enabled": True,
        "check_on_raw": True,
        "max_size_kb": 1024,
        "max_size": 1048576,
        "max_objects": 50,
    }
    rest_reusable.set_user_quota(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.quota_uid, "user", user_q
    )
    got = rest_reusable.get_user_quota(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.quota_uid, "user"
    )
    _assert_quota_fields(got, user_q, "set_user_quota")
    log.info(f"set_user_quota ok: {got}")


def op_set_bucket_quota_scope(ctx):
    if not ctx.quota_uid:
        op_set_user_quota(ctx)
    user_q = {
        "enabled": True,
        "check_on_raw": True,
        "max_size_kb": 1024,
        "max_size": 1048576,
        "max_objects": 50,
    }
    rest_reusable.set_user_quota(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.quota_uid, "bucket", user_q
    )
    got = rest_reusable.get_user_quota(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, ctx.quota_uid, "bucket"
    )
    _assert_quota_fields(got, user_q, "set_bucket_quota_scope")
    log.info(f"set_bucket_quota_scope ok: {got}")


def op_set_individual_bucket_quota(ctx):
    uid = _rand_uid("bq")
    data = rest_reusable.create_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        names.get_full_name().lower(),
    )
    _track_uid(ctx, uid)
    ak = data["keys"][0]["access_key"]
    sk = data["keys"][0]["secret_key"]
    bkt = "ibq-" + rest_reusable.generate_random_string(6)
    rest_reusable.create_bucket_s3(ctx.endpoint, ak, sk, bkt)
    q = {
        "enabled": True,
        "check_on_raw": True,
        "max_size_kb": 512,
        "max_size": 524288,
        "max_objects": 25,
    }
    rest_reusable.set_individual_bucket_quota(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid, bkt, q
    )
    rest_reusable.delete_bucket_admin_api(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, bkt
    )
    log.info(f"set_individual_bucket_quota ok for {bkt}")


def op_create_account(ctx):
    ctx.account_id = _rand_account_id()
    name = "acct-" + rest_reusable.generate_random_string(6)
    acct = rest_reusable.create_account(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.account_id,
        name,
        email=f"{name}@example.com",
        max_users=100,
        max_buckets=100,
    )
    ctx.created_accounts.append({"id": ctx.account_id, "name": name})
    if not acct.get("id"):
        raise TestExecError(f"create_account missing id: {acct}")
    log.info(f"create_account ok: {acct}")


def op_create_tenant_account(ctx):
    ctx.account_tenant = "ta" + rest_reusable.generate_random_string(5)
    ctx.tenant_account_id = _rand_account_id()
    tname = "tacct-" + rest_reusable.generate_random_string(5)
    acct = rest_reusable.create_account(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.tenant_account_id,
        tname,
        tenant=ctx.account_tenant,
        email=f"{tname}@example.com",
    )
    ctx.created_accounts.append(
        {
            "id": ctx.tenant_account_id,
            "name": tname,
            "tenant": ctx.account_tenant,
        }
    )
    uid = _rand_uid("tacctu")
    rest_reusable.create_account_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        _iam_display_name(uid),
        ctx.tenant_account_id,
        account_root=True,
        tenant=ctx.account_tenant,
    )
    _track_uid(ctx, uid, ctx.account_tenant)
    log.info(f"create_tenant_account ok: {acct}")


def op_create_account_user(ctx):
    if not ctx.account_id:
        raise TestExecError(
            "create_account_user requires account_id from create_account"
        )
    uid = _rand_uid("acctu")
    rest_reusable.create_account_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        _iam_display_name(uid),
        ctx.account_id,
        account_root=True,
    )
    _track_uid(ctx, uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    if info.get("account_id") != ctx.account_id:
        raise TestExecError(f"account_id mismatch: {info.get('account_id')}")
    # Account-root users are type=root (and may also expose account_root).
    is_root = str(info.get("type", "")).lower() == "root" or info.get(
        "account_root"
    ) in (True, "true", 1)
    if not is_root:
        raise TestExecError(f"expected account-root user: {info}")
    log.info(f"create_account_user ok: {uid}")


def op_create_account_user_non_root(ctx):
    if not ctx.account_id:
        raise TestExecError(
            "create_account_user_non_root requires account_id from create_account"
        )
    uid = _rand_uid("acctnr")
    rest_reusable.create_account_user(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        uid,
        _iam_display_name(uid),
        ctx.account_id,
        account_root=False,
    )
    _track_uid(ctx, uid)
    info = rest_reusable.get_user_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
    )
    if info.get("account_id") != ctx.account_id:
        raise TestExecError(f"account_id mismatch: {info.get('account_id')}")
    if info.get("account_root") in (True, "true", 1):
        raise TestExecError(f"expected non-root account user: {info}")
    if str(info.get("type", "")).lower() in ("root",):
        raise TestExecError(f"expected non-root account user type: {info}")
    log.info(f"create_account_user_non_root ok: {uid}")


def op_modify_account(ctx):
    if not ctx.account_id:
        raise TestExecError("modify_account requires account_id")
    rest_reusable.modify_account(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        account_id=ctx.account_id,
        max_buckets=200,
    )
    info = rest_reusable.get_account_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, account_id=ctx.account_id
    )
    if info.get("max_buckets") != 200:
        raise TestExecError(f"modify_account max_buckets not applied: {info}")
    log.info("modify_account ok")


def op_get_account_info(ctx):
    if not ctx.account_id:
        raise TestExecError("get_account_info requires account_id")
    info = rest_reusable.get_account_info(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, account_id=ctx.account_id
    )
    if info.get("id") != ctx.account_id:
        raise TestExecError(f"get_account_info id mismatch: {info}")
    log.info(f"get_account_info ok: {json.dumps(info)[:200]}")


def op_set_account_quota(ctx):
    if not ctx.account_id:
        raise TestExecError("set_account_quota requires account_id")
    rest_reusable.set_account_quota(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.account_id,
        quota_type="account",
        max_size=1048576,
        max_objects=100,
        enabled=True,
    )
    qinfo = rest_reusable.get_account_quota(
        ctx.endpoint,
        ctx.admin_key,
        ctx.admin_secret,
        ctx.account_id,
        quota_type="account",
    )
    # GET account?quota returns the account object with nested quota.
    quota = qinfo.get("quota") if isinstance(qinfo, dict) else None
    if not isinstance(quota, dict):
        raise TestExecError(f"set_account_quota: missing quota in {qinfo}")
    if quota.get("max_size") != 1048576 or quota.get("max_objects") != 100:
        raise TestExecError(f"set_account_quota values not applied: {quota}")
    if quota.get("enabled") not in (True, "true", 1):
        raise TestExecError(f"set_account_quota enabled not applied: {quota}")
    log.info(f"set_account_quota ok: {quota}")


def op_delete_account(ctx):
    if not ctx.account_id:
        raise TestExecError("delete_account requires account_id")
    acct_id = ctx.account_id
    for uid in list(ctx.created_uids):
        info = rest_reusable.get_user_info(
            ctx.endpoint,
            ctx.admin_key,
            ctx.admin_secret,
            uid,
            allow_missing=True,
        )
        if info and info.get("account_id") == acct_id:
            rest_reusable.delete_user_api(
                ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
            )
            ctx.created_uids.remove(uid)
    rest_reusable.delete_account(
        ctx.endpoint, ctx.admin_key, ctx.admin_secret, account_id=acct_id
    )
    # Confirm account is gone (NoSuchAccount / error Code).
    try:
        leftover = rest_reusable.get_account_info(
            ctx.endpoint, ctx.admin_key, ctx.admin_secret, account_id=acct_id
        )
    except TestExecError:
        leftover = None
    if (
        isinstance(leftover, dict)
        and leftover.get("id") == acct_id
        and not leftover.get("Code")
    ):
        raise TestExecError(f"account {acct_id} still exists after delete: {leftover}")
    ctx.created_accounts = [a for a in ctx.created_accounts if a.get("id") != acct_id]
    log.info(f"delete_account ok: {acct_id}")
    ctx.account_id = None


# Map YAML test_ops keys -> handlers that call rest.reusable
OP_HANDLERS = {
    "list_users": op_list_users,
    "list_users_pagination": op_list_users_pagination,
    "create_user_with_attrs": op_create_user_with_attrs,
    "create_user_no_key": op_create_user_no_key,
    "create_user_exclusive": op_create_user_exclusive,
    "create_user_explicit_keys": op_create_user_explicit_keys,
    "get_user_by_access_key": op_get_user_by_access_key,
    "create_tenant_user": op_create_tenant_user,
    "create_tenant_subuser": op_create_tenant_subuser,
    "create_tenant_s3_subuser": op_create_tenant_s3_subuser,
    "tenanted_user_caps": op_tenanted_user_caps,
    "create_admin_ops_user": op_create_admin_ops_user,
    "create_system_user": op_create_system_user,
    "create_swift_user": op_create_swift_user,
    "create_swift_subuser": op_create_swift_subuser,
    "create_swift_key": op_create_swift_key,
    "remove_swift_key": op_remove_swift_key,
    "gen_subuser": op_gen_subuser,
    "suspend_enable_user": op_suspend_enable_user,
    "create_key_variants": op_create_key_variants,
    "create_key_active_false": op_create_key_active_false,
    "remove_key": op_remove_key,
    "purge_data_user_delete": op_purge_data_user_delete,
    "purge_keys_subuser_delete": op_purge_keys_subuser_delete,
    "set_user_quota": op_set_user_quota,
    "set_bucket_quota_scope": op_set_bucket_quota_scope,
    "set_individual_bucket_quota": op_set_individual_bucket_quota,
    "create_account": op_create_account,
    "create_tenant_account": op_create_tenant_account,
    "create_account_user": op_create_account_user,
    "create_account_user_non_root": op_create_account_user_non_root,
    "modify_account": op_modify_account,
    "get_account_info": op_get_account_info,
    "set_account_quota": op_set_account_quota,
    "delete_account": op_delete_account,
}


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    endpoint = aws_reusable.get_endpoint(ssh_con)
    if not endpoint.startswith("http"):
        endpoint = f"http://{endpoint}"
    log.info(f"AdminOps endpoint: {endpoint}")

    admin_key, admin_secret, admin_info = _seed_admin_creds(ssh_con)
    ops = config.test_ops if hasattr(config, "test_ops") else {}
    ctx = AdminOpsContext(endpoint, admin_key, admin_secret, admin_info)

    # Run every enabled op; collect failures instead of aborting on first error.
    # results: ordered list of (scenario, status, detail) for end-of-run report
    results = []
    try:
        for op_name, enabled in ops.items():
            if not enabled:
                results.append((op_name, "SKIP", "disabled in config"))
                continue
            handler = OP_HANDLERS.get(op_name)
            if handler is None:
                log.warning(f"No handler for test_ops.{op_name}; skipping")
                results.append((op_name, "SKIP", "no handler"))
                continue
            log.info("-" * 80)
            log.info(f"Running AdminOps REST op: {op_name}")
            try:
                handler(ctx)
                results.append((op_name, "PASS", ""))
                log.info(f"AdminOps REST op PASSED: {op_name}")
            except Exception as e:
                log.error(f"AdminOps REST op FAILED: {op_name}: {e}")
                log.error(traceback.format_exc())
                results.append((op_name, "FAIL", str(e)))

        passed = [n for n, s, _ in results if s == "PASS"]
        failures = [(n, d) for n, s, d in results if s == "FAIL"]
        skipped = [n for n, s, _ in results if s == "SKIP"]

        log.info("-" * 80)
        log.info("All scenarios:")
        name_width = max((len(n) for n, _, _ in results), default=10)
        for name, status, detail in results:
            line = f"  {name:<{name_width}} : {status}"
            if detail and status == "FAIL":
                line = f"{line} ({detail})"
            elif detail and status == "SKIP":
                line = f"{line} ({detail})"
            log.info(line)
        log.info("-" * 80)
        log.info(
            f"AdminOps user-types summary: "
            f"{len(passed)} passed, {len(failures)} failed, {len(skipped)} skipped"
        )
        if failures:
            raise TestExecError(
                "AdminOps user-types failures: "
                + "; ".join(f"{n}: {e}" for n, e in failures)
            )
        log.info("ALL DECLARED ADMINOPS USER-TYPE TESTS PASSED")
    finally:
        if config.user_remove if hasattr(config, "user_remove") else True:
            for uid in ctx.created_uids:
                try:
                    rest_reusable.delete_user_api(
                        ctx.endpoint, ctx.admin_key, ctx.admin_secret, uid
                    )
                except Exception:
                    rest_reusable.delete_user(uid)
            for acct in ctx.created_accounts:
                try:
                    rest_reusable.delete_account(
                        ctx.endpoint,
                        ctx.admin_key,
                        ctx.admin_secret,
                        account_id=acct.get("id"),
                        name=acct.get("name"),
                        tenant=acct.get("tenant"),
                    )
                except Exception as e:
                    log.warning(f"account cleanup failed: {e}")

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test AdminOps REST user types")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW AdminOps user types test")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            default="info",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", default="127.0.0.1", help="RGW Node"
        )
        args = parser.parse_args()

        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)

        configure_logging(
            f_name=os.path.basename(os.path.splitext(args.config)[0]),
            set_level=args.log_level.upper(),
        )
        config = Config(args.config)
        config.read(ssh_con)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
