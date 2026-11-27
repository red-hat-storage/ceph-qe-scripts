"""
v2.tests.rest.reusable - Reusable RGW AdminOps REST helpers (SigV2).

Sibling of v2.tests.curl. All AdminOps user/account/quota/key/subuser helpers
live here. Tests should call these based on YAML config; do not embed raw
AdminOps curl in test scripts.
"""

import json
import logging
import random
import re
import string
import time
from urllib.parse import quote

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError

log = logging.getLogger()

__all__ = [
    "generate_random_string",
    "parse_json_response",
    "build_query_params",
    "admin_api_call",
    "create_user",
    "create_key",
    "remove_key",
    "get_user_info",
    "verify_key_replication",
    "verify_all_keys",
    "modify_user",
    "delete_user_api",
    "create_subuser",
    "modify_subuser",
    "delete_subuser",
    "verify_replication",
    "add_user_capabilities",
    "remove_user_capabilities",
    "verify_user_capabilities",
    "create_bucket_s3",
    "delete_bucket_admin_api",
    "list_buckets_s3",
    "verify_bucket_exists",
    "list_users",
    "resolve_tenanted_uid",
    "create_tenant_user",
    "create_tenant_subuser",
    "create_system_user",
    "create_admin_ops_user",
    "create_swift_user",
    "create_swift_subuser",
    "create_swift_key",
    "suspend_user",
    "enable_user",
    "create_account_user",
    "create_account",
    "modify_account",
    "get_account_info",
    "delete_account",
    "set_user_quota",
    "get_user_quota",
    "set_individual_bucket_quota",
    "set_account_quota",
    "get_account_quota",
    "delete_user",
]

# Map Python kwargs -> AdminOps query parameter names for /admin/user
_USER_PARAM_MAP = {
    "tenant": "tenant",
    "email": "email",
    "key_type": "key-type",
    "access_key": "access-key",
    "secret_key": "secret-key",
    "user_caps": "user-caps",
    "generate_key": "generate-key",
    "generate_secret": "generate-secret",
    "max_buckets": "max-buckets",
    "suspended": "suspended",
    "system": "system",
    "exclusive": "exclusive",
    "op_mask": "op-mask",
    "account_id": "account-id",
    "account_root": "account-root",
    "default_placement": "default-placement",
    "default_storage_class": "default-storage-class",
    "placement_tags": "placement-tags",
    "path": "path",
    "subuser": "subuser",
    "access": "access",
    "active": "active",
    "purge_data": "purge-data",
    "gen_subuser": "gen-subuser",
}


def generate_random_string(length=8):
    """Generate random string for user names"""
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for i in range(length)
    )


def parse_json_response(response, context="API"):
    """Parse and validate JSON response"""
    log.info(f"Response: {response}")
    if not response or not isinstance(response, str):
        raise TestExecError(f"{context} command execution failed: {response}")
    try:
        return json.loads(response.strip())
    except (json.JSONDecodeError, TypeError):
        raise TestExecError(f"Invalid JSON response from {context}: {response!r}")


def _format_query_value(value):
    """Normalize bools/ints for AdminOps query strings.

    Use lowercase true/false so RGW RESTArgs::get_bool parses reliably
    (e.g. create-key active=false).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def resolve_tenanted_uid(uid, tenant=None):
    """
    Build AdminOps uid for a tenanted user.

    Subuser AdminOps has no separate tenant= param; Ceph expects
    uid=tenant$uid (parsed by rgw_user). If uid already contains '$',
    it is returned unchanged.
    """
    if not tenant:
        return uid
    if "$" in str(uid):
        return uid
    return f"{tenant}${uid}"


def build_query_params(base_params=None, **options):
    """
    Build AdminOps query string from base params and optional kwargs.

    Unknown kwargs that match _USER_PARAM_MAP are included. Values of None
    are skipped. Keys already present in base_params are not overwritten.
    """
    params = dict(base_params or {})
    for key, value in options.items():
        if value is None:
            continue
        param_name = _USER_PARAM_MAP.get(key, key.replace("_", "-"))
        if param_name not in params:
            params[param_name] = value

    # Boolean CLI-style flags: emit the bare name when True; omit when False
    # (sending account-root=false / system=false has caused InvalidArgument).
    _FLAG_ONLY = {
        "key",
        "caps",
        "list",
        "quota",
        "subuser",
        "account-root",
        "system",
        "exclusive",
        "purge-data",
        "purge-keys",
        "purge-objects",
        "gen-subuser",
    }
    parts = []
    for name, value in params.items():
        if value is None:
            continue
        if name in _FLAG_ONLY and isinstance(value, bool):
            if value is True:
                parts.append(name)
            continue
        # Do not leave '$' unescaped: admin_api_call embeds the URL in a
        # double-quoted shell string, so tenant$uid would expand as a variable.
        encoded = quote(_format_query_value(value), safe=";=*")
        parts.append(f"{name}={encoded}")
    return "?" + "&".join(parts) if parts else ""


def admin_api_call(
    method,
    endpoint,
    admin_key,
    admin_secret,
    params="",
    data="",
    content_type="",
    resource="user",
):
    """
    Execute admin API call with AWS signature authentication

    Args:
        method: HTTP method (GET, PUT, POST, DELETE)
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        params: URL query parameters (must start with '?' when non-empty)
        data: Request body data
        content_type: Content-Type header value
        resource: Admin resource path segment (user, account, bucket, ...)

    Returns:
        Response string from curl command
    """
    host = endpoint.split("//")[1]
    ct_header = f'-H "Content-Type: {content_type}"' if content_type else ""
    data_param = f"-d '{data}'" if data else ""
    admin_path = f"/admin/{resource}"

    cmd = f"""
DATE=$(date -R -u)
STRING_TO_SIGN="{method}\\n\\n{content_type}\\n$DATE\\n{admin_path}"
SIGNATURE=$(echo -en "$STRING_TO_SIGN" | openssl sha1 -hmac {admin_secret} -binary | base64)
curl -s -X {method} {ct_header} -H "Date: $DATE" -H "Authorization: AWS {admin_key}:$SIGNATURE" -H "Host: {host}" {data_param} "{endpoint}{admin_path}{params}"
"""
    return utils.exec_shell_cmd(cmd)


def _user_created_successfully(user_data):
    """Accept S3, Swift, or no-key create responses as success."""
    if not isinstance(user_data, dict):
        return False
    if user_data.get("Code"):
        return False
    return (
        "user_id" in user_data
        or "keys" in user_data
        or "swift_keys" in user_data
        or "tenant" in user_data
    )


def _raise_if_admin_error(data, context):
    """Fail fast when AdminOps returns an error payload (e.g. NoSuchUser)."""
    if isinstance(data, dict) and data.get("Code"):
        raise TestExecError(f"{context} failed: {data}")


def create_user(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    display_name,
    site_name="",
    tenant=None,
    email=None,
    key_type=None,
    access_key=None,
    secret_key=None,
    user_caps=None,
    generate_key=None,
    max_buckets=None,
    suspended=None,
    system=None,
    exclusive=None,
    op_mask=None,
    account_id=None,
    account_root=None,
    default_placement=None,
    default_storage_class=None,
    path=None,
):
    """
    Create user on specified endpoint via PUT /admin/user.

    Optional AdminOps params map 1:1 to Ceph docs (tenant, email, key-type,
    access-key, secret-key, user-caps, generate-key, max-buckets, suspended,
    system, exclusive, op-mask, account-id, account-root, etc.).

    Note: CLI ``--admin`` has no AdminOps REST equivalent; use system=True
    and/or user_caps / create_admin_ops_user() for admin-capable users.
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating user '{uid}'{site_info}")
    params = build_query_params(
        {
            "uid": uid,
            "display-name": display_name,
            "format": "json",
        },
        tenant=tenant,
        email=email,
        key_type=key_type,
        access_key=access_key,
        secret_key=secret_key,
        user_caps=user_caps,
        generate_key=generate_key,
        max_buckets=max_buckets,
        suspended=suspended,
        system=system,
        exclusive=exclusive,
        op_mask=op_mask,
        account_id=account_id,
        account_root=account_root,
        default_placement=default_placement,
        default_storage_class=default_storage_class,
        path=path,
    )
    for attempt in range(5):
        response = admin_api_call(
            "PUT",
            endpoint,
            admin_key,
            admin_secret,
            params,
        )
        if response:
            try:
                user_data = parse_json_response(response, "user creation")
                # Permanent AdminOps errors should not be retried.
                if isinstance(user_data, dict) and user_data.get("Code"):
                    raise TestExecError(f"Failed to create user '{uid}': {user_data}")
                if _user_created_successfully(user_data):
                    log.info(f"User '{uid}' created successfully{site_info}")
                    keys = user_data.get("keys") or []
                    if keys:
                        log.info(f"Initial access key: {keys[0].get('access_key')}")
                    return user_data
            except TestExecError:
                raise
            except Exception as e:
                log.warning(f"Parse failed (attempt {attempt+1}/5): {e}")

        if attempt < 4:
            log.warning(f"Empty/invalid response, retrying ({attempt+1}/5)...")
            time.sleep(3)

    raise TestExecError(f"Failed to create user '{uid}' after 5 retries")


def create_key(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    site_name="",
    key_type="s3",
    subuser=None,
    access_key=None,
    secret_key=None,
    generate_key=None,
    active=None,
    tenant=None,
):
    """
    Create access key for user via PUT /admin/user?key.

    Defaults to S3 key-type for backward compatibility. Pass key_type='swift'
    for Swift keys; optionally set subuser, access_key, secret_key,
    generate_key, active, tenant.
    """
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating new {key_type} key for user '{resolved_uid}'{site_info}")
    params = build_query_params(
        {"uid": resolved_uid, "key": True, "format": "json"},
        key_type=key_type,
        subuser=subuser,
        access_key=access_key,
        secret_key=secret_key,
        generate_key=generate_key,
        active=active,
    )

    for attempt in range(5):
        response = admin_api_call(
            "PUT",
            endpoint,
            admin_key,
            admin_secret,
            params,
            "",
            "application/json",
        )

        if response:
            try:
                key_data = parse_json_response(response, "key creation")
                _raise_if_admin_error(key_data, f"create key for '{resolved_uid}'")
                # Response may be a list of keys or a single key object / user info
                if isinstance(key_data, list) and key_data:
                    chosen = key_data[-1]
                    log.info(
                        f"Access key created successfully{site_info}: "
                        f"{chosen.get('access_key') or chosen.get('user')}"
                    )
                    return chosen
                if isinstance(key_data, dict):
                    if "access_key" in key_data:
                        log.info(
                            f"Access key created successfully{site_info}: "
                            f"{key_data['access_key']}"
                        )
                        return key_data
                    keys = key_data.get("keys") or []
                    swift_keys = key_data.get("swift_keys") or []
                    if key_type == "swift" and swift_keys:
                        log.info(f"Swift key created successfully{site_info}")
                        return swift_keys[-1]
                    if keys:
                        log.info(
                            f"Access key created successfully{site_info}: "
                            f"{keys[-1].get('access_key')}"
                        )
                        return keys[-1]
            except TestExecError:
                raise
            except Exception as e:
                log.warning(f"Parse failed (attempt {attempt+1}): {e}")

        log.warning(f"Empty/invalid response, retrying ({attempt+1}/5)...")
        time.sleep(3)

    raise TestExecError(f"Failed to create key after retries for user {uid}")


def remove_key(
    endpoint,
    admin_key,
    admin_secret,
    access_key=None,
    uid=None,
    subuser=None,
    key_type=None,
    site_name="",
    tenant=None,
):
    """Remove a key via DELETE /admin/user?key (access-key required for S3)."""
    resolved_uid = resolve_tenanted_uid(uid, tenant) if uid else None
    site_info = f" on {site_name} site" if site_name else ""
    log.info(
        f"Removing key{site_info} access_key={access_key} uid={resolved_uid} "
        f"key_type={key_type}"
    )
    params = build_query_params(
        {"key": True, "format": "json"},
        access_key=access_key,
        uid=resolved_uid,
        subuser=subuser,
        key_type=key_type,
    )
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    log.info(f"Remove key response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            parsed = parse_json_response(response, "remove_key")
        except TestExecError:
            parsed = None
        if isinstance(parsed, dict):
            _raise_if_admin_error(parsed, "remove_key")
    return response


def get_user_info(
    endpoint,
    admin_key,
    admin_secret,
    uid=None,
    retries=5,
    wait_time=3,
    tenant=None,
    access_key=None,
    allow_missing=False,
):
    """
    Get user information from endpoint.

    Either uid (optional tenant via tenant$uid — GET ignores a separate
    tenant= param until upstream Ceph PR #71301) or access_key must be supplied.

    When allow_missing=True, NoSuchUser returns None instead of raising.
    """
    if uid is None and access_key is None:
        raise TestExecError("get_user_info requires uid or access_key")
    base = {"format": "json"}
    if uid is not None:
        # Must embed tenant in uid; separate tenant= is create-only on current RGW.
        base["uid"] = resolve_tenanted_uid(uid, tenant)
    if access_key is not None:
        base["access-key"] = access_key
    params = build_query_params(base)
    for attempt in range(retries):
        response = admin_api_call("GET", endpoint, admin_key, admin_secret, params)
        if response is not False:
            data = parse_json_response(response, "user info")
            if isinstance(data, dict) and data.get("Code"):
                if allow_missing and data.get("Code") in (
                    "NoSuchUser",
                    "NoSuchKey",
                ):
                    return None
                _raise_if_admin_error(data, "get_user_info")
            return data
        if attempt < retries - 1:
            log.warning(
                f"get_user_info failed (attempt {attempt+1}/{retries}) for {endpoint}, retrying in {wait_time}s..."
            )
            time.sleep(wait_time)
        else:
            log.error(
                f"get_user_info failed (attempt {attempt+1}/{retries}) for {endpoint}"
            )

    raise TestExecError(
        f"user info command failed after {retries} retries for endpoint {endpoint}"
    )


def verify_key_replication(
    key,
    source_site,
    target_site,
    target_endpoint,
    admin_key,
    admin_secret,
    uid,
    max_retries=15,
    wait_time=5,
):
    """
    Verify key replicated from source to target site

    Args:
        key: Access key to verify
        source_site: Source site name (for logging)
        target_site: Target site name (for logging)
        target_endpoint: Target RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to check
        max_retries: Maximum number of retry attempts (default: 15)
        wait_time: Seconds to wait between retries (default: 5)

    Returns:
        User information from target site
    """
    log.info(f"Verifying key replication from {source_site} to {target_site} site")
    keys = []

    for attempt in range(max_retries):
        try:
            user_info = get_user_info(
                target_endpoint, admin_key, admin_secret, uid, retries=3, wait_time=2
            )

            if "Code" in user_info and user_info["Code"] == "NoSuchUser":
                log.warning(
                    f"User '{uid}' not yet replicated on {target_site} "
                    f"(attempt {attempt+1}/{max_retries})"
                )
                time.sleep(wait_time)
                continue

            keys = [k.get("access_key") for k in user_info.get("keys", [])]

            if key in keys:
                log.info(
                    f"REPLICATION VERIFIED: Key '{key}' replicated from {source_site} to {target_site} (attempt {attempt+1}/{max_retries})"
                )
                return user_info

            log.info(
                f"Key not found yet on {target_site} (attempt {attempt+1}/{max_retries}), retrying in {wait_time}s..."
            )
            time.sleep(wait_time)
        except TestExecError as e:
            log.warning(
                f"Failed to get user info on {target_site} (attempt {attempt+1}/{max_retries}): {e}"
            )
            if attempt < max_retries - 1:
                log.info(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise

    log.error(
        f"REPLICATION FAILED: Key '{key}' NOT present on {target_site} after {max_retries} attempts, keys found: {keys}"
    )
    raise TestExecError(
        f"Key {key} not replicated to {target_site} after {max_retries} attempts"
    )


def verify_all_keys(
    keys,
    primary_endpoint,
    secondary_endpoint,
    admin_key,
    admin_secret,
    uid,
    max_retries=15,
    wait_time=5,
):
    """
    Verify all keys exist on both primary and secondary sites

    Args:
        keys: List of access keys to verify
        primary_endpoint: Primary RGW endpoint URL
        secondary_endpoint: Secondary RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to check
        max_retries: Maximum number of retry attempts (default: 10)
        wait_time: Seconds to wait between retries (default: 5)
    """
    log.info(
        f"Verifying all {len(keys)} keys exist on both Primary and Secondary sites"
    )

    for attempt in range(max_retries):
        try:
            primary_info = get_user_info(
                primary_endpoint, admin_key, admin_secret, uid, retries=5, wait_time=3
            )
            secondary_info = get_user_info(
                secondary_endpoint, admin_key, admin_secret, uid, retries=5, wait_time=3
            )

            primary_keys = [k.get("access_key") for k in primary_info.get("keys", [])]
            secondary_keys = [
                k.get("access_key") for k in secondary_info.get("keys", [])
            ]

            all_keys_present = True
            for key in keys:
                if key not in primary_keys or key not in secondary_keys:
                    all_keys_present = False
                    log.warning(
                        f"Key '{key}' not yet on both sites (attempt {attempt+1}/{max_retries})"
                    )
                    log.info(f"  Primary keys: {primary_keys}")
                    log.info(f"  Secondary keys: {secondary_keys}")
                    break
                else:
                    log.info(f"  Key '{key}' - Present on both sites")

            if all_keys_present:
                log.info(
                    f"ALL KEYS VERIFIED: Primary site has {len(primary_keys)} keys, Secondary site has {len(secondary_keys)} keys"
                )
                return

            if attempt < max_retries - 1:
                log.info(f"Waiting {wait_time}s before retry...")
                time.sleep(wait_time)

        except TestExecError as e:
            log.warning(
                f"Failed to verify keys (attempt {attempt+1}/{max_retries}): {e}"
            )
            if attempt < max_retries - 1:
                log.info(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise

    # All retries exhausted
    log.error(
        f"VERIFICATION FAILED: Not all keys present on both sites after {max_retries} attempts"
    )
    raise TestExecError(f"Key verification failed after {max_retries} attempts")


def modify_user(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    display_name=None,
    site_name="",
    tenant=None,
    email=None,
    generate_key=None,
    access_key=None,
    secret_key=None,
    key_type=None,
    max_buckets=None,
    suspended=None,
    system=None,
    op_mask=None,
    account_id=None,
    account_root=None,
    default_placement=None,
    default_storage_class=None,
):
    """
    Modify user via POST /admin/user.

    display_name remains the common positional arg for existing callers; pass
    additional AdminOps fields as kwargs (email, max_buckets, suspended,
    op_mask, system, account_id, generate_key, key_type, ...).
    """
    site_info = f" on {site_name} site" if site_name else ""
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    log.info(f"Modifying user '{resolved_uid}'{site_info}")
    # POST modify ignores separate tenant=; embed as tenant$uid (URL-encoded).
    base = {"uid": resolved_uid, "format": "json"}
    if display_name is not None:
        base["display-name"] = display_name
    params = build_query_params(
        base,
        email=email,
        generate_key=generate_key,
        access_key=access_key,
        secret_key=secret_key,
        key_type=key_type,
        max_buckets=max_buckets,
        suspended=suspended,
        system=system,
        op_mask=op_mask,
        account_id=account_id,
        account_root=account_root,
        default_placement=default_placement,
        default_storage_class=default_storage_class,
    )
    response = admin_api_call(
        "POST",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    user_data = parse_json_response(response, "user modification")
    _raise_if_admin_error(user_data, f"modify user '{resolved_uid}'")
    log.info(f"User '{resolved_uid}' modified successfully{site_info}")
    return user_data


def delete_user_api(
    endpoint, admin_key, admin_secret, uid, site_name="", tenant=None, purge_data=None
):
    """Delete user using Admin API"""
    site_info = f" on {site_name} site" if site_name else ""
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    log.info(f"Deleting user '{resolved_uid}'{site_info}")
    # DELETE ignores separate tenant=; embed as tenant$uid (URL-encoded).
    params = build_query_params(
        {"uid": resolved_uid, "format": "json"}, purge_data=purge_data
    )
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    # Success is often an empty body; only fail when RGW returns an error JSON.
    if response and isinstance(response, str) and response.strip():
        try:
            _raise_if_admin_error(
                json.loads(response.strip()), f"delete user '{resolved_uid}'"
            )
        except json.JSONDecodeError:
            pass
    log.info(f"User '{resolved_uid}' deleted successfully{site_info}")


def create_subuser(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    subuser=None,
    site_name="",
    key_type="s3",
    access=None,
    secret_key=None,
    generate_secret=None,
    tenant=None,
    gen_subuser=None,
):
    """
    Create subuser for a user.

    Defaults to key-type=s3 for existing MS tests. Pass key_type='swift' for
    Swift subusers (Ceph default for subuser create).

    For tenanted parents, pass tenant=... (AdminOps has no tenant= on subuser;
    uid is sent as tenant$uid). Either subuser or gen_subuser must be set.
    """
    if subuser is None and gen_subuser is None:
        raise TestExecError("create_subuser requires subuser or gen_subuser")
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    label = subuser or gen_subuser
    log.info(
        f"Creating subuser '{label}' (key-type={key_type}) for user "
        f"'{resolved_uid}'{site_info}"
    )
    base = {"uid": resolved_uid, "format": "json"}
    if subuser is not None:
        base["subuser"] = subuser
    params = build_query_params(
        base,
        key_type=key_type,
        access=access,
        secret_key=secret_key,
        generate_secret=generate_secret,
        gen_subuser=gen_subuser,
    )
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    log.info(f"Create subuser response: {response}")
    subuser_data = parse_json_response(response, "subuser creation")
    _raise_if_admin_error(subuser_data, f"create subuser '{resolved_uid}:{label}'")
    log.info(f"Subuser '{resolved_uid}:{label}' created successfully{site_info}")
    return subuser_data


def modify_subuser(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    subuser,
    site_name="",
    key_type="s3",
    access="full",
    generate_secret=None,
    secret_key=None,
    tenant=None,
):
    """Modify subuser permissions / key (defaults preserve existing MS behavior)."""
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(
        f"Modifying subuser '{resolved_uid}:{subuser}'{site_info} - "
        f"access={access}, key-type={key_type}"
    )
    params = build_query_params(
        {"uid": resolved_uid, "subuser": subuser, "format": "json"},
        key_type=key_type,
        access=access,
        generate_secret=generate_secret,
        secret_key=secret_key,
    )
    response = admin_api_call(
        "POST",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    log.info(f"Modify subuser response: {response}")
    subuser_data = parse_json_response(response, "subuser modification")
    _raise_if_admin_error(subuser_data, f"modify subuser '{resolved_uid}:{subuser}'")
    log.info(f"Subuser '{resolved_uid}:{subuser}' modified successfully{site_info}")
    return subuser_data


def delete_subuser(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    subuser,
    site_name="",
    purge_keys=None,
    tenant=None,
):
    """Delete subuser"""
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Deleting subuser '{resolved_uid}:{subuser}'{site_info}")
    base = {"uid": resolved_uid, "subuser": subuser, "format": "json"}
    if purge_keys is not None:
        base["purge-keys"] = purge_keys
    params = build_query_params(base)
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    log.info(f"Delete subuser response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            _raise_if_admin_error(
                json.loads(response.strip()),
                f"delete subuser '{resolved_uid}:{subuser}'",
            )
        except json.JSONDecodeError:
            pass
    log.info(f"Subuser '{resolved_uid}:{subuser}' deleted successfully{site_info}")


def verify_replication(
    verification_type,
    source_site,
    target_site,
    target_endpoint,
    admin_key,
    admin_secret,
    **kwargs,
):
    """
    Generic verification function for replication

    Args:
        verification_type: Type of verification ('user_modification', 'user_deletion', 'subuser', 'subuser_deletion')
        source_site: Source site name
        target_site: Target site name
        target_endpoint: Target RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        **kwargs: Additional parameters based on verification type
    """
    log.info(
        f"Verifying {verification_type} replication from {source_site} to {target_site} site"
    )

    uid = kwargs.get("uid")

    if verification_type == "user_modification":
        expected_display_name = kwargs.get("expected_display_name")
        user_info = get_user_info(target_endpoint, admin_key, admin_secret, uid)
        actual_display_name = user_info.get("display_name", "")
        if actual_display_name != expected_display_name:
            log.error(
                f"REPLICATION FAILED: Display name on {target_site} is '{actual_display_name}', expected '{expected_display_name}'"
            )
            raise TestExecError(f"User modification not replicated to {target_site}")
        log.info(f"REPLICATION VERIFIED: User modification successfully replicated")

    elif verification_type == "user_deletion":
        response = admin_api_call(
            "GET",
            target_endpoint,
            admin_key,
            admin_secret,
            f"?uid={uid}&format=json",
            "",
            "application/json",
        )
        response_str = str(response) if response else ""
        if (
            "NoSuchUser" in response_str
            or "user does not exist" in response_str.lower()
        ):
            log.info(f"REPLICATION VERIFIED: User deletion successfully replicated")
        else:
            log.error(
                f"REPLICATION FAILED: User '{uid}' still exists on {target_site} site"
            )
            log.error(f"Response: {response_str}")
            raise TestExecError(f"User deletion not replicated to {target_site}")

    elif verification_type == "subuser":
        subuser = kwargs.get("subuser")
        user_info = get_user_info(target_endpoint, admin_key, admin_secret, uid)
        subusers = user_info.get("subusers", [])
        subuser_ids = [su.get("id") for su in subusers]
        expected_id = f"{uid}:{subuser}"
        if expected_id not in subuser_ids:
            log.error(
                f"REPLICATION FAILED: Subuser '{expected_id}' not found on {target_site} site"
            )
            raise TestExecError(f"Subuser not replicated to {target_site}")
        log.info(
            f"REPLICATION VERIFIED: Subuser '{expected_id}' successfully replicated"
        )

    elif verification_type == "subuser_modification":
        subuser = kwargs.get("subuser")
        expected_permissions = kwargs.get("expected_permissions", "full-control")
        user_info = get_user_info(target_endpoint, admin_key, admin_secret, uid)
        log.info(f"Verification response: {user_info}")
        subusers = user_info.get("subusers", [])
        expected_id = f"{uid}:{subuser}"
        subuser_found = next(
            (su for su in subusers if su.get("id") == expected_id), None
        )
        if not subuser_found:
            log.error(
                f"REPLICATION FAILED: Subuser '{expected_id}' not found on {target_site} site"
            )
            raise TestExecError(f"Subuser not found on {target_site}")
        actual_permissions = subuser_found.get("permissions", "")
        if actual_permissions != expected_permissions:
            log.error(
                f"REPLICATION FAILED: Subuser permissions on {target_site} is '{actual_permissions}', expected '{expected_permissions}'"
            )
            raise TestExecError(f"Subuser modification not replicated to {target_site}")
        log.info(
            f"REPLICATION VERIFIED: Subuser '{expected_id}' permissions successfully changed to '{expected_permissions}'"
        )

    elif verification_type == "subuser_deletion":
        subuser = kwargs.get("subuser")
        user_info = get_user_info(target_endpoint, admin_key, admin_secret, uid)
        log.info(f"Verification response: {user_info}")
        subusers = user_info.get("subusers", [])
        subuser_ids = [su.get("id") for su in subusers]
        expected_id = f"{uid}:{subuser}"
        if expected_id in subuser_ids:
            log.error(
                f"REPLICATION FAILED: Subuser '{expected_id}' still exists on {target_site} site"
            )
            raise TestExecError(f"Subuser deletion not replicated to {target_site}")
        log.info(f"REPLICATION VERIFIED: Subuser deletion successfully replicated")


def add_user_capabilities(
    endpoint, admin_key, admin_secret, uid, caps, site_name="", tenant=None
):
    """
    Add capabilities to user

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to add capabilities to
        caps: Capabilities string (e.g., "usage=read,write")
        site_name: Site name for logging (optional)
        tenant: Optional tenant (uid sent as tenant$uid)

    Returns:
        Capabilities data
    """
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Adding capabilities '{caps}' to user '{resolved_uid}'{site_info}")
    params = build_query_params(
        {"uid": resolved_uid, "caps": True, "format": "json"}, user_caps=caps
    )
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    caps_data = parse_json_response(response, "add capabilities")
    _raise_if_admin_error(caps_data, f"add caps for '{resolved_uid}'")
    log.info(f"Capabilities added successfully{site_info}: {caps_data}")
    return caps_data


def remove_user_capabilities(
    endpoint, admin_key, admin_secret, uid, caps, site_name="", tenant=None
):
    """
    Remove capabilities from user

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to remove capabilities from
        caps: Capabilities string (e.g., "usage=read,write")
        site_name: Site name for logging (optional)
        tenant: Optional tenant (uid sent as tenant$uid)
    """
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Removing capabilities '{caps}' from user '{resolved_uid}'{site_info}")
    params = build_query_params(
        {"uid": resolved_uid, "caps": True, "format": "json"}, user_caps=caps
    )
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
    )
    log.info(f"Remove capabilities response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            _raise_if_admin_error(
                json.loads(response.strip()), f"remove caps for '{resolved_uid}'"
            )
        except json.JSONDecodeError:
            pass
    log.info(f"Capabilities removed successfully{site_info}")


def verify_user_capabilities(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    expected_caps=None,
    should_exist=True,
    tenant=None,
):
    """
    Verify user capabilities

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to check
        expected_caps: Expected capabilities list (e.g., [{"type": "usage", "perm": "*"}])
        should_exist: Whether capabilities should exist (True) or be empty (False)
        tenant: Optional tenant
    """
    user_info = get_user_info(endpoint, admin_key, admin_secret, uid, tenant=tenant)
    actual_caps = user_info.get("caps", [])

    if should_exist and expected_caps:
        if not actual_caps:
            log.error(f"VERIFICATION FAILED: No capabilities found for user '{uid}'")
            raise TestExecError(f"Expected capabilities not found for user {uid}")

        for expected_cap in expected_caps:
            cap_found = any(
                cap.get("type") == expected_cap.get("type")
                and cap.get("perm") == expected_cap.get("perm")
                for cap in actual_caps
            )
            if not cap_found:
                log.error(
                    f"VERIFICATION FAILED: Expected capability {expected_cap} not found"
                )
                log.error(f"Actual capabilities: {actual_caps}")
                raise TestExecError(f"Capability {expected_cap} not found")
        log.info(
            f"VERIFICATION PASSED: All expected capabilities found for user '{uid}'"
        )
    elif not should_exist:
        if actual_caps:
            log.error(f"VERIFICATION FAILED: Capabilities still exist: {actual_caps}")
            raise TestExecError(
                f"Capabilities should be empty but found: {actual_caps}"
            )
        log.info(
            f"VERIFICATION PASSED: No capabilities found as expected for user '{uid}'"
        )

    return actual_caps


def create_bucket_s3(endpoint, access_key, secret_key, bucket_name, site_name=""):
    """
    Create bucket via SigV1 curl PUT (does not require aws CLI).

    Tentacle client nodes often lack `aws`; AdminOps suites must not soft-pass
    when bucket setup fails.
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating bucket '{bucket_name}'{site_info}")
    host = endpoint.split("//")[1]
    cmd = f"""
DATE=$(date -R -u)
STRING_TO_SIGN="PUT\\n\\n\\n$DATE\\n/{bucket_name}"
SIGNATURE=$(echo -en "$STRING_TO_SIGN" | openssl sha1 -hmac {secret_key} -binary | base64)
curl -s -o /tmp/rgw_bkt_create_body -w "%{{http_code}}" -X PUT \\
  -H "Date: $DATE" -H "Authorization: AWS {access_key}:$SIGNATURE" \\
  -H "Host: {host}" "{endpoint}/{bucket_name}"
"""
    code = utils.exec_shell_cmd(cmd)
    body = utils.exec_shell_cmd("cat /tmp/rgw_bkt_create_body 2>/dev/null || true")
    log.info(f"Create bucket HTTP {code} body={body!r}")
    if code is False or str(code).strip() not in ("200", "201", "204"):
        raise TestExecError(
            f"Failed to create bucket '{bucket_name}'{site_info}: "
            f"HTTP {code} body={body!r}"
        )
    log.info(f"Bucket '{bucket_name}' created successfully{site_info}")
    return True


def delete_bucket_admin_api(
    endpoint, admin_key, admin_secret, bucket_name, site_name=""
):
    """
    Delete bucket using Admin API

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        bucket_name: Bucket name to delete
        site_name: Site name for logging (optional)
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Deleting bucket '{bucket_name}'{site_info}")
    params = build_query_params(
        {"bucket": bucket_name, "purge-objects": True, "format": "json"}
    )
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
        resource="bucket",
    )
    log.info(f"Delete bucket response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            parsed = parse_json_response(response, "delete bucket")
        except TestExecError:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("Code"):
            # NoSuchBucket after successful purge is acceptable.
            if parsed.get("Code") not in ("NoSuchBucket", "NoSuchKey"):
                _raise_if_admin_error(parsed, f"delete bucket '{bucket_name}'")
    log.info(f"Bucket '{bucket_name}' deleted successfully{site_info}")


def list_buckets_s3(endpoint, access_key, secret_key):
    """
    List buckets using AWS CLI

    Args:
        endpoint: RGW endpoint URL
        access_key: User access key
        secret_key: User secret key

    Returns:
        List of bucket names
    """
    cmd = f"AWS_ACCESS_KEY_ID={access_key} AWS_SECRET_ACCESS_KEY={secret_key} aws s3 ls --endpoint-url {endpoint}"
    response = utils.exec_shell_cmd(cmd)
    log.info(f"List buckets response: {response}")

    # Parse bucket names from response
    buckets = []
    if response:
        for line in response.strip().split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    buckets.append(parts[2])
    return buckets


def verify_bucket_exists(
    endpoint, access_key, secret_key, bucket_name, should_exist=True
):
    """
    Verify bucket existence

    Args:
        endpoint: RGW endpoint URL
        access_key: User access key
        secret_key: User secret key
        bucket_name: Bucket name to verify
        should_exist: Whether bucket should exist (True) or not (False)
    """
    buckets = list_buckets_s3(endpoint, access_key, secret_key)
    bucket_found = bucket_name in buckets

    if should_exist and not bucket_found:
        log.error(f"VERIFICATION FAILED: Bucket '{bucket_name}' not found")
        log.error(f"Available buckets: {buckets}")
        raise TestExecError(f"Bucket {bucket_name} not found")
    elif not should_exist and bucket_found:
        log.error(f"VERIFICATION FAILED: Bucket '{bucket_name}' still exists")
        raise TestExecError(f"Bucket {bucket_name} should not exist")

    if should_exist:
        log.info(f"VERIFICATION PASSED: Bucket '{bucket_name}' exists")
    else:
        log.info(f"VERIFICATION PASSED: Bucket '{bucket_name}' does not exist")


def list_users(
    endpoint, admin_key, admin_secret, max_entries=None, marker=None, site_name=""
):
    """List users via GET /admin/user?list (AdminOps user list)."""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Listing users{site_info}")
    base = {"list": True, "format": "json"}
    if max_entries is not None:
        base["max-entries"] = max_entries
    if marker is not None:
        base["marker"] = marker
    params = build_query_params(base)
    response = admin_api_call("GET", endpoint, admin_key, admin_secret, params)
    return parse_json_response(response, "user list")


def create_tenant_user(
    endpoint,
    admin_key,
    admin_secret,
    tenant,
    uid,
    display_name,
    site_name="",
    **options,
):
    """Create a tenanted user (tenant query param and/or tenant$uid)."""
    log.info(f"Creating tenant user tenant={tenant} uid={uid}")
    return create_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        display_name,
        site_name=site_name,
        tenant=tenant,
        **options,
    )


def create_tenant_subuser(
    endpoint,
    admin_key,
    admin_secret,
    tenant,
    uid,
    subuser,
    site_name="",
    key_type="swift",
    access="full",
    generate_secret=True,
    **options,
):
    """
    Create a subuser under a tenanted parent user via AdminOps.

    REST has no tenant= on subuser ops; parent is addressed as tenant$uid.
    Defaults match CLI tenant Swift subuser create (key-type=swift, access=full).
    """
    log.info(
        f"Creating tenanted subuser tenant={tenant} uid={uid} subuser={subuser} "
        f"key-type={key_type}"
    )
    return create_subuser(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        subuser,
        site_name=site_name,
        key_type=key_type,
        access=access,
        generate_secret=generate_secret,
        tenant=tenant,
        **options,
    )


def create_system_user(
    endpoint, admin_key, admin_secret, uid, display_name, site_name="", **options
):
    """
    Create a system user via AdminOps (system=True).

    Caller credentials must belong to a system user or Ceph returns EINVAL.
    """
    log.info(f"Creating system user '{uid}'")
    return create_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        display_name,
        site_name=site_name,
        system=True,
        **options,
    )


def create_admin_ops_user(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    display_name,
    site_name="",
    caps="users=*;accounts=*;buckets=*;metadata=*;usage=*;zone=*",
    **options,
):
    """
    Create a user with AdminOps capabilities (REST equivalent of
    create_rest_admin_user). CLI ``--admin`` flag is not exposed over AdminOps.
    """
    log.info(f"Creating admin-ops user '{uid}' with caps={caps}")
    user_data = create_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        display_name,
        site_name=site_name,
        user_caps=caps,
        **options,
    )
    # Ensure caps are present even if create ignored user-caps on older builds
    try:
        add_user_capabilities(
            endpoint, admin_key, admin_secret, uid, caps, site_name=site_name
        )
    except Exception as e:
        log.warning(f"caps add after create_admin_ops_user: {e}")
    return get_user_info(endpoint, admin_key, admin_secret, uid) or user_data


def create_swift_user(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    display_name,
    site_name="",
    subuser="swift",
    access="full",
    generate_key=True,
    **options,
):
    """
    Create a Swift-capable user the Ceph way: S3 parent user + Swift subuser.

    AdminOps does not support key-type=swift on user create; Swift secrets
    belong to subusers (see radosgw-admin subuser create / key create).
    """
    log.info(f"Creating Swift user '{uid}' (parent + subuser={subuser})")
    create_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        display_name,
        site_name=site_name,
        generate_key=generate_key,
        **options,
    )
    create_swift_subuser(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        subuser,
        site_name=site_name,
        access=access,
        generate_secret=True,
    )
    return get_user_info(endpoint, admin_key, admin_secret, uid)


def create_swift_subuser(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    subuser,
    site_name="",
    access="full",
    generate_secret=True,
    tenant=None,
    **options,
):
    """Create a Swift subuser (key-type=swift). Pass tenant= for tenanted parents."""
    return create_subuser(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        subuser,
        site_name=site_name,
        key_type="swift",
        access=access,
        generate_secret=generate_secret,
        tenant=tenant,
        **options,
    )


def create_swift_key(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    site_name="",
    subuser="swift",
    generate_key=True,
    **options,
):
    """Create a Swift key for a subuser (subuser is required for key-type=swift)."""
    if not subuser:
        raise TestExecError("create_swift_key requires subuser")
    return create_key(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        site_name=site_name,
        key_type="swift",
        subuser=subuser,
        generate_key=generate_key,
        **options,
    )


def suspend_user(endpoint, admin_key, admin_secret, uid, site_name="", tenant=None):
    """Suspend user via POST /admin/user?suspended=True."""
    log.info(f"Suspending user '{uid}'")
    return modify_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        site_name=site_name,
        tenant=tenant,
        suspended=True,
    )


def enable_user(endpoint, admin_key, admin_secret, uid, site_name="", tenant=None):
    """Re-enable suspended user via POST /admin/user?suspended=False."""
    log.info(f"Enabling user '{uid}'")
    return modify_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        site_name=site_name,
        tenant=tenant,
        suspended=False,
    )


def create_account_user(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    display_name,
    account_id,
    site_name="",
    account_root=False,
    tenant=None,
    **options,
):
    """
    Create a user under an RGW account (account-id / account-root).

    account-root is sent as a flag when True and omitted when False (matches
    radosgw-admin --account-root).

    Account users require IAM-safe display names ([\\w+=,.@-]+); spaces and
    other characters cause InvalidArgument from validate_iam_user_name.
    """
    # Sanitize so callers with faker "first last" names do not fail.
    safe_name = re.sub(r"[^\w+=,.@-]", "-", str(display_name or uid)).strip("-")
    if not safe_name:
        safe_name = str(uid)
    if safe_name != display_name:
        log.info(
            f"Sanitized account user display-name {display_name!r} -> {safe_name!r}"
        )
    log.info(
        f"Creating account user '{uid}' account_id={account_id} root={account_root}"
    )
    # Only pass account_root when True so we emit flag ``account-root``.
    root_kw = {"account_root": True} if account_root else {}
    return create_user(
        endpoint,
        admin_key,
        admin_secret,
        uid,
        safe_name[:64],
        site_name=site_name,
        tenant=tenant,
        account_id=account_id,
        **root_kw,
        **options,
    )


def create_account(
    endpoint,
    admin_key,
    admin_secret,
    account_id,
    name,
    site_name="",
    email=None,
    tenant=None,
    max_users=None,
    max_roles=None,
    max_groups=None,
    max_access_keys=None,
    max_buckets=None,
):
    """Create account via POST /admin/account (Squid+)."""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating account id={account_id} name={name}{site_info}")
    base = {"id": account_id, "name": name, "format": "json"}
    if email is not None:
        base["email"] = email
    if tenant is not None:
        base["tenant"] = tenant
    if max_users is not None:
        base["max-users"] = max_users
    if max_roles is not None:
        base["max-roles"] = max_roles
    if max_groups is not None:
        base["max-groups"] = max_groups
    if max_access_keys is not None:
        base["max-access-keys"] = max_access_keys
    if max_buckets is not None:
        base["max-buckets"] = max_buckets
    params = build_query_params(base)
    response = admin_api_call(
        "POST",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
        resource="account",
    )
    data = parse_json_response(response, "account creation")
    _raise_if_admin_error(data, f"create account '{account_id}'")
    return data


def modify_account(
    endpoint,
    admin_key,
    admin_secret,
    account_id=None,
    name=None,
    email=None,
    site_name="",
    tenant=None,
    max_users=None,
    max_roles=None,
    max_groups=None,
    max_access_keys=None,
    max_buckets=None,
):
    """Modify account via PUT /admin/account."""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Modifying account id={account_id} name={name}{site_info}")
    base = {"format": "json"}
    if account_id is not None:
        base["id"] = account_id
    if name is not None:
        base["name"] = name
    if email is not None:
        base["email"] = email
    if tenant is not None:
        base["tenant"] = tenant
    if max_users is not None:
        base["max-users"] = max_users
    if max_roles is not None:
        base["max-roles"] = max_roles
    if max_groups is not None:
        base["max-groups"] = max_groups
    if max_access_keys is not None:
        base["max-access-keys"] = max_access_keys
    if max_buckets is not None:
        base["max-buckets"] = max_buckets
    params = build_query_params(base)
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
        resource="account",
    )
    data = parse_json_response(response, "account modification")
    _raise_if_admin_error(data, f"modify account '{account_id or name}'")
    return data


def get_account_info(
    endpoint, admin_key, admin_secret, account_id=None, name=None, site_name=""
):
    """Get account info via GET /admin/account."""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Getting account info id={account_id} name={name}{site_info}")
    base = {"format": "json"}
    if account_id is not None:
        base["id"] = account_id
    if name is not None:
        base["name"] = name
    params = build_query_params(base)
    response = admin_api_call(
        "GET", endpoint, admin_key, admin_secret, params, resource="account"
    )
    data = parse_json_response(response, "account info")
    _raise_if_admin_error(data, f"get account info '{account_id or name}'")
    return data


def delete_account(
    endpoint,
    admin_key,
    admin_secret,
    account_id=None,
    name=None,
    email=None,
    tenant=None,
    site_name="",
):
    """Delete account via DELETE /admin/account."""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Deleting account id={account_id} name={name}{site_info}")
    base = {"format": "json"}
    if account_id is not None:
        base["id"] = account_id
    if name is not None:
        base["name"] = name
    if email is not None:
        base["email"] = email
    if tenant is not None:
        base["tenant"] = tenant
    params = build_query_params(base)
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
        resource="account",
    )
    log.info(f"Delete account response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            parsed = parse_json_response(response, "delete account")
        except TestExecError:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("Code"):
            if parsed.get("Code") not in ("NoSuchAccount", "NoSuchKey", "NoSuchUser"):
                _raise_if_admin_error(parsed, f"delete account '{account_id or name}'")
    return response


def set_user_quota(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    quota_type,
    quota_json,
    site_name="",
    tenant=None,
):
    """
    Set user or bucket-scope quota via PUT /admin/user?quota.

    quota_type: 'user' or 'bucket'
    quota_json: dict e.g. enabled/max_size/max_objects/max_size_kb
    """
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Setting {quota_type} quota for '{resolved_uid}'{site_info}")
    params = build_query_params(
        {
            "uid": resolved_uid,
            "quota": True,
            "quota-type": quota_type,
            "format": "json",
        }
    )
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        params,
        json.dumps(quota_json),
        "application/json",
    )
    log.info(f"set_user_quota response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            parsed = parse_json_response(response, "set_user_quota")
        except TestExecError:
            parsed = None
        if isinstance(parsed, dict):
            _raise_if_admin_error(parsed, "set_user_quota")
    return response


def get_user_quota(
    endpoint, admin_key, admin_secret, uid, quota_type, site_name="", tenant=None
):
    """Get user/bucket-scope quota via GET /admin/user?quota."""
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Getting {quota_type} quota for '{resolved_uid}'{site_info}")
    params = build_query_params(
        {
            "uid": resolved_uid,
            "quota": True,
            "quota-type": quota_type,
            "format": "json",
        }
    )
    response = admin_api_call("GET", endpoint, admin_key, admin_secret, params)
    return parse_json_response(response, f"{quota_type} quota")


def set_individual_bucket_quota(
    endpoint,
    admin_key,
    admin_secret,
    uid,
    bucket_name,
    quota_json,
    site_name="",
    tenant=None,
):
    """Set per-bucket quota via PUT /admin/bucket?quota."""
    resolved_uid = resolve_tenanted_uid(uid, tenant)
    site_info = f" on {site_name} site" if site_name else ""
    log.info(
        f"Setting individual bucket quota for bucket '{bucket_name}' "
        f"uid='{resolved_uid}'{site_info}"
    )
    params = build_query_params(
        {
            "uid": resolved_uid,
            "bucket": bucket_name,
            "quota": True,
            "format": "json",
        }
    )
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        params,
        json.dumps(quota_json),
        "application/json",
        resource="bucket",
    )
    log.info(f"set_individual_bucket_quota response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            parsed = parse_json_response(response, "set_individual_bucket_quota")
        except TestExecError:
            parsed = None
        if isinstance(parsed, dict):
            _raise_if_admin_error(parsed, "set_individual_bucket_quota")
    return response


def set_account_quota(
    endpoint,
    admin_key,
    admin_secret,
    account_id,
    quota_type="account",
    max_size=None,
    max_objects=None,
    enabled=None,
    site_name="",
):
    """
    Set account quota via PUT /admin/account?quota (Squid+).

    quota_type: 'account' or 'bucket'
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Setting account quota id={account_id} type={quota_type}{site_info}")
    base = {
        "id": account_id,
        "quota": True,
        "quota-type": quota_type,
        "format": "json",
    }
    if max_size is not None:
        base["max-size"] = max_size
    if max_objects is not None:
        base["max-objects"] = max_objects
    if enabled is not None:
        base["enabled"] = enabled
    params = build_query_params(base)
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        params,
        "",
        "application/json",
        resource="account",
    )
    log.info(f"set_account_quota response: {response}")
    if response and isinstance(response, str) and response.strip():
        try:
            parsed = parse_json_response(response, "set_account_quota")
        except TestExecError:
            parsed = None
        if isinstance(parsed, dict):
            _raise_if_admin_error(parsed, f"set_account_quota '{account_id}'")
    return response


def get_account_quota(
    endpoint,
    admin_key,
    admin_secret,
    account_id,
    quota_type="account",
    site_name="",
):
    """Get account quota via GET /admin/account?quota."""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Getting account quota id={account_id} type={quota_type}{site_info}")
    params = build_query_params(
        {
            "id": account_id,
            "quota": True,
            "quota-type": quota_type,
            "format": "json",
        }
    )
    response = admin_api_call(
        "GET", endpoint, admin_key, admin_secret, params, resource="account"
    )
    data = parse_json_response(response, "account quota")
    _raise_if_admin_error(data, f"get_account_quota '{account_id}'")
    return data


def delete_user(uid):
    """Delete user using radosgw-admin"""
    try:
        utils.exec_shell_cmd(f"radosgw-admin user rm --uid={uid} --purge-data")
        log.info(f"Cleaned up user: {uid}")
    except Exception as e:
        log.warning(f"Failed to cleanup {uid}: {e}")
