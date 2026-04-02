"""
admin_api.py - Admin API functions for multisite S3 credential operations

This module provides reusable functions for testing S3 credential replication
in multisite RGW setups using Admin API with AWS Signature authentication.
"""

import json
import logging
import random
import string
from urllib.parse import quote

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError

log = logging.getLogger()


def generate_random_string(length=8):
    """Generate random string for user names"""
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for i in range(length)
    )


def parse_json_response(response, context="API"):
    """Parse and validate JSON response"""
    if not response or not isinstance(response, str):
        raise TestExecError(f"{context} command execution failed: {response}")
    try:
        return json.loads(response)
    except (json.JSONDecodeError, TypeError):
        raise TestExecError(f"Invalid JSON response from {context}: {response}")


def admin_api_call(
    method, endpoint, admin_key, admin_secret, params="", data="", content_type=""
):
    """
    Execute admin API call with AWS signature authentication

    Args:
        method: HTTP method (GET, PUT, POST, DELETE)
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        params: URL query parameters
        data: Request body data
        content_type: Content-Type header value

    Returns:
        Response string from curl command
    """
    host = endpoint.split("//")[1]
    ct_header = f'-H "Content-Type: {content_type}"' if content_type else ""
    data_param = f"-d '{data}'" if data else ""

    cmd = f"""
DATE=$(date -R -u)
STRING_TO_SIGN="{method}\\n\\n{content_type}\\n$DATE\\n/admin/user"
SIGNATURE=$(echo -en "$STRING_TO_SIGN" | openssl sha1 -hmac {admin_secret} -binary | base64)
curl -s -X {method} {ct_header} -H "Date: $DATE" -H "Authorization: AWS {admin_key}:$SIGNATURE" -H "Host: {host}" {data_param} "{endpoint}/admin/user{params}"
"""
    return utils.exec_shell_cmd(cmd)


def create_user(endpoint, admin_key, admin_secret, uid, display_name, site_name=""):
    """
    Create user on specified endpoint

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to create
        display_name: Display name for user
        site_name: Site name for logging (optional)

    Returns:
        User data dictionary with keys information
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating user '{uid}'{site_info}")
    # URL encode display_name to handle spaces and special characters
    encoded_display_name = quote(display_name)
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        f"?display-name={encoded_display_name}&uid={uid}",
    )
    user_data = parse_json_response(response, "user creation")
    if "keys" not in user_data:
        raise TestExecError(f"Failed to create user: {user_data}")
    log.info(f"User '{uid}' created successfully{site_info}")
    log.info(f"Initial access key: {user_data['keys'][0]['access_key']}")
    return user_data


def create_key(endpoint, admin_key, admin_secret, uid, site_name=""):
    """
    Create access key for user

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to create key for
        site_name: Site name for logging (optional)

    Returns:
        Key data dictionary with access_key and secret_key
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating new access key for user '{uid}'{site_info}")
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&key&format=json",
        '{"key-type":"s3"}',
        "application/json",
    )
    key_data = parse_json_response(response, "key creation")
    if "access_key" not in key_data:
        raise TestExecError(f"Failed to create key: {key_data}")
    log.info(f"Access key created successfully{site_info}: {key_data['access_key']}")
    return key_data


def get_user_info(endpoint, admin_key, admin_secret, uid):
    """
    Get user information from endpoint

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to query

    Returns:
        User information dictionary
    """
    response = admin_api_call("GET", endpoint, admin_key, admin_secret, f"?uid={uid}")
    return parse_json_response(response, "user info")


def verify_key_replication(
    key, source_site, target_site, target_endpoint, admin_key, admin_secret, uid
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

    Returns:
        User information from target site
    """
    log.info(f"Verifying key replication from {source_site} to {target_site} site")
    user_info = get_user_info(target_endpoint, admin_key, admin_secret, uid)
    keys = [k.get("access_key") for k in user_info.get("keys", [])]
    if key not in keys:
        log.error(
            f"REPLICATION FAILED: Key '{key}' created on {source_site} site is NOT present on {target_site} site"
        )
        log.error(f"Keys found on {target_site} site: {keys}")
        raise TestExecError(f"Key {key} not replicated to {target_site}")
    log.info(
        f"REPLICATION VERIFIED: Key '{key}' successfully replicated from {source_site} to {target_site} site"
    )
    return user_info


def verify_all_keys(
    keys, primary_endpoint, secondary_endpoint, admin_key, admin_secret, uid
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
    """
    log.info(
        f"Verifying all {len(keys)} keys exist on both Primary and Secondary sites"
    )
    primary_info = get_user_info(primary_endpoint, admin_key, admin_secret, uid)
    secondary_info = get_user_info(secondary_endpoint, admin_key, admin_secret, uid)

    primary_keys = [k.get("access_key") for k in primary_info.get("keys", [])]
    secondary_keys = [k.get("access_key") for k in secondary_info.get("keys", [])]

    for key in keys:
        if key not in primary_keys or key not in secondary_keys:
            log.error(f"VERIFICATION FAILED: Key '{key}' missing on one or both sites")
            raise TestExecError(f"Key {key} missing on one or both sites")
        log.info(f"  Key '{key}' - Present on both sites")

    log.info(
        f"ALL KEYS VERIFIED: Primary site has {len(primary_keys)} keys, Secondary site has {len(secondary_keys)} keys"
    )


def delete_user(uid):
    """
    Delete user using radosgw-admin

    Args:
        uid: User ID to delete
    """
    try:
        utils.exec_shell_cmd(f"radosgw-admin user rm --uid={uid} --purge-data")
        log.info(f"Cleaned up user: {uid}")
    except Exception as e:
        log.warning(f"Failed to cleanup {uid}: {e}")
