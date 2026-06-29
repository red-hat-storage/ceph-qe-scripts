"""
admin_api.py - Admin API functions for multisite S3 credential operations

This module provides reusable functions for testing S3 credential replication
in multisite RGW setups using Admin API with AWS Signature authentication.
"""

import json
import logging
import random
import string
import time
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
    log.info(f"Response: {response}")
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
    encoded_display_name = quote(display_name)
    for attempt in range(5):
        response = admin_api_call(
            "PUT",
            endpoint,
            admin_key,
            admin_secret,
            f"?display-name={encoded_display_name}&uid={uid}",
        )
        if response:
            try:
                user_data = parse_json_response(response, "user creation")
                if "keys" in user_data:
                    log.info(f"User '{uid}' created successfully{site_info}")
                    log.info(
                        f"Initial access key: {user_data['keys'][0]['access_key']}"
                    )
                    return user_data
            except Exception as e:
                log.warning(f"Parse failed (attempt {attempt+1}/5): {e}")

        if attempt < 4:
            log.warning(f"Empty/invalid response, retrying ({attempt+1}/5)...")
            time.sleep(3)

    raise TestExecError(f"Failed to create user '{uid}' after 5 retries")


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

    for attempt in range(5):
        response = admin_api_call(
            "PUT",
            endpoint,
            admin_key,
            admin_secret,
            f"?uid={uid}&key&format=json",
            '{"key-type":"s3"}',
            "application/json",
        )

        if response:
            try:
                key_data = parse_json_response(response, "key creation")
                if "access_key" in key_data:
                    log.info(
                        f"Access key created successfully{site_info}: {key_data['access_key']}"
                    )
                    return key_data
            except Exception as e:
                log.warning(f"Parse failed (attempt {attempt+1}): {e}")

        log.warning(f"Empty/invalid response, retrying ({attempt+1}/5)...")
        time.sleep(3)

    raise TestExecError(f"Failed to create key after retries for user {uid}")


def get_user_info(endpoint, admin_key, admin_secret, uid, retries=5, wait_time=3):
    """
    Get user information from endpoint

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to query
        retries: Number of retry attempts for transient failures (default: 5)
        wait_time: Seconds to wait between retries (default: 3)

    Returns:
        User information dictionary
    """
    for attempt in range(retries):
        response = admin_api_call(
            "GET", endpoint, admin_key, admin_secret, f"?uid={uid}"
        )
        if response is not False:
            return parse_json_response(response, "user info")
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


def modify_user(endpoint, admin_key, admin_secret, uid, display_name, site_name=""):
    """Modify user display name"""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Modifying user '{uid}'{site_info} with new display name: {display_name}")
    encoded_display_name = quote(display_name)
    response = admin_api_call(
        "POST",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&display-name={encoded_display_name}&format=json",
        "",
        "application/json",
    )
    user_data = parse_json_response(response, "user modification")
    log.info(f"User '{uid}' modified successfully{site_info}")
    return user_data


def delete_user_api(endpoint, admin_key, admin_secret, uid, site_name=""):
    """Delete user using Admin API"""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Deleting user '{uid}'{site_info}")
    admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&format=json",
        "",
        "application/json",
    )
    log.info(f"User '{uid}' deleted successfully{site_info}")


def create_subuser(endpoint, admin_key, admin_secret, uid, subuser, site_name=""):
    """Create subuser for a user"""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating subuser '{subuser}' for user '{uid}'{site_info}")
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&subuser={subuser}&key-type=s3&format=json",
        "",
        "application/json",
    )
    log.info(f"Create subuser response: {response}")
    subuser_data = parse_json_response(response, "subuser creation")
    log.info(f"Subuser '{uid}:{subuser}' created successfully{site_info}")
    return subuser_data


def modify_subuser(endpoint, admin_key, admin_secret, uid, subuser, site_name=""):
    """Modify subuser permissions to full-control and generate new key"""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(
        f"Modifying subuser '{uid}:{subuser}'{site_info} - setting permissions to full-control"
    )
    response = admin_api_call(
        "POST",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&subuser={subuser}&key-type=s3&access=full&format=json",
        "",
        "application/json",
    )
    log.info(f"Modify subuser response: {response}")
    subuser_data = parse_json_response(response, "subuser modification")
    log.info(
        f"Subuser '{uid}:{subuser}' modified successfully{site_info} - permissions set to full-control"
    )
    return subuser_data


def delete_subuser(endpoint, admin_key, admin_secret, uid, subuser, site_name=""):
    """Delete subuser"""
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Deleting subuser '{uid}:{subuser}'{site_info}")
    response = admin_api_call(
        "DELETE",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&subuser={subuser}&format=json",
        "",
        "application/json",
    )
    log.info(f"Delete subuser response: {response}")
    log.info(f"Subuser '{uid}:{subuser}' deleted successfully{site_info}")


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


def add_user_capabilities(endpoint, admin_key, admin_secret, uid, caps, site_name=""):
    """
    Add capabilities to user

    Args:
        endpoint: RGW endpoint URL
        admin_key: Admin access key
        admin_secret: Admin secret key
        uid: User ID to add capabilities to
        caps: Capabilities string (e.g., "usage=read,write")
        site_name: Site name for logging (optional)

    Returns:
        Capabilities data
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Adding capabilities '{caps}' to user '{uid}'{site_info}")
    response = admin_api_call(
        "PUT",
        endpoint,
        admin_key,
        admin_secret,
        f"?uid={uid}&caps&user-caps={caps}&format=json",
        "",
        "application/json",
    )
    caps_data = parse_json_response(response, "add capabilities")
    log.info(f"Capabilities added successfully{site_info}: {caps_data}")
    return caps_data


def remove_user_capabilities(
    endpoint, admin_key, admin_secret, uid, caps, site_name=""
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
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Removing capabilities '{caps}' from user '{uid}'{site_info}")
    host = endpoint.split("//")[1]
    cmd = f"""
DATE=$(date -R -u)
STRING_TO_SIGN="DELETE\\n\\napplication/json\\n$DATE\\n/admin/user"
SIGNATURE=$(echo -en "$STRING_TO_SIGN" | openssl sha1 -hmac {admin_secret} -binary | base64)
curl -s -X DELETE -H "Content-Type: application/json" -H "Date: $DATE" -H "Authorization: AWS {admin_key}:$SIGNATURE" -H "Host: {host}" "{endpoint}/admin/user?uid={uid}&caps&user-caps={caps}&format=json"
"""
    response = utils.exec_shell_cmd(cmd)
    log.info(f"Remove capabilities response: {response}")
    log.info(f"Capabilities removed successfully{site_info}")


def verify_user_capabilities(
    endpoint, admin_key, admin_secret, uid, expected_caps=None, should_exist=True
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
    """
    user_info = get_user_info(endpoint, admin_key, admin_secret, uid)
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
    Create bucket using AWS CLI

    Args:
        endpoint: RGW endpoint URL
        access_key: User access key
        secret_key: User secret key
        bucket_name: Bucket name to create
        site_name: Site name for logging (optional)
    """
    site_info = f" on {site_name} site" if site_name else ""
    log.info(f"Creating bucket '{bucket_name}'{site_info}")
    cmd = f"AWS_ACCESS_KEY_ID={access_key} AWS_SECRET_ACCESS_KEY={secret_key} aws s3 mb s3://{bucket_name} --endpoint-url {endpoint}"
    response = utils.exec_shell_cmd(cmd)
    log.info(f"Create bucket response: {response}")
    log.info(f"Bucket '{bucket_name}' created successfully{site_info}")


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
    host = endpoint.split("//")[1]
    cmd = f"""
DATE=$(date -R -u)
STRING_TO_SIGN="DELETE\\n\\napplication/json\\n$DATE\\n/admin/bucket"
SIGNATURE=$(echo -en "$STRING_TO_SIGN" | openssl sha1 -hmac {admin_secret} -binary | base64)
curl -s -X DELETE -H "Content-Type: application/json" -H "Date: $DATE" -H "Authorization: AWS {admin_key}:$SIGNATURE" -H "Host: {host}" "{endpoint}/admin/bucket?bucket={bucket_name}&purge-objects=True&format=json"
"""
    response = utils.exec_shell_cmd(cmd)
    log.info(f"Delete bucket response: {response}")
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


def delete_user(uid):
    """Delete user using radosgw-admin"""
    try:
        utils.exec_shell_cmd(f"radosgw-admin user rm --uid={uid} --purge-data")
        log.info(f"Cleaned up user: {uid}")
    except Exception as e:
        log.warning(f"Failed to cleanup {uid}: {e}")
