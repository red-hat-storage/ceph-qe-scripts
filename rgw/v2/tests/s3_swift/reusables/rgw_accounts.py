import json
import logging
import os
import random
import time

import boto
import boto3
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format string
    raise TypeError(f"Type {type(obj)} not serializable")


def get_rgw_account():
    """Fetches the RGW account ID using radosgw-admin and returns it."""
    command = "radosgw-admin account list"
    account_list_output = utils.exec_shell_cmd(command)

    if not account_list_output:
        raise RuntimeError("Failed to fetch RGW account list or no accounts found.")

    try:
        account_list = json.loads(account_list_output)  # Convert string output to JSON
    except json.JSONDecodeError:
        raise ValueError(
            f"Invalid JSON output from radosgw-admin account list: {account_list_output}"
        )

    if isinstance(account_list, list) and account_list:
        return account_list[0]  # Assuming there's at least one account
    else:
        raise ValueError(
            f"Unexpected output format from radosgw-admin account list: {account_list_output}"
        )


def create_rgw_account_with_iam_user(config, tenant_name, region="shared"):
    """
    Automates the creation of an RGW tenanted account, root user, IAM user, and grants full S3 access.

    Returns:
        dict: IAM user details, including access/secret keys and RGW IAM user info.
    """
    rgw_ip_primary_zone = utils.get_rgw_ip_zone("primary")
    rgw_port_primary_zone = utils.get_radosgw_port_no()
    endpoint_url = f"http://{rgw_ip_primary_zone}:{rgw_port_primary_zone}"

    # Fetch existing accounts
    account_list_output = utils.exec_shell_cmd("radosgw-admin account list")
    existing_accounts = json.loads(account_list_output) if account_list_output else []

    if not isinstance(existing_accounts, list):
        log.error(f"Unexpected response format for account list: {account_list_output}")
        existing_accounts = []

    account_id = None
    account_name = None

    # Check if a suitable account already exists
    for account in existing_accounts:
        if not account or account == "0":
            continue

        account_info_output = utils.exec_shell_cmd(
            f"radosgw-admin account get --account-id {account}"
        )
        if not account_info_output:
            continue

        try:
            account_info = json.loads(account_info_output)
            if (
                isinstance(account_info, dict)
                and account_info.get("tenant") == tenant_name
            ):
                log.info(f"Reusing existing account: {account}")
                account_id = account
                account_name = account_info.get(
                    "name", f"account-{random.randint(1000, 9999)}"
                )
                break
        except json.JSONDecodeError:
            log.error(f"Invalid JSON response for account {account}. Skipping...")

    # Create a new account if none found
    if not account_id:
        account_id = f"RGW{random.randint(10**16, 10**17 - 1)}"
        account_name = f"account-{random.randint(1000, 9999)}"
        account_email = f"{account_name}@email.com"

        new_account = utils.exec_shell_cmd(
            f"radosgw-admin account create --account-name {account_name} "
            f"--tenant {tenant_name} --email {account_email} --account-id {account_id}"
        )
        if not new_account:
            raise RuntimeError("Failed to create account.")

        log.info(f"Created new account: {account_id}")

    # Check for existing users under this account
    user_list_output = utils.exec_shell_cmd(
        f"radosgw-admin user list --account-id {account_id}"
    )
    user_list = json.loads(user_list_output) if user_list_output else []

    root_user = None
    iam_user_uid = None
    for user in user_list:
        if "root" in user:
            root_user = user
        elif user != root_user:
            iam_user_uid = user

    # Fetch credentials for root user if exists
    if root_user:
        log.info(f"Found existing root user: {root_user}")
        root_user_info = json.loads(
            utils.exec_shell_cmd(
                f"radosgw-admin user info --uid {root_user.split('$')[-1]} --tenant {tenant_name}"
            )
        )
        access_key = root_user_info["keys"][0]["access_key"]
        secret_key = root_user_info["keys"][0]["secret_key"]
    else:
        # Create root user if not found
        root_user_name = f"{account_name}root-user"
        root_user_info = json.loads(
            utils.exec_shell_cmd(
                f"radosgw-admin user create --uid {root_user_name} --display-name {root_user_name} "
                f"--tenant {tenant_name} --account-id {account_id} --account-root --gen-secret --gen-access-key"
            )
        )
        access_key = root_user_info["keys"][0]["access_key"]
        secret_key = root_user_info["keys"][0]["secret_key"]
        log.info(f"Created RGW root user: {root_user_name}")

    # Establish IAM session
    rgw_session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    iam_client = rgw_session.client("iam", endpoint_url=endpoint_url)
    # Check if `testing_bucket_notification` is enabled
    testing_bucket_notification = config.test_ops.get(
        "testing_bucket_notification", False
    )

    # Check if IAM user exists
    iam_user_name = f"{account_name}iam-user"
    if iam_user_uid:
        log.info(f"Found existing IAM user: {iam_user_uid}")
        iam_user_rgw_info = json.loads(
            utils.exec_shell_cmd(
                f"radosgw-admin user info --uid {iam_user_uid.split('$')[-1]} --tenant {tenant_name}"
            )
        )
        # Attach AmazonSNSFullAccess if `testing_bucket_notification` is True
        if testing_bucket_notification:
            log.info(
                f"Attaching AmazonSNSFullAccess to existing IAM user: {iam_user_name}"
            )
            iam_client.attach_user_policy(
                UserName=iam_user_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonSNSFullAccess",
            )
    else:
        # Create IAM user
        try:
            iam_client.create_user(UserName=iam_user_name)
            access_key_data = iam_client.create_access_key(UserName=iam_user_name)
            iam_client.attach_user_policy(
                UserName=iam_user_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            )
            log.info(f"Created IAM user: {iam_user_name} with full S3 access")
            if testing_bucket_notification:
                iam_client.attach_user_policy(
                    UserName=iam_user_name,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonSNSFullAccess",
                )
        except iam_client.exceptions.EntityAlreadyExistsException:
            log.info(f"IAM user '{iam_user_name}' already exists.")
            access_key_data = None

        # Step 8: Get IAM user info
        user_info = iam_client.get_user(UserName=iam_user_name)
        log.info(f"Retrieved IAM user info: {user_info}")

        # Step 9: Fetch IAM user details from RGW
        user_list = utils.exec_shell_cmd(
            f"radosgw-admin user list --account-id {account_id}"
        )
        # Convert the output string to a list
        try:
            user_list = json.loads(user_list)
        except json.JSONDecodeError:
            raise RuntimeError(f"Failed to parse user list: {user_list}")
        log.info(f"Parsed user list: {user_list}")
        iam_user_uid = next((uid for uid in user_list if uid != root_user_name), None)
        # Extract IAM user ID (remove tenant prefix)
        iam_user_uid = iam_user_uid.split("$")[-1]
        iam_user_rgw_info = utils.exec_shell_cmd(
            f"radosgw-admin user info --uid {iam_user_uid} --tenant {tenant_name}"
        )
        log.info(f"Display the iam_user_rgw_info {iam_user_rgw_info}")
        # Ensure output is valid JSON
        try:
            iam_user_rgw_info = json.loads(iam_user_rgw_info)
            log.info(f"Parsed IAM user info: {iam_user_rgw_info}")
        except json.JSONDecodeError:
            log.error(f"Failed to parse IAM user info: {iam_user_rgw_info}")
            raise RuntimeError(
                f"Invalid JSON response for IAM user: {iam_user_rgw_info}"
            )
    iam_user_details = [
        {
            "user_id": iam_user_rgw_info["user_id"],
            "display_name": iam_user_rgw_info["display_name"],
            "access_key": iam_user_rgw_info["keys"][0]["access_key"],
            "secret_key": iam_user_rgw_info["keys"][0]["secret_key"],
        }
    ]
    write_user_info = AddUserInfo()
    basic_io_structure = BasicIOInfoStructure()
    user_info = basic_io_structure.user(
        **{
            "user_id": iam_user_rgw_info["user_id"],
            "access_key": iam_user_rgw_info["keys"][0]["access_key"],
            "secret_key": iam_user_rgw_info["keys"][0]["secret_key"],
        }
    )
    write_user_info.add_user_info(user_info)
    lib_dir = "/home/cephuser/rgw-ms-tests/ceph-qe-scripts/rgw/v2/lib"
    user_detail_file = os.path.join(lib_dir, "user_details.json")
    with open(user_detail_file, "w") as fout:
        json.dump(iam_user_details, fout)
    return iam_user_details


def reuse_account_bucket(config, rgw, user_info, location=None):
    """
    Reuse an existing bucket for an RGW account if it meets predefined conditions.
    If the bucket has more than 1M objects, it is selected for reuse.
    :param rgw: RGW resource connection
    :param user_info: Dictionary containing user credentials
    :return: Bucket resource object if criteria met, else None
    """
    rgw_account_id = get_rgw_account()
    log.info(f"Fetching bucket list for RGW account: {rgw_account_id}")

    # Get the list of buckets
    cmd = f"radosgw-admin bucket list --account-id {rgw_account_id}"
    bucket_list_json = utils.exec_shell_cmd(cmd)

    if not bucket_list_json:
        log.error("Failed to retrieve bucket list or received empty response.")
        return None

    bucket_list = json.loads(bucket_list_json)

    if not bucket_list:
        log.warning("No buckets found for the given account.")
        return None

    log.info(f"Found {len(bucket_list)} buckets. Checking stats...")

    for bucket_name in bucket_list:
        original_bucket_name = bucket_name  # Keep original for logging
        if "tenant" in bucket_name:
            tenant_name, bucket_short_name = bucket_name.split(".", 1)
            bucket_name = f"{tenant_name}/{bucket_name}"

        log.info(f"Checking stats for bucket: {original_bucket_name}")

        # Fetch bucket statistics
        stats_cmd = f"radosgw-admin bucket stats --bucket {bucket_name}"
        bucket_stats_json = utils.exec_shell_cmd(stats_cmd)

        if not bucket_stats_json:
            log.warning(f"Skipping {original_bucket_name}: Failed to retrieve stats.")
            continue

        bucket_stats = json.loads(bucket_stats_json)
        num_objects = (
            bucket_stats.get("usage", {}).get("rgw.main", {}).get("num_objects", 0)
        )

        log.info(f"Bucket {original_bucket_name} has {num_objects} objects.")

        if num_objects >= 1100000:
            log.info(
                f"Bucket {original_bucket_name} meets criteria. Returning for reuse."
            )

            # Return bucket in the expected format
            bucket = s3lib.resource_op(
                {"obj": rgw, "resource": "Bucket", "args": [original_bucket_name]}
            )
            return bucket  # Return the first valid bucket

    log.warning("No buckets met the 1M objects criteria.")
    return None  # No valid bucket found


def perform_user_adoption(config, user_info, bucket):
    """
    Perform user adoption by migrating an RGW user to an RGW account.
    Ensures the full function runs completely.
    """
    user_id = user_info["user_id"]
    bucket_name = bucket.name

    log.info("Checking for existing RGW accounts...")
    account_list_output = utils.exec_shell_cmd("radosgw-admin account list")

    if not account_list_output:
        log.warning("No accounts found or command failed! Creating a new RGW account.")
        existing_accounts = []
    else:
        existing_accounts = json.loads(account_list_output)

    target_account_id = None
    for account_id in existing_accounts:
        account_details_output = utils.exec_shell_cmd(
            f"radosgw-admin account get --account-id {account_id}"
        )

        if not account_details_output:
            log.warning(
                f"Failed to fetch details for account {account_id}, skipping..."
            )
            continue

        account_details = json.loads(account_details_output)
        if "tenant" in account_details:
            continue

        target_account_id = account_id
        log.info(f"Found existing account {target_account_id} without a tenant.")
        break

    # If no suitable account found, create a new one
    if not target_account_id:
        log.info("No suitable account found. Creating a new RGW account...")
        target_account_id = f"RGW{random.randint(10**16, 10**17 - 1)}"
        account_name = f"account-{random.randint(1000, 9999)}"
        account_email = f"{account_name}@email.com"

        create_account_cmd = (
            f"radosgw-admin account create --account-name {account_name} "
            f"--email {account_email} --account-id {target_account_id}"
        )
        create_account_output = utils.exec_shell_cmd(create_account_cmd)

        if not create_account_output:
            log.error("Failed to create new RGW account! Exiting user adoption.")
            raise RuntimeError("RGW account creation failed")

        log.info(f"Created new account {account_name} with ID {target_account_id}")

    # Proceed with user adoption
    log.info(f"Migrating user {user_id} to account {target_account_id}...")
    log.info(
        f"Before migrating user {user_id} to account {target_account_id}, rename the user to {account_name}-migration-rgw "
    )

    rename_user_cmd = f"radosgw-admin user rename --uid {user_id} --new-uid {account_name}-migration-rgw"
    utils.exec_shell_cmd(rename_user_cmd)
    user_id = f"{account_name}-migration-rgw"

    modify_user_cmd = f"radosgw-admin user modify --uid={user_id} --account-id={target_account_id} --account-root --display-name {account_name}MigratedUser"
    if not utils.exec_shell_cmd(modify_user_cmd):
        log.error(f"Failed to modify user {user_id} for adoption.")
        raise RuntimeError("User adoption modification failed!")

    # Attach Amazon S3 Full Access policy
    attach_policy_cmd = f"radosgw-admin user policy attach --uid={user_id} --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess"
    if not utils.exec_shell_cmd(attach_policy_cmd):
        log.error(f"Failed to attach policy to user {user_id}.")
        raise RuntimeError("User policy attachment failed!")

    # Reset account-root flag to 0
    reset_root_cmd = f"radosgw-admin user modify --uid={user_id} --account-root=0"
    if not utils.exec_shell_cmd(reset_root_cmd):
        log.warning(f"Failed to reset account-root for user {user_id}.")

    log.info("Waiting 2 seconds to ensure the adoption is fully applied...")
    time.sleep(2)

    # Validate bucket ownership after adoption
    log.info("Validating bucket stats after adoption...")
    bucket_stats_output = utils.exec_shell_cmd(
        f"radosgw-admin bucket stats --bucket {bucket_name}"
    )

    if not bucket_stats_output:
        log.error("Failed to fetch bucket stats! Adoption validation incomplete.")
        raise RuntimeError("Bucket stats retrieval failed")

    bucket_stats = json.loads(bucket_stats_output)
    new_owner = bucket_stats.get("owner")

    if new_owner == target_account_id:
        log.info(
            f"Bucket {bucket_name} successfully adopted by account {target_account_id}"
        )
    else:
        log.error(
            f"Bucket adoption failed! Expected owner {target_account_id}, found {new_owner}"
        )
        raise RuntimeError("Bucket adoption validation failed")


def account_ownership_change(config):
    """
    Test RGW account ownership change of two RGW users belonging to different accounts.
    """
    log.info("Creating two RGW accounts")
    account1_id = f"RGW{random.randint(10**16, 10**17 - 1)}"
    account2_id = f"RGW{random.randint(10**16, 10**17 - 1)}"
    account1_name = f"account-{random.randint(1000, 9999)}"
    account2_name = f"account-{random.randint(1000, 9999)}"
    account1_email = f"{account1_name}@email.com"
    account2_email = f"{account2_name}@email.com"

    utils.exec_shell_cmd(
        f"radosgw-admin account create --account-name {account1_name} --email {account1_email} --account-id {account1_id}"
    )
    utils.exec_shell_cmd(
        f"radosgw-admin account create --account-name {account2_name} --email {account2_email} --account-id {account2_id}"
    )

    root_user1 = "rootuser1"
    root_user2 = "rootuser2"
    user1 = "user1"
    user2 = "user2"

    utils.exec_shell_cmd(
        f"radosgw-admin user create --uid={root_user1} --display-name='Rootuser1' --account-id={account1_id} --account-root --gen-secret --gen-access-key"
    )
    utils.exec_shell_cmd(
        f"radosgw-admin user create --uid={root_user2} --display-name='Rootuser2' --account-id={account2_id} --account-root --gen-secret --gen-access-key"
    )

    utils.exec_shell_cmd(
        f"radosgw-admin user create --uid={user1} --display-name='User1' --account-id={account1_id} --account-root 0 --gen-secret --gen-access-key"
    )
    utils.exec_shell_cmd(
        f"radosgw-admin user create --uid={user2} --display-name='User2' --account-id={account2_id} --account-root 0 --gen-secret --gen-access-key"
    )

    log.info(
        "Attempting to change ownership of user1 from account1 to account2 (should fail)"
    )
    try:
        utils.exec_shell_cmd(
            f"radosgw-admin user modify --uid={user1} --account-id={account2_id}"
        )
    except Exception as e:
        log.info("Ownership change failed as expected: " + str(e))
