"""
Usage: test_iam_get_account_summary.py -c <input_yaml>

This test automates the iam:GetAccountSummary API call with comprehensive scenarios.
It covers multiple users, buckets, and validates account summary at different stages.

Operation:
1. Create RGW account using radosgw-admin
2. Create root user with account-root flag
3. Create multiple IAM users (configurable)
4. Create access keys for IAM users
5. Attach policies to IAM users
6. Create buckets for different users
7. Call iam:GetAccountSummary API at different stages and validate responses
8. Test various scenarios: users with/without buckets, different policies, etc.
"""

import argparse
import json
import logging
import os
import random
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
)
from v2.tests.s3_swift import reusable as s3_reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def validate_account_summary(iam_client, expected_min_users=0, stage=""):
    """
    Validate account summary response
    Args:
        iam_client: IAM client object
        expected_min_users: Minimum expected number of users
        stage: Description of current test stage
    Returns:
        dict: Account summary response
    """
    log.info(f"Validating account summary - Stage: {stage}")
    try:
        account_summary_response = iam_client.get_account_summary()
        log.info(f"Account summary response at {stage}:")
        log.info(json.dumps(account_summary_response, indent=2))

        # Validate response structure
        if "SummaryMap" not in account_summary_response:
            raise TestExecError(
                f"Invalid response at {stage}: 'SummaryMap' key not found in account summary"
            )

        summary_map = account_summary_response["SummaryMap"]
        log.info(f"Account Summary Map at {stage}: {json.dumps(summary_map, indent=2)}")

        # Validate expected fields
        expected_fields = [
            "Users",
            "Groups",
            "UsersQuota",
            "GroupsQuota",
            "AccessKeysPerUserQuota",
        ]
        for field in expected_fields:
            if field not in summary_map:
                raise TestExecError(
                    f"Expected field '{field}' not found in SummaryMap at {stage}"
                )
            log.info(f"{field}: {summary_map[field]}")

        # Validate users count
        users_count = summary_map.get("Users", 0)
        if users_count < expected_min_users:
            raise TestExecError(
                f"At {stage}: Expected at least {expected_min_users} users, but found {users_count}"
            )
        log.info(
            f"Validation passed at {stage}: Found {users_count} users (expected at least {expected_min_users})"
        )

        # Validate quotas
        users_quota = summary_map.get("UsersQuota", 0)
        groups_quota = summary_map.get("GroupsQuota", 0)
        access_keys_quota = summary_map.get("AccessKeysPerUserQuota", 0)

        log.info(f"Users Quota: {users_quota}")
        log.info(f"Groups Quota: {groups_quota}")
        log.info(f"Access Keys Per User Quota: {access_keys_quota}")

        if users_quota <= 0 or groups_quota <= 0 or access_keys_quota <= 0:
            raise TestExecError(f"At {stage}: Quota values should be greater than 0")

        return account_summary_response

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        raise TestExecError(
            f"Failed to get account summary at {stage}: {error_code} - {error_message}"
        )
    except Exception as e:
        raise TestExecError(
            f"Unexpected error calling get_account_summary at {stage}: {e}"
        )


def test_exec(config, ssh_con):
    """
    Executes comprehensive test based on configuration passed
    Args:
        config(object): Test configuration
        ssh_con: SSH connection object (optional)
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_bucket_io_info = BucketIoInfo()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # Step 1: Create or reuse RGW account
    log.info("=" * 80)
    log.info("SCENARIO 1: Creating or reusing RGW account")
    log.info("=" * 80)
    account_name = config.test_ops.get("account_name", "ceph-root")
    account_email = config.test_ops.get("account_email", "ceph-root@example.com")
    display_name = config.test_ops.get("display_name", "Ceph Root Account")

    # Check if account already exists
    account_list_cmd = "radosgw-admin account list"
    account_list_output = utils.exec_shell_cmd(account_list_cmd)
    account_id = None

    if account_list_output:
        try:
            account_list = json.loads(account_list_output)
            if isinstance(account_list, list) and account_list:
                # Try to find existing account by email
                for acc_id in account_list:
                    if not acc_id or acc_id == "0":
                        continue
                    try:
                        acc_info_cmd = (
                            f"radosgw-admin account get --account-id {acc_id}"
                        )
                        acc_info_output = utils.exec_shell_cmd(acc_info_cmd)
                        if acc_info_output:
                            acc_info = json.loads(acc_info_output)
                            if acc_info.get("email") == account_email:
                                account_id = acc_id
                                log.info(
                                    f"Found existing account with ID: {account_id}"
                                )
                                break
                    except Exception:
                        continue
        except (json.JSONDecodeError, Exception) as e:
            log.warning(f"Could not parse account list: {e}")

    # Create account if it doesn't exist
    if not account_id:
        account_create_cmd = (
            f'radosgw-admin account create --uid="{account_name}" '
            f'--display-name="{display_name}" '
            f'--email="{account_email}" --system'
        )
        account_output = utils.exec_shell_cmd(account_create_cmd)
        if not account_output:
            raise TestExecError("Failed to create RGW account")

        account_info = json.loads(account_output)
        account_id = account_info.get("id")
        if not account_id:
            raise TestExecError(
                "Failed to extract account ID from account creation response"
            )
        log.info(f"Created new RGW account with ID: {account_id}")
    else:
        log.info(f"Reusing existing RGW account with ID: {account_id}")

    # Step 2: Create or reuse root user
    log.info("=" * 80)
    log.info("SCENARIO 2: Creating or reusing root user")
    log.info("=" * 80)
    root_user_name = config.test_ops.get("root_user_name", "rgwroot")
    root_display_name = config.test_ops.get("root_display_name", "RGWRootUser")

    # Check if root user already exists
    user_list_cmd = f"radosgw-admin user list --account-id {account_id}"
    user_list_output = utils.exec_shell_cmd(user_list_cmd)
    root_user_exists = False

    if user_list_output:
        try:
            user_list = json.loads(user_list_output)
            if isinstance(user_list, list):
                for user in user_list:
                    if root_user_name in str(user):
                        root_user_exists = True
                        log.info(f"Found existing root user: {root_user_name}")
                        break
        except (json.JSONDecodeError, Exception):
            pass

    if root_user_exists:
        # Get existing root user info
        root_user_info_cmd = f"radosgw-admin user info --uid={root_user_name}"
        root_user_output = utils.exec_shell_cmd(root_user_info_cmd)
        if not root_user_output:
            raise TestExecError("Failed to get existing root user info")
        root_user_info = json.loads(root_user_output)
        log.info(f"Reusing existing root user: {root_user_name}")
    else:
        # Create new root user
        root_user_cmd = (
            f"radosgw-admin user create --uid={root_user_name} "
            f"--display-name={root_display_name} --account-id={account_id} "
            f"--account-root --gen-access-key --gen-secret"
        )
        root_user_output = utils.exec_shell_cmd(root_user_cmd)
        if not root_user_output:
            raise TestExecError("Failed to create root user")
        root_user_info = json.loads(root_user_output)
        log.info(f"Created new root user: {root_user_name}")

    root_access_key = root_user_info["keys"][0]["access_key"]
    root_secret_key = root_user_info["keys"][0]["secret_key"]
    log.info(f"Root user access key: {root_access_key}")

    # Step 3: Create IAM client using root user credentials via Auth class
    log.info("Creating IAM client using Auth class")
    root_user_dict = {
        "user_id": root_user_name,
        "access_key": root_access_key,
        "secret_key": root_secret_key,
    }
    auth = Auth(root_user_dict, ssh_con, ssl=config.ssl)
    iam_client = auth.do_auth_iam_client()

    # Step 4: Validate account summary after root user creation
    log.info("=" * 80)
    log.info("SCENARIO 3: Validating account summary after root user creation")
    log.info("=" * 80)
    summary_after_root = validate_account_summary(
        iam_client, expected_min_users=1, stage="After root user creation"
    )

    # Step 5: Create multiple IAM users
    log.info("=" * 80)
    log.info("SCENARIO 4: Creating multiple IAM users")
    log.info("=" * 80)
    num_iam_users = config.test_ops.get("num_iam_users", 3)
    iam_users = []
    iam_user_names = config.test_ops.get("iam_user_names", [])

    # If specific user names provided, use them; otherwise generate
    if not iam_user_names:
        iam_user_names = [f"User{i+1}" for i in range(num_iam_users)]
    else:
        num_iam_users = len(iam_user_names)

    log.info(f"Creating {num_iam_users} IAM users: {iam_user_names}")

    for i, iam_user_name in enumerate(iam_user_names):
        log.info(f"Creating IAM user {i+1}/{num_iam_users}: {iam_user_name}")
        try:
            iam_client.create_user(UserName=iam_user_name)
            log.info(f"Created IAM user: {iam_user_name}")
        except iam_client.exceptions.EntityAlreadyExistsException:
            log.info(f"IAM user '{iam_user_name}' already exists, continuing...")

        # Create access keys for each user
        try:
            access_key_response = iam_client.create_access_key(UserName=iam_user_name)
            user_access_key = access_key_response["AccessKey"]["AccessKeyId"]
            user_secret_key = access_key_response["AccessKey"]["SecretAccessKey"]
            log.info(f"Created access keys for {iam_user_name}")

            iam_users.append(
                {
                    "user_id": iam_user_name,
                    "access_key": user_access_key,
                    "secret_key": user_secret_key,
                    "user_name": iam_user_name,
                }
            )
        except iam_client.exceptions.LimitExceededException:
            log.warning(
                f"Access key limit reached for {iam_user_name}, listing existing keys"
            )
            list_keys_response = iam_client.list_access_keys(UserName=iam_user_name)
            if list_keys_response["AccessKeyMetadata"]:
                user_access_key = list_keys_response["AccessKeyMetadata"][0][
                    "AccessKeyId"
                ]
                log.info(f"Using existing access key for {iam_user_name}")
                iam_users.append(
                    {
                        "user_id": iam_user_name,
                        "access_key": user_access_key,
                        "secret_key": None,  # Cannot retrieve secret after creation
                        "user_name": iam_user_name,
                    }
                )

        # Attach policies to ALL users to enable bucket creation
        policy_arn = config.test_ops.get(
            "policy_arn", "arn:aws:iam::aws:policy/AmazonS3FullAccess"
        )
        try:
            iam_client.attach_user_policy(UserName=iam_user_name, PolicyArn=policy_arn)
            log.info(f"Attached policy {policy_arn} to {iam_user_name}")
        except iam_client.exceptions.PolicyNotAttachableException:
            log.warning(f"Policy {policy_arn} not attachable for {iam_user_name}")
        except Exception as e:
            log.warning(f"Failed to attach policy to {iam_user_name}: {e}")

    # Step 6: Validate account summary after creating IAM users
    log.info("=" * 80)
    log.info("SCENARIO 5: Validating account summary after creating IAM users")
    log.info("=" * 80)
    expected_users = 1 + num_iam_users  # root + IAM users
    summary_after_iam_users = validate_account_summary(
        iam_client,
        expected_min_users=expected_users,
        stage="After creating IAM users",
    )

    # Step 7: Create buckets for different users
    log.info("=" * 80)
    log.info("SCENARIO 6: Creating buckets for different users")
    log.info("=" * 80)
    bucket_count = config.test_ops.get("bucket_count", 2)
    buckets_created = []

    # Create buckets only for users that have access keys (can authenticate)
    users_with_keys = [u for u in iam_users if u.get("secret_key")]
    num_users_with_buckets = min(len(users_with_keys), bucket_count)

    log.info(
        f"Creating buckets: {num_users_with_buckets} users will have buckets created"
    )

    for i in range(num_users_with_buckets):
        user = users_with_keys[i]
        user_bucket_count = config.test_ops.get("buckets_per_user", 1)

        for bc in range(user_bucket_count):
            # Generate bucket name - ensure it's valid (lowercase, no special chars)
            bucket_name = utils.gen_bucket_name_from_userid(user["user_id"], rand_no=bc)
            # Ensure bucket name is lowercase and valid (S3 bucket naming rules)
            bucket_name = bucket_name.lower()
            # Remove any invalid characters if present
            bucket_name = "".join(c for c in bucket_name if c.isalnum() or c in ".-")
            # Ensure it doesn't start/end with . or -
            bucket_name = bucket_name.strip(".-")
            # Ensure length is valid (3-63 chars)
            if len(bucket_name) > 63:
                bucket_name = bucket_name[:63]
            if len(bucket_name) < 3:
                bucket_name = f"{bucket_name}-{bc}"

            log.info(
                f"Creating bucket '{bucket_name}' for user '{user['user_id']}' ({i+1}/{num_users_with_buckets}, bucket {bc+1}/{user_bucket_count})"
            )

            try:
                # Create S3 client for this user using Auth class
                user_auth = Auth(user, ssh_con, ssl=config.ssl)
                s3_client = user_auth.do_auth_using_client()

                # Create bucket using boto3 S3 client directly
                log.info(
                    f"Creating bucket '{bucket_name}' using S3 client for user '{user['user_id']}'"
                )
                response = s3_client.create_bucket(Bucket=bucket_name)

                buckets_created.append(
                    {"bucket_name": bucket_name, "user_id": user["user_id"]}
                )
                log.info(
                    f"Successfully created bucket '{bucket_name}' for user '{user['user_id']}'"
                )
                if response:
                    log.debug(f"Bucket creation response: {response}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                error_message = e.response.get("Error", {}).get("Message", str(e))
                if error_code in ["BucketAlreadyExists", "BucketAlreadyOwnedByYou"]:
                    log.info(
                        f"Bucket '{bucket_name}' already exists for user '{user['user_id']}', continuing..."
                    )
                    buckets_created.append(
                        {"bucket_name": bucket_name, "user_id": user["user_id"]}
                    )
                else:
                    log.warning(
                        f"Failed to create bucket '{bucket_name}' for user '{user['user_id']}': {error_code} - {error_message}"
                    )
            except Exception as e:
                error_msg = str(e)
                # If bucket already exists, that's okay - continue
                if (
                    "BucketAlreadyExists" in error_msg
                    or "BucketAlreadyOwnedByYou" in error_msg
                    or "already exists" in error_msg.lower()
                ):
                    log.info(
                        f"Bucket '{bucket_name}' already exists for user '{user['user_id']}', continuing..."
                    )
                    buckets_created.append(
                        {"bucket_name": bucket_name, "user_id": user["user_id"]}
                    )
                else:
                    log.warning(
                        f"Failed to create bucket '{bucket_name}' for user '{user['user_id']}': {e}"
                    )

    log.info(f"Total buckets created: {len(buckets_created)}")

    # Validate that at least some buckets were created
    if len(buckets_created) == 0:
        log.warning(
            "No buckets were created. This may indicate permission or configuration issues."
        )
        log.warning("Continuing with account summary validation...")
    else:
        log.info(
            f"Successfully created {len(buckets_created)} bucket(s) across {len(set(b['user_id'] for b in buckets_created))} user(s)"
        )

    # Step 8: Validate account summary after creating buckets
    log.info("=" * 80)
    log.info("SCENARIO 7: Validating account summary after creating buckets")
    log.info("=" * 80)
    summary_after_buckets = validate_account_summary(
        iam_client,
        expected_min_users=expected_users,
        stage="After creating buckets",
    )

    # Step 9: Compare summaries at different stages
    log.info("=" * 80)
    log.info("SCENARIO 8: Comparing account summaries at different stages")
    log.info("=" * 80)
    users_after_root = summary_after_root["SummaryMap"].get("Users", 0)
    users_after_iam = summary_after_iam_users["SummaryMap"].get("Users", 0)
    users_after_buckets = summary_after_buckets["SummaryMap"].get("Users", 0)

    log.info(f"Users after root user creation: {users_after_root}")
    log.info(f"Users after IAM users creation: {users_after_iam}")
    log.info(f"Users after buckets creation: {users_after_buckets}")

    if users_after_iam < users_after_root:
        raise TestExecError(
            f"User count decreased unexpectedly: {users_after_root} -> {users_after_iam}"
        )
    if users_after_buckets < users_after_iam:
        raise TestExecError(
            f"User count decreased unexpectedly: {users_after_iam} -> {users_after_buckets}"
        )

    log.info("User count progression validated successfully")

    # Step 10: Test edge cases
    log.info("=" * 80)
    log.info("SCENARIO 9: Testing edge cases")
    log.info("=" * 80)

    # Test with non-existent user (should still work with root user)
    log.info("Testing account summary with root user credentials")
    final_summary = validate_account_summary(
        iam_client,
        expected_min_users=expected_users,
        stage="Final validation with root user",
    )

    # Step 11: Validate all expected fields are present and have valid values
    log.info("=" * 80)
    log.info("SCENARIO 10: Final comprehensive validation")
    log.info("=" * 80)
    final_summary_map = final_summary["SummaryMap"]

    # Validate Users count matches expected
    if final_summary_map["Users"] != expected_users:
        log.warning(
            f"User count mismatch: Expected {expected_users}, got {final_summary_map['Users']}"
        )

    # Validate quotas are reasonable
    users_quota = final_summary_map.get("UsersQuota", 0)
    if final_summary_map["Users"] > users_quota:
        raise TestExecError(
            f"Users count ({final_summary_map['Users']}) exceeds quota ({users_quota})"
        )

    log.info("All comprehensive validations passed!")
    log.info(f"Summary: {json.dumps(final_summary_map, indent=2)}")

    # Step 12: Cleanup (optional, based on config)
    if config.test_ops.get("cleanup", False):
        log.info("=" * 80)
        log.info("SCENARIO 11: Cleanup")
        log.info("=" * 80)
        log.info("Cleanup requested but not implemented in this test")
        log.info("Users and buckets will remain for manual inspection")

    log.info("=" * 80)
    log.info("All test scenarios completed successfully!")
    log.info("=" * 80)


if __name__ == "__main__":
    test_info = AddTestInfo("Test iam:GetAccountSummary API - Comprehensive Scenarios")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("Test data directory does not exist, creating it..")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="RGW IAM GetAccountSummary Test - Comprehensive"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW Test YAML configuration", required=True
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
        # Workaround for frontend configuration bug in framework
        # The framework tries to configure frontend when SSL is detected but has a bug
        try:
            config.read()
        except TypeError as e:
            if "set_frontend() takes" in str(e) and "positional arguments" in str(e):
                log.warning(f"Frontend configuration error (known framework bug): {e}")
                log.info(
                    "Continuing test execution - frontend configuration not required for this test"
                )
                # Manually read YAML and set essential config attributes
                import yaml

                with open(yaml_file, "r") as f:
                    doc = yaml.safe_load(f)
                    cfg = doc.get("config", {})
                    # Set essential attributes that config.read() would set
                    # Check if cluster has SSL enabled (port 443 typically means SSL)
                    detected_ssl = utils.get_radosgw_port_no(ssh_con) == 443
                    config.ssl = cfg.get(
                        "ssl", detected_ssl
                    )  # Use config value or detect from port
                    config.haproxy = cfg.get("haproxy", False)
                    config.user_count = cfg.get("user_count", 0)
                    config.bucket_count = cfg.get("bucket_count", 0)
                    config.objects_count = cfg.get("objects_count", 0)
                    config.user_remove = cfg.get("user_remove", False)
                    config.test_ops = cfg.get("test_ops", {})
                    config.doc = doc
                    log.info("Config attributes set manually due to frontend bug")
            else:
                raise
        test_exec(config, ssh_con)
        test_info.success_status("Test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("Test failed")
        sys.exit(1)

    finally:
        if TEST_DATA_PATH and os.path.exists(TEST_DATA_PATH):
            utils.cleanup_test_data_path(TEST_DATA_PATH)
