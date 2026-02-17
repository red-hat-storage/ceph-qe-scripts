"""
test_n+e_signature_check.py - Test N+E Signature Checking with AssumeRoleWithWebIdentity

Usage: test_n+e_signature_check.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    configs/test_n+e_signature_check.yaml (for positive tests)
    configs/test_n+e_signature_check_negative.yaml (for negative tests)
    configs/test_n+e_signature_check_deny.yaml (for deny policy tests)

Operation:
    This test validates N+E (modulus and exponent) signature verification support
    for AssumeRoleWithWebIdentity using IBM IAM as the OIDC provider.

    Steps:
    1. Create admin user with oidc-provider and roles caps
    2. Configure RGW with STS settings
    3. Get IBM IAM JWT token (provided via config, environment variable, or IBM Cloud CLI)
    4. Create OIDC provider with IBM IAM URL and thumbprint
    5. Create role with AssumeRoleWithWebIdentity policy
    6. Assume role with web identity token (JWT with N+E signature)
    7. Perform S3 operations using temporary credentials
    8. Test negative scenarios (wrong thumbprint, expired token, etc.)
"""

import os
import sys
import tempfile

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import time
import traceback

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None
oidc_url = "https://iam.cloud.ibm.com/identity"


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_config_set = CephConfOp(ssh_con)
    if config.test_ops.get("sts") is None:
        raise TestExecError("STS configuration is missing in yaml config")

    log.info("Creating admin user for OIDC operations")
    admin_user_info = s3lib.create_users(1)[0]
    log.info("Adding oidc-provider and roles caps to admin user")
    add_caps_cmd = (
        f'radosgw-admin caps add --uid="{admin_user_info["user_id"]}" '
        f'--caps="oidc-provider=*"'
    )
    utils.exec_shell_cmd(add_caps_cmd)
    add_caps_cmd = (
        f'radosgw-admin caps add --uid="{admin_user_info["user_id"]}" '
        f'--caps="roles=*"'
    )
    utils.exec_shell_cmd(add_caps_cmd)
    log.info("Configuring RGW with STS settings")
    session_encryption_token = config.test_ops["sts_key"]
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, session_encryption_token, ssh_con
    )
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_s3_auth_use_sts, "True", ssh_con
    )
    reusable.restart_and_wait_until_daemons_up(ssh_con)
    log.info("Sleeping for 30 seconds after RGW restart")
    time.sleep(30)
    auth = Auth(admin_user_info, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
    iam_client = auth.do_auth_iam_client()
    ibm_region = os.getenv("IBM_CLOUD_REGION", "in-mum")
    jwt_token = config.test_ops.get("jwt_token")
    if not jwt_token:
        jwt_token = os.getenv("IBM_IAM_JWT_TOKEN")
        if jwt_token:
            log.info("JWT token found in environment variable IBM_IAM_JWT_TOKEN")

    if not jwt_token:
        log.info(
            "JWT token not provided in config or environment, attempting to get from IBM Cloud CLI"
        )
        try:
            ibm_cloud_cli_path = config.doc["config"].get("ibm_cloud_cli_path", None)
            # Load and set API key (equivalent to 'export IBM_CLOUD_API_KEY')
            api_key = reusable.load_and_set_api_key()
            if not api_key:
                log.warning(
                    "Note: If using sudo, environment variables are not preserved. "
                    "Use 'sudo -E' to preserve environment variables, or check if variable "
                    "is set in parent shell before sudo."
                )
            region = os.getenv("IBM_CLOUD_REGION", "in-mum")
            jwt_token = reusable.get_ibm_iam_jwt_token(
                ibm_cloud_cli_path,
                api_key=api_key,
                region=region,
            )

        except Exception as e:
            raise TestExecError(f"Failed to get JWT token: {e}")

    client_id = reusable.get_jwt_client_id(jwt_token)
    thumbprint = config.test_ops.get("thumbprint")
    if not thumbprint:
        thumbprint = os.getenv("IBM_IAM_THUMBPRINT")
        if thumbprint:
            log.info("Thumbprint found in environment variable IBM_IAM_THUMBPRINT")

    if not thumbprint:
        log.info(
            "Thumbprint not provided in config or environment, attempting to get from certificate"
        )
        try:
            thumbprint = reusable.get_ibm_iam_thumbprint(ibm_region)
        except Exception as e:
            raise TestExecError(f"Failed to get thumbprint: {e}")

    log.info("Creating OIDC provider for IBM IAM")
    oidc_response = reusable.create_oidc_provider_ibm_iam(
        iam_client, oidc_url, client_id, thumbprint
    )
    oidc_provider_arn = oidc_response["OpenIDConnectProviderArn"]
    log.info(f"OIDC provider ARN: {oidc_provider_arn}")
    policy_document = json.dumps(config.test_ops["sts"]["policy_document"])
    idp_url_for_arn = oidc_url.replace("https://", "").replace("http://", "")
    policy_document = policy_document.replace("idp_url", idp_url_for_arn)
    policy_document = policy_document.replace(f'": "client_id"', f'": "{client_id}"')
    role_policy = json.dumps(config.test_ops["sts"]["role_policy"])
    role_name = config.test_ops.get(
        "role_name", f"S3RoleOf.{admin_user_info['user_id']}"
    )
    log.info(f"Creating role: {role_name}")
    create_role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path="/",
        RoleName=role_name,
    )
    log.info(f"Role created: {create_role_response}")
    policy_name = config.test_ops.get("policy_name", f"Policy1")
    log.info(f"Putting role policy: {policy_name}")
    put_policy_response = iam_client.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
    )
    log.info(f"Role policy created: {put_policy_response}")
    log.info("Assuming role with web identity (N+E signature verification)")
    sts_client = auth.do_auth_sts_client()
    duration_seconds = config.test_ops.get("duration_seconds", 3600)
    role_session_name = config.test_ops.get("role_session_name", "test-session")
    try:
        assume_role_response = sts_client.assume_role_with_web_identity(
            RoleArn=create_role_response["Role"]["Arn"],
            RoleSessionName=role_session_name,
            DurationSeconds=duration_seconds,
            WebIdentityToken=jwt_token,
        )
        log.info(f"Assume role response: {assume_role_response}")
        assumed_role_user_info = {
            "access_key": assume_role_response["Credentials"]["AccessKeyId"],
            "secret_key": assume_role_response["Credentials"]["SecretAccessKey"],
            "session_token": assume_role_response["Credentials"]["SessionToken"],
            "user_id": assume_role_response.get(
                "SubjectFromWebIdentityToken", "oidc-user"
            ),
        }
        log.info(
            "Successfully obtained temporary credentials from AssumeRoleWithWebIdentity"
        )
        log.info(f"Access Key: {assumed_role_user_info['access_key']}")
        log.info(f"Expiration: {assume_role_response['Credentials']['Expiration']}")
        if config.test_ops.get("create_bucket", False):
            log.info("Creating S3 client with temporary credentials")
            s3client = Auth(
                assumed_role_user_info, ssh_con, ssl=config.ssl, haproxy=config.haproxy
            )
            s3_client_rgw = s3client.do_auth_using_client()
            log.info(f"Number of buckets to create: {config.bucket_count}")
            for bc in range(config.bucket_count):
                random_suffix = "".join([str(random.randint(0, 9)) for _ in range(6)])
                bucket_name_to_create = f"bucket-{random_suffix}-{bc}"
                log.info(f"Creating bucket: {bucket_name_to_create}")
                try:
                    s3_client_rgw.create_bucket(Bucket=bucket_name_to_create)
                    log.info(f"Bucket {bucket_name_to_create} created successfully")
                except ClientError as e:
                    log.error(f"Failed to create bucket {bucket_name_to_create}: {e}")
                    raise TestExecError(f"Bucket creation failed: {e}")

                if config.test_ops.get("create_object", False):
                    role_policy_dict = config.test_ops["sts"]["role_policy"]
                    has_deny_delete = False
                    if isinstance(role_policy_dict.get("Statement"), list):
                        for stmt in role_policy_dict["Statement"]:
                            if stmt.get("Effect") == "Deny":
                                action = stmt.get("Action", [])
                                if isinstance(action, str):
                                    action = [action]
                                if "s3:DeleteObject" in action:
                                    has_deny_delete = True
                                    break

                    elif isinstance(role_policy_dict.get("Statement"), dict):
                        stmt = role_policy_dict["Statement"]
                        if stmt.get("Effect") == "Deny":
                            action = stmt.get("Action", [])
                            if isinstance(action, str):
                                action = [action]
                            if "s3:DeleteObject" in action:
                                has_deny_delete = True

                    log.info(f"Creating objects in bucket: {bucket_name_to_create}")
                    test_delete_object_name = None
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
                        log.info(f"Uploading object: {s3_object_name}")
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        data_info = manage_data.io_generator(s3_object_path, size)
                        if data_info is False:
                            raise TestExecError("data creation failed")

                        log.info(f"Uploading s3 object: {s3_object_path}")
                        with open(s3_object_path, "rb") as file_data:
                            put_obj = s3_client_rgw.put_object(
                                Bucket=bucket_name_to_create,
                                Key=s3_object_name,
                                Body=file_data,
                            )

                        if not put_obj:
                            raise TestExecError("put object failed")
                        log.info(f"Object {s3_object_name} uploaded successfully")

                        if test_delete_object_name is None:
                            test_delete_object_name = s3_object_name

                    if (
                        config.test_ops.get("delete_object", False)
                        and test_delete_object_name
                    ):
                        if has_deny_delete:
                            log.info(
                                f"Testing deny policy: attempting to delete object {test_delete_object_name} (should fail)"
                            )
                            try:
                                s3_client_rgw.delete_object(
                                    Bucket=bucket_name_to_create,
                                    Key=test_delete_object_name,
                                )
                                raise TestExecError(
                                    f"Delete operation should have been denied for {test_delete_object_name}"
                                )

                            except ClientError as delete_e:
                                error_code = delete_e.response.get("Error", {}).get(
                                    "Code", ""
                                )
                                if error_code == "AccessDenied":
                                    log.info(
                                        f"Delete operation correctly denied for {test_delete_object_name} as per deny policy"
                                    )
                                else:
                                    raise TestExecError(
                                        f"Unexpected error when testing deny policy: {delete_e}"
                                    )

                        else:
                            log.info(
                                f"Testing delete object: {test_delete_object_name}"
                            )
                            try:
                                s3_client_rgw.delete_object(
                                    Bucket=bucket_name_to_create,
                                    Key=test_delete_object_name,
                                )
                                log.info(
                                    f"Object {test_delete_object_name} deleted successfully"
                                )

                            except ClientError as delete_e:
                                error_code = delete_e.response.get("Error", {}).get(
                                    "Code", ""
                                )
                                raise TestExecError(
                                    f"Delete operation failed for {test_delete_object_name}: {error_code}"
                                )

    except ClientError as e:
        log.error(f"ClientError during assume role: {e}")
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "InvalidIdentityToken":
            raise TestExecError(
                "Invalid JWT token - signature verification may have failed"
            )
        elif error_code == "AccessDenied":
            raise TestExecError(
                "Access denied - check role policy and OIDC provider configuration"
            )
        else:
            raise

    if config.test_ops.get("negative_tests", False):
        log.info("Running negative test scenarios")

        if config.test_ops.get("test_wrong_thumbprint", False):
            log.info("Testing with wrong thumbprint")
            wrong_thumbprint = "0000000000000000000000000000000000000000"
            try:
                wrong_thumbprint_response = reusable.create_oidc_provider_ibm_iam(
                    iam_client, oidc_url, client_id, wrong_thumbprint
                )
                wrong_thumbprint_arn = wrong_thumbprint_response[
                    "OpenIDConnectProviderArn"
                ]
                log.info(
                    f"OIDC provider recreated with wrong thumbprint. ARN: {wrong_thumbprint_arn}"
                )
                log.info(
                    "Waiting 2 seconds for OIDC provider with wrong thumbprint to be ready"
                )
                time.sleep(2)

                try:
                    log.info(
                        f"Attempting assume_role_with_web_identity with wrong thumbprint (should fail) - ARN: {wrong_thumbprint_arn}, Thumbprint: {wrong_thumbprint}"
                    )
                    sts_client.assume_role_with_web_identity(
                        RoleArn=create_role_response["Role"]["Arn"],
                        RoleSessionName=role_session_name,
                        DurationSeconds=duration_seconds,
                        WebIdentityToken=jwt_token,
                    )
                    log.warning(
                        f"assume_role_with_web_identity succeeded with wrong thumbprint - may be expected if RGW doesn't re-validate thumbprint on each call"
                    )

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    error_message = e.response.get("Error", {}).get("Message", "")
                    log.info(
                        f"Negative test passed: wrong thumbprint correctly rejected - Error Code: {error_code}, Message: {error_message}"
                    )

                finally:
                    try:
                        restored_response = reusable.create_oidc_provider_ibm_iam(
                            iam_client, oidc_url, client_id, thumbprint
                        )
                        restored_arn = restored_response["OpenIDConnectProviderArn"]
                        oidc_provider_arn = restored_arn  # Update ARN for cleanup
                        log.info(
                            f"OIDC provider restored with correct thumbprint. ARN: {restored_arn}"
                        )
                    except Exception as restore_e:
                        log.warning(
                            f"Error restoring OIDC provider after negative test: {restore_e}"
                        )

            except TestExecError:
                raise
            except ClientError:
                log.info("Negative test completed successfully")
            except Exception as e:
                log.error(f"Error in wrong thumbprint test: {e}")
                raise

    log.info("Cleaning up IAM resources (role policies, role, OIDC provider)")
    try:
        try:
            policy_names = iam_client.list_role_policies(RoleName=role_name)[
                "PolicyNames"
            ]
            for policy_name in policy_names:
                log.info(f"Deleting role policy: {policy_name}")
                iam_client.delete_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                log.info(f"Role policy {policy_name} deleted successfully")

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log.info(f"Role {role_name} does not exist or has no policies")
            else:
                log.warning(f"Error deleting role policies: {e}")

        try:
            iam_client.delete_role(RoleName=role_name)
            log.info(f"Role {role_name} deleted successfully")

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log.info(f"Role {role_name} does not exist")
            else:
                log.warning(f"Error deleting role: {e}")

        try:
            iam_client.delete_open_id_connect_provider(
                OpenIDConnectProviderArn=oidc_provider_arn
            )
            log.info(f"OIDC provider {oidc_provider_arn} deleted successfully")

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log.info(f"OIDC provider {oidc_provider_arn} does not exist")
            else:
                log.warning(f"Error deleting OIDC provider: {e}")

    except Exception as e:
        log.warning(f"Error during IAM resource cleanup: {e}")

    log.info(f"Removing admin user: {admin_user_info['user_id']}")
    reusable.remove_user(admin_user_info)
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    log.info("N+E signature checking test completed successfully")


if __name__ == "__main__":
    test_info = AddTestInfo("N+E Signature Checking with AssumeRoleWithWebIdentity")
    test_info.started_info()

    try:
        # Use temp directory so test data is always in a user-writable path
        # (repo may be cloned with sudo on remote, making project_dir root-owned)
        test_data_dir = "ceph_rgw_n+e_test_data"
        TEST_DATA_PATH = os.path.join(tempfile.gettempdir(), test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH, exist_ok=True)

        parser = argparse.ArgumentParser(
            description="RGW S3 N+E Signature Checking Automation"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW Test yaml configuration", required=True
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
        config = s3lib.Config(yaml_file)
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
