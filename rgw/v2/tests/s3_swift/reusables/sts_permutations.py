import inspect
import json
import logging
import random
import string
import time
from datetime import datetime, timedelta

from botocore.exceptions import ClientError
from v2.lib.s3.auth import Auth

log = logging.getLogger()


FAILED_ACTIONS = []
PASSED_ACTIONS = []

BUCKET = None
OBJECT_KEY = None
s3_client_bucket_owner = None


# setup actions and resource db

BUCKET_ACTIONS = [
    "create_bucket",
    "delete_bucket",
    "delete_bucket_encryption",
    "delete_bucket_policy",
    "delete_bucket_website",
    "delete_public_access_block",
    "delete_replication_configuration",
    "get_accelerate_configuration",
    "get_bucket_acl",
    "get_bucket_cors",
    "get_bucket_encryption",
    "get_bucket_location",
    "get_bucket_logging",
    "get_bucket_notification",
    "get_bucket_policy",
    "get_bucket_request_payment",
    "get_bucket_tagging",
    "get_bucket_versioning",
    "get_bucket_website",
    "get_lifecycle_configuration",
    "get_object_lock_configuration",
    "get_public_access_block",
    "get_replication_configuration",
    "head_bucket",
    # "list_bucket",
    "list_bucket_multipart_uploads",
    # "list_bucket_versions",
    "list_object_versions",
    "list_objects",
    "list_objects_v2",
    "put_bucket_acl",
    "put_bucket_cors",
    "put_bucket_encryption",
    # "put_bucket_logging",
    "put_bucket_notification",
    "put_bucket_policy",
    "put_bucket_tagging",
    "put_bucket_versioning",
    "put_bucket_website",
    "put_lifecycle_configuration",
    "put_object_lock_configuration",
    "put_public_access_block",
]

OBJECT_ACTIONS = [
    "abort_multipart_upload",
    "copy_object",
    "delete_object",
    "delete_object_version",
    "delete_objects",
    "get_object",
    "get_object_acl",
    "get_object_attributes",
    "get_object_legal_hold",
    "get_object_retention",
    "get_object_tagging",
    "put_object_tagging",
    "get_object_version",
    "get_object_version_acl",
    "head_object",
    "list_multipart_upload_parts",
    "multipart_upload",
    "put_object",
    "put_object_acl",
    "put_object_legal_hold",
    "put_object_retention",
    "put_object_version_acl",
    "remove_object_legal_hold",
    "remove_object_retention",
    # "restore_object",
    "select_object_content",
]

GLOBAL_ACTIONS = ["list_all_my_buckets"]

all_actions = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS


s3_action_allowed_methods = {
    "s3:AbortMultipartUpload": ["abort_multipart_upload"],
    "s3:CreateBucket": ["create_bucket"],
    "s3:DeleteBucketPolicy": ["delete_bucket_policy"],
    "s3:DeleteBucket": ["delete_bucket"],
    "s3:DeleteBucketWebsite": ["delete_bucket_website"],
    "s3:DeleteObject": ["delete_object"],
    "s3:DeleteObjectVersion": ["delete_object_version", "delete_objects"],
    "s3:DeleteReplicationConfiguration": ["delete_replication_configuration"],
    "s3:GetAccelerateConfiguration": ["get_accelerate_configuration"],
    "s3:GetBucketAcl": ["get_bucket_acl"],
    "s3:GetBucketCORS": ["get_bucket_cors"],
    "s3:GetBucketLocation": ["get_bucket_location"],
    "s3:GetBucketLogging": ["get_bucket_logging"],
    "s3:GetBucketNotification": ["get_bucket_notification"],
    "s3:GetBucketPolicy": ["get_bucket_policy"],
    "s3:GetBucketRequestPayment": ["get_bucket_request_payment"],
    "s3:GetBucketTagging": ["get_bucket_tagging"],
    "s3:GetBucketVersioning": ["get_bucket_versioning"],
    "s3:GetBucketWebsite": ["get_bucket_website"],
    "s3:GetLifecycleConfiguration": ["get_lifecycle_configuration"],
    # "s3:GetObjectAcl": ["get_object_acl"],
    "s3:GetObjectAcl": [],
    # "s3:GetObject": ["get_object"],
    "s3:GetObject": [],
    "s3:GetObjectVersion": [
        "get_object_version",
        "get_object",
        "get_object_attributes",
        "head_object",
        "select_object_content",
        "copy_object",
    ],
    # "s3:GetObjectVersion": ["get_object_version", "get_object", "head_object", "select_object_content"],
    # "s3:GetObjectAttributes": ["get_object_attributes"],
    "s3:GetObjectAttributes": [],
    # "s3:GetObjectVersionAttributes": ["get_object_attributes"],
    "s3:GetObjectVersionAttributes": [],
    # "s3:GetObjectTorrent": [],
    "s3:GetObjectVersionAcl": ["get_object_version_acl", "get_object_acl"],
    # "s3:GetObjectVersionTorrent": [],
    "s3:GetReplicationConfiguration": ["get_replication_configuration"],
    # "s3:IPAddress": [],
    # "s3:NotIpAddress": [],
    "s3:ListAllMyBuckets": ["list_all_my_buckets"],
    "s3:ListBucketMultipartUploads": ["list_bucket_multipart_uploads"],
    # "s3:ListBucket": ["list_bucket"],
    "s3:ListBucket": ["head_bucket", "list_objects", "list_objects_v2"],
    # "s3:ListBucketVersions": ["list_bucket_versions"],
    "s3:ListBucketVersions": ["list_object_versions"],
    "s3:ListMultipartUploadParts": ["list_multipart_upload_parts"],
    "s3:PutAccelerateConfiguration": [],
    "s3:PutBucketAcl": ["put_bucket_acl"],
    "s3:PutBucketCORS": ["put_bucket_cors"],
    # "s3:PutBucketLogging": ["put_bucket_logging"],
    "s3:PutBucketLogging": [],
    "s3:PutBucketNotification": ["put_bucket_notification"],
    "s3:PutBucketPolicy": ["put_bucket_policy"],
    "s3:PutBucketRequestPayment": [],
    "s3:PutBucketTagging": ["put_bucket_tagging"],
    "s3:PutBucketVersioning": ["put_bucket_versioning"],
    "s3:PutBucketWebsite": ["put_bucket_website"],
    "s3:PutLifecycleConfiguration": ["put_lifecycle_configuration"],
    # "s3:PutObjectAcl": ["put_object_acl"],
    "s3:PutObjectAcl": [],
    "s3:PutObjectVersionAcl": ["put_object_version_acl", "put_object_acl"],
    # "s3:PutObject": ["put_object", "multipart_upload", "copy_object"],
    "s3:PutObject": ["put_object", "multipart_upload"],
    "s3:PutReplicationConfiguration": [],
    "s3:RestoreObject": ["restore_object"],
}


s3_action_required_resource = {
    "s3:AbortMultipartUpload": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:CreateBucket": [
        "arn_access_all_buckets_and_objects",
        # "arn_access_only_the_bucket"
    ],
    "s3:DeleteBucketPolicy": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:DeleteBucket": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:DeleteBucketWebsite": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:DeleteObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:DeleteObjectVersion": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:DeleteReplicationConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetAccelerateConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketCORS": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketLocation": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketLogging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketNotification": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketPolicy": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketRequestPayment": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketTagging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketVersioning": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetBucketWebsite": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetLifecycleConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:GetObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:GetObjectVersion": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:GetObjectAttributes": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:GetObjectVersionAttributes": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:GetObjectAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:GetObjectVersionAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    # "s3:GetObjectTorrent": [
    #     "arn_access_all_buckets_and_objects",
    #     "arn_access_all_objects_under_all_buckets",
    #     "arn_access_only_the_bucket",
    #     "arn_access_all_objects_under_the_bucket"
    # ],
    # "s3:GetObjectVersionTorrent": [
    #     "arn_access_all_buckets_and_objects",
    #     "arn_access_all_objects_under_all_buckets",
    #     "arn_access_only_the_bucket",
    #     "arn_access_all_objects_under_the_bucket"
    # ],
    "s3:GetReplicationConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    # "s3:IPAddress": [
    #     "arn_access_all_buckets_and_objects"
    # ],
    # "s3:NotIpAddress": [
    #     "arn_access_all_buckets_and_objects"
    # ],
    "s3:ListAllMyBuckets": ["arn_access_all_buckets_and_objects"],
    "s3:ListBucketMultipartUploads": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:ListBucket": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:ListBucketVersions": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:ListMultipartUploadParts": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:PutAccelerateConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketCORS": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketLogging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketNotification": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketPolicy": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketRequestPayment": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketTagging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketVersioning": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutBucketWebsite": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutLifecycleConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutObjectAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:PutObjectVersionAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:PutObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
    "s3:PutReplicationConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:RestoreObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access",
    ],
}


def test_sts_static_role_session_policy(tenant_name, user1, user2, ssh_con, config):
    global BUCKET, OBJECT_KEY, s3_client_bucket_owner, PASSED_ACTIONS, FAILED_ACTIONS
    # Generate a random string of 5 characters
    characters = string.ascii_lowercase + string.digits
    random_string = "".join(random.choice(characters) for i in range(5))

    user1_name = user1["user_id"]
    auth1 = Auth(user1, ssh_con, ssl=config.ssl)
    iam = auth1.do_auth_iam_client()
    user1_s3_client = auth1.do_auth_using_client(**{"region_name": "us-east-1"})

    user2_name = user2["user_id"]
    auth2 = Auth(user2, ssh_con, ssl=config.ssl)
    user2_s3_client = auth2.do_auth_using_client(**{"region_name": "us-east-1"})
    user2_sts_client = auth2.do_auth_sts_client()

    # user3_name = user3["user_id"]
    # auth3 = Auth(user3, ssh_con, ssl=config.ssl)
    # user3_s3_client = auth1.do_auth_using_client(**{"region_name": "us-east-1"})(

    global s3_client_bucket_owner
    s3_client_bucket_owner = user1_s3_client
    assume_role_principal = user2_name

    index = 1
    FAILED_ACTIONS = []
    PASSED_ACTIONS = []
    BUCKET = f"bkt-{random_string}"
    # OBJECT_KEY = resource_type["object_name"]
    OBJECT_KEY = f"warehouse/test-object1-{random_string}"
    # raw_resources = resource_type["resource_list"]
    raw_resources = [
        f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse",
        f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/",
        f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/*",
    ]
    resource_list = [r.replace("<BUCKET>", BUCKET) for r in raw_resources]
    # arn_type = resource_type["name"]
    arn_type = "arn_pseudo_directory_access"
    expected_allowed_actions = config.test_ops.get("expected_allowed_actions", [])
    expected_denied_actions = config.test_ops.get("expected_denied_actions", [])
    if not expected_allowed_actions:
        expected_allowed_actions = sorted(
            list(set(all_actions) - set(expected_denied_actions))
        )
    if not expected_denied_actions:
        expected_denied_actions = sorted(
            list(set(all_actions) - set(expected_allowed_actions))
        )

    log.info(
        f"\n\n====================================================================================================== Test {arn_type}"
    )
    log.info(f"BUCKET {BUCKET}")
    log.info(f"OBJECT_KEY {OBJECT_KEY}")
    log.info(f"resource_list {resource_list}")

    if config.test_ops.get("same_bucket_owner_and_principal", False):
        user_name = user1_name
        s3_client_bucket_owner = user1_s3_client
    else:
        user_name = user2_name
        s3_client_bucket_owner = user2_s3_client

    log.info(f"creating bucket {BUCKET} from {user_name}")
    # resp = s3_client_bucket_owner.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    resp = s3_client_bucket_owner.create_bucket(Bucket=BUCKET)
    log.info(f"creating bucket response: {resp}")

    trust_policy = json.dumps(config.sts["trust_policy"]).replace(" ", "")
    trust_policy = trust_policy.replace("<tenant_name>", tenant_name)
    trust_policy = trust_policy.replace("<user_name>", assume_role_principal)

    role_policy = json.dumps(config.sts["role_policy"]).replace(" ", "")
    role_policy = role_policy.replace("<tenant_name>", tenant_name)
    role_policy = role_policy.replace("<bucket_name>", BUCKET)

    session_policy = json.dumps(config.sts["session_policy"]).replace(" ", "")
    session_policy = session_policy.replace("<tenant_name>", tenant_name)
    session_policy = session_policy.replace("<bucket_name>", BUCKET)

    # Step 1: Create Role
    role_name = f"TestRole-{random_string}-{index}"
    log.info(f"role_name {role_name}")
    log.info(f"trust policy: {trust_policy}")

    try:
        create_role_response = iam.create_role(
            RoleName=role_name,
            Path="/",
            AssumeRolePolicyDocument=trust_policy,
            Description="Role for testing STS assume-role in Ceph RGW",
        )
        log.info("Role created:", create_role_response)
    except ClientError as e:
        log.error(f"create role failed: {e}")
    role_arn = create_role_response["Role"]["Arn"]

    # Step 2: Attach Inline Policy
    policy_name = "TestPolicy"
    log.info(f"role policy: {role_policy}")

    try:
        put_role_resp = iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
        )
        log.info(f"Policy attached to role. resp: {put_role_resp}")
    except ClientError as e:
        log.error(f"put role policy failed: {e}")

    log.info(f"session policy: {session_policy}")

    # Step 3: Assume Role
    assumed_role = user2_sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName="TestSession", Policy=session_policy
    )
    credentials = assumed_role["Credentials"]
    log.info("Assumed role credentials:")
    log.info(f"Access Key: {credentials['AccessKeyId']}")
    log.info(f"Secret Key: {credentials['SecretAccessKey']}")
    log.info(f"Session Token: {credentials['SessionToken']}")

    assumed_role_user_info = {
        "access_key": credentials["AccessKeyId"],
        "secret_key": credentials["SecretAccessKey"],
        "session_token": credentials["SessionToken"],
        "user_id": assume_role_principal,
    }

    # log.info("got the credentials after assume role")
    auth_temporary_user = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
    s3 = auth_temporary_user.do_auth_using_client(**{"region_name": "us-east-1"})
    s3_client = s3

    # time.sleep(2)

    exercise_all_s3api_requests(s3_client)

    log.info(f"------------------------------------- Test Summary")
    actual_allowed_actions = sorted(PASSED_ACTIONS)
    actual_denied_actions = sorted(FAILED_ACTIONS)
    log.info(f"\nactual_allowed_actions: {actual_allowed_actions}")
    log.info(f"\nexpected_allowed_actions: {expected_allowed_actions}")
    log.info(f"\nactual_denied_actions: {actual_denied_actions}")
    log.info(f"\nexpected_denied_actions: {expected_denied_actions}")
    if expected_allowed_actions != actual_allowed_actions:
        log.info(
            f"\nthese actions are expected to be allowed but not allowed: {list(set(expected_allowed_actions) - set(actual_allowed_actions))}"
        )
        log.info(
            f"\nthese actions are not expected to be allowed but allowed: {list(set(actual_allowed_actions) - set(expected_allowed_actions))}"
        )
        raise Exception(
            f"\nactual_allowed_actions not matched with expected_allowed_actions."
        )
    if expected_denied_actions != actual_denied_actions:
        log.info(
            f"\nthese actions are expected to be denied but not denied: {list(set(expected_denied_actions) - set(actual_denied_actions))}"
        )
        log.info(
            f"\nthese actions are not expected to be denied but denied: {list(set(actual_denied_actions) - set(expected_denied_actions))}"
        )
        raise Exception(
            f"\nactual_denied_actions not matched with expected_allowed_actions."
        )

    # output_list.append([])
    # for action in BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS:
    #     result = ""
    #     if action in actual_allowed_actions:
    #         result = "Allowed"
    #     elif action in actual_denied_actions:
    #         result = "Denied"
    #     output_list[index_s3_client].append(result)
    # log.info("\n".join(output_list[index_s3_client]))

    # output_string = "action sts-user-s3-client object-owner-s3-client bucket-owner-s3-client\n"
    # actions_list = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
    # for i in range(0, len(actions_list)):
    #     result = ""
    #     output_string += f"{actions_list[i]} {output_list[0][i]} {output_list[1][i]} {output_list[2][i]}\n"
    # log.info(output_string)
    # raise Exception("stop the flow")


def exercise_all_s3api_requests(s3_client):
    global PASSED_ACTIONS, FAILED_ACTIONS
    FAILED_ACTIONS = []
    PASSED_ACTIONS = []

    # Call each method
    log.info("------------------------------------- Test create_bucket")
    create_bucket(s3_client)
    log.info("")
    log.info("------------------------------------- Test abort_multipart_upload")
    abort_multipart_upload(s3_client)
    log.info("------------------------------------- Test put_object")
    put_object(s3_client)
    log.info("------------------------------------- Test multipart_upload")
    multipart_upload(s3_client)
    log.info("------------------------------------- Test get_object")
    get_object(s3_client)
    log.info("------------------------------------- Test put_object_acl")
    put_object_acl(s3_client)
    log.info("------------------------------------- Test get_object_acl")
    get_object_acl(s3_client)
    log.info("------------------------------------- Test put_bucket_acl")
    put_bucket_acl(s3_client)
    log.info("------------------------------------- Test put_bucket_cors")
    put_bucket_cors(s3_client)
    log.info("")
    # log.info("------------------------------------- Test put_bucket_logging")
    # put_bucket_logging(s3_client)
    log.info("------------------------------------- Test put_bucket_notification")
    put_bucket_notification(s3_client)
    log.info("------------------------------------- Test put_bucket_policy")
    put_bucket_policy(s3_client)
    log.info("------------------------------------- Test put_bucket_tagging")
    put_bucket_tagging(s3_client)
    log.info("------------------------------------- Test put_bucket_versioning")
    put_bucket_versioning(s3_client)
    log.info("------------------------------------- Test put_object_version_acl")
    put_object_version_acl(s3_client)
    log.info("------------------------------------- Test put_bucket_website")
    put_bucket_website(s3_client)
    log.info("------------------------------------- Test put_lifecycle_configuration")
    put_lifecycle_configuration(s3_client)
    log.info("")
    # log.info("------------------------------------- Test restore_object")
    # restore_object(s3_client)
    log.info("------------------------------------- Test copy_object")
    copy_object(s3_client)
    log.info("------------------------------------- Test put_bucket_encryption")
    put_bucket_encryption(s3_client)
    log.info("------------------------------------- Test get_bucket_encryption")
    get_bucket_encryption(s3_client)
    log.info("------------------------------------- Test delete_bucket_encryption")
    delete_bucket_encryption(s3_client)
    log.info("------------------------------------- Test put_public_access_block")
    put_public_access_block(s3_client)
    log.info("------------------------------------- Test get_public_access_block")
    get_public_access_block(s3_client)
    log.info("------------------------------------- Test delete_public_access_block")
    delete_public_access_block(s3_client)
    log.info("------------------------------------- Test head_bucket")
    head_bucket(s3_client)
    log.info("------------------------------------- Test head_object")
    head_object(s3_client)
    log.info("------------------------------------- Test list_object_versions")
    list_object_versions(s3_client)
    log.info("------------------------------------- Test list_objects")
    list_objects(s3_client)
    log.info("------------------------------------- Test list_objects_v2")
    list_objects_v2(s3_client)
    log.info("------------------------------------- Test select_object_content")
    select_object_content(s3_client)
    log.info("------------------------------------- Test put_object_tagging")
    put_object_tagging(s3_client)
    log.info("------------------------------------- Test get_object_tagging")
    get_object_tagging(s3_client)
    log.info("------------------------------------- Test get_object_attributes")
    get_object_attributes(s3_client)
    log.info("------------------------------------- Test put_object_lock_configuration")
    put_object_lock_configuration(s3_client)
    log.info("------------------------------------- Test get_object_lock_configuration")
    get_object_lock_configuration(s3_client)
    log.info("------------------------------------- Test put_object_legal_hold")
    put_object_legal_hold(s3_client)
    log.info("------------------------------------- Test get_object_legal_hold")
    get_object_legal_hold(s3_client)
    log.info("------------------------------------- Test remove_object_legal_hold")
    remove_object_legal_hold(s3_client)
    log.info("------------------------------------- Test put_object_retention")
    put_object_retention(s3_client)
    log.info("------------------------------------- Test get_object_retention")
    get_object_retention(s3_client)
    log.info("------------------------------------- Test remove_object_retention")
    remove_object_retention(s3_client)
    log.info("------------------------------------- Test get_accelerate_configuration")
    get_accelerate_configuration(s3_client)
    log.info("------------------------------------- Test get_bucket_acl")
    get_bucket_acl(s3_client)
    log.info("------------------------------------- Test get_bucket_cors")
    get_bucket_cors(s3_client)
    log.info("------------------------------------- Test get_bucket_location")
    get_bucket_location(s3_client)
    log.info("------------------------------------- Test get_bucket_logging")
    get_bucket_logging(s3_client)
    log.info("------------------------------------- Test get_bucket_notification")
    get_bucket_notification(s3_client)
    log.info("------------------------------------- Test get_bucket_policy")
    get_bucket_policy(s3_client)
    log.info("------------------------------------- Test get_bucket_request_payment")
    get_bucket_request_payment(s3_client)
    log.info("------------------------------------- Test get_bucket_tagging")
    get_bucket_tagging(s3_client)
    log.info("------------------------------------- Test get_bucket_versioning")
    get_bucket_versioning(s3_client)
    log.info("------------------------------------- Test get_bucket_website")
    get_bucket_website(s3_client)
    log.info("------------------------------------- Test get_lifecycle_configuration")
    get_lifecycle_configuration(s3_client)
    log.info("------------------------------------- Test get_object_version_acl")
    get_object_version_acl(s3_client)
    log.info("------------------------------------- Test get_object_version")
    get_object_version(s3_client)
    # log.info("------------------------------------- Test put_replication_configuration")
    # put_replication_configuration(s3_client)
    log.info("------------------------------------- Test get_replication_configuration")
    get_replication_configuration(s3_client)
    log.info("------------------------------------- Test list_all_my_buckets")
    list_all_my_buckets(s3_client)
    log.info("------------------------------------- Test list_bucket_multipart_uploads")
    list_bucket_multipart_uploads(s3_client)
    log.info("------------------------------------- Test list_multipart_upload_parts")
    list_multipart_upload_parts(s3_client)
    log.info("------------------------------------- Test delete_bucket_website")
    delete_bucket_website(s3_client)
    log.info(
        "------------------------------------- Test delete_replication_configuration"
    )
    delete_replication_configuration(s3_client)
    log.info("------------------------------------- Test delete_object_version")
    delete_object_version(s3_client)
    log.info("------------------------------------- Test delete_object")
    delete_object(s3_client)
    log.info("------------------------------------- Test delete_objects")
    delete_objects(s3_client)
    log.info("------------------------------------- Test delete_bucket_policy")
    delete_bucket_policy(s3_client)
    log.info("------------------------------------- Test delete_bucket")
    delete_bucket(s3_client)
    log.info("")
    # log.info("------------------------------------- Test list_bucket")
    # list_bucket()
    # log.info("------------------------------------- Test list_bucket_versions")
    # list_bucket_versions()


def abort_multipart_upload(s3_client):
    try:
        response = s3_client_bucket_owner.create_multipart_upload(
            Bucket=BUCKET, Key=OBJECT_KEY
        )
        upload_id = response["UploadId"]
        s3_client.abort_multipart_upload(
            Bucket=BUCKET, Key=OBJECT_KEY, UploadId=upload_id
        )
        log.info("AbortMultipartUpload succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"AbortMultipartUpload failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def create_bucket(s3):
    try:
        log.info(f"CreateBucket {BUCKET}-copy")
        s3.create_bucket(Bucket=f"{BUCKET}-copy", ObjectLockEnabledForBucket=True)
        log.info("CreateBucket succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"CreateBucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("Creating Bucket with permanent creds for following tests")
        # s3_client_bucket_owner.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)


def delete_bucket_policy(s3):
    try:
        s3.delete_bucket_policy(Bucket=BUCKET)
        log.info("DeleteBucketPolicy succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"DeleteBucketPolicy failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_bucket(s3):
    time.sleep(2)
    try:
        s3.delete_bucket(Bucket=BUCKET)
        log.info("DeleteBucket succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"DeleteBucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_bucket_website(s3):
    try:
        s3.delete_bucket_website(Bucket=BUCKET)
        log.info("DeleteBucketWebsite succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"DeleteBucketWebsite failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_object(s3):
    try:
        s3.delete_object(Bucket=BUCKET, Key=OBJECT_KEY)
        log.info("DeleteObject succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"DeleteObject failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_object_version(s3):
    try:
        log.info(f"Deleting versions of object {OBJECT_KEY}")
        versions = s3_client_bucket_owner.list_object_versions(
            Bucket=BUCKET, Prefix=OBJECT_KEY
        )
        for version in versions.get("Versions", []):
            s3.delete_object(
                Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version["VersionId"]
            )
            log.info(f"Deleted version {version['VersionId']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"DeleteObjectVersion failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_accelerate_configuration(s3):
    try:
        response = s3.get_bucket_accelerate_configuration(Bucket=BUCKET)
        log.info(f"GetAccelerateConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetAccelerateConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_accelerate_configuration(s3):
    try:
        response = s3.get_bucket_accelerate_configuration(Bucket=BUCKET)
        log.info(f"GetAccelerateConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetAccelerateConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_acl(s3):
    try:
        response = s3.get_bucket_acl(Bucket=BUCKET)
        log.info(f"GetBucketAcl succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_cors(s3):
    try:
        response = s3.get_bucket_cors(Bucket=BUCKET)
        log.info(f"GetBucketCORS succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketCORS failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_location(s3):
    try:
        response = s3.get_bucket_location(Bucket=BUCKET)
        log.info(f"GetBucketLocation succeeded: {response['LocationConstraint']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketLocation failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_logging(s3):
    try:
        response = s3.get_bucket_logging(Bucket=BUCKET)
        log.info(f"GetBucketLogging succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketLogging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_notification(s3):
    try:
        response = s3.get_bucket_notification_configuration(Bucket=BUCKET)
        log.info(f"GetBucketNotification succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketNotification failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_policy(s3):
    try:
        response = s3.get_bucket_policy(Bucket=BUCKET)
        log.info(f"GetBucketPolicy succeeded: {response['Policy']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketPolicy failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_request_payment(s3):
    try:
        response = s3.get_bucket_request_payment(Bucket=BUCKET)
        log.info(f"GetBucketRequestPayment succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketRequestPayment failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_tagging(s3):
    try:
        response = s3.get_bucket_tagging(Bucket=BUCKET)
        log.info(f"GetBucketTagging succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketTagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_versioning(s3):
    try:
        response = s3.get_bucket_versioning(Bucket=BUCKET)
        log.info(f"GetBucketVersioning succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketVersioning failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_website(s3):
    try:
        response = s3.get_bucket_website(Bucket=BUCKET)
        log.info(f"GetBucketWebsite succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetBucketWebsite failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_lifecycle_configuration(s3):
    try:
        response = s3.get_bucket_lifecycle_configuration(Bucket=BUCKET)
        log.info(f"GetLifecycleConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetLifecycleConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_object_acl(s3):
    try:
        response = s3.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
        log.info(f"GetObjectAcl succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"GetObjectAcl from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
        # log.info(f"GetObjectAcl succeeded: {response}")
    except ClientError as e:
        log.error(f"GetObjectAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"GetObjectAcl from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
        # log.info(f"GetObjectAcl succeeded: {response}")
    # try:
    #     log.info(f"GetObjectAcl from object_owner")
    #     response = s3_client_bucket_owner_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
    #     log.info(f"GetObjectAcl succeeded: {response}")
    # except ClientError as e:
    #     log.error(f"GetObjectAcl failed from object_owner: {e}")
    # try:
    #     log.info(f"GetObjectAcl from bucket_owner")
    #     response = s3_client_bucket_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
    #     log.info(f"GetObjectAcl succeeded: {response}")
    # except ClientError as e:
    #     log.error(f"GetObjectAcl failed from bucket_owner: {e}")


def get_object(s3):
    multipart_obj_name = f"{OBJECT_KEY}_multi"
    try:
        response = s3.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        content = response["Body"].read().decode("utf-8")
        log.info(f"GetObject succeeded for {OBJECT_KEY}: {content}")
        response = s3.get_object(Bucket=BUCKET, Key=multipart_obj_name)
        content = response["Body"].read().decode("utf-8")
        log.info(f"GetObject succeeded for {multipart_obj_name}: {content}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"GetObject from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        # log.info(f"GetObject succeeded: {response}")
    except ClientError as e:
        log.error(f"GetObject failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"GetObject from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        # log.info(f"GetObject succeeded: {response}")
    # try:
    #     log.info(f"GetObject from object_owner")
    #     response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
    #     content = response['Body'].read().decode('utf-8')
    #     log.info(f"GetObject succeeded for {OBJECT_KEY}: {content}")
    #     response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=multipart_obj_name)
    #     content = response['Body'].read().decode('utf-8')
    #     log.info(f"GetObject succeeded for {multipart_obj_name}: {content}")
    # except ClientError as e:
    #     log.error(f"GetObject failed from object_owner: {e}")
    # try:
    #     log.info(f"GetObject from bucket_owner")
    #     response = s3_client_bucket_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
    #     content = response['Body'].read().decode('utf-8')
    #     log.info(f"GetObject succeeded for {OBJECT_KEY}: {content}")
    #     response = s3_client_bucket_owner.get_object(Bucket=BUCKET, Key=multipart_obj_name)
    #     content = response['Body'].read().decode('utf-8')
    #     log.info(f"GetObject succeeded for {multipart_obj_name}: {content}")
    # except ClientError as e:
    #     log.error(f"GetObject failed from bucket_owner: {e}")


def get_object_version_acl(s3):
    versions = s3_client_bucket_owner.list_object_versions(
        Bucket=BUCKET, Prefix=OBJECT_KEY
    )
    log.info(versions)
    if versions.get("Versions"):
        version_id = versions["Versions"][0]["VersionId"]
    else:
        raise Exception("versions empty")
    try:
        response = s3.get_object_acl(
            Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id
        )
        log.info(f"GetObjectVersionAcl succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except Exception as e:
        log.error(f"GetObjectVersionAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    # try:
    #     log.info(f"GetObjectVersionAcl from object_owner")
    #     response = s3_client_bucket_owner_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     log.info(f"GetObjectVersionAcl succeeded: {response}")
    # except Exception as e:
    #     log.error(f"GetObjectVersionAcl failed from object_owner: {e}")
    # try:
    #     log.info(f"GetObjectVersionAcl from bucket_owner")
    #     response = s3_client_bucket_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     log.info(f"GetObjectVersionAcl succeeded: {response}")
    # except Exception as e:
    #     log.error(f"GetObjectVersionAcl failed from bucket_owner: {e}")


def get_object_version(s3):
    versions = s3_client_bucket_owner.list_object_versions(
        Bucket=BUCKET, Prefix=OBJECT_KEY
    )
    version_id = ""
    if versions.get("Versions"):
        version_id = versions["Versions"][0]["VersionId"]
    else:
        raise Exception("versions empty")
    try:
        response = s3.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        content = response["Body"].read().decode("utf-8")
        log.info(f"GetObjectVersion succeeded for {OBJECT_KEY}: {content}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"GetObjectVersion from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        # log.info(f"GetObjectVersion succeeded: {response}")
    except Exception as e:
        log.error(f"GetObjectVersion failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"GetObjectVersion from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        # log.info(f"GetObjectVersion succeeded: {response}")
    # try:
    #     log.info(f"GetObjectVersion from object_owner")
    #     response = s3_client_bucket_owner_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     content = response['Body'].read().decode('utf-8')
    #     log.info(f"GetObjectVersion succeeded for {OBJECT_KEY}: {content}")
    # except Exception as e:
    #     log.error(f"GetObjectVersion failed from object_owner: {e}")
    # try:
    #     if versions.get('Versions'):
    #         version_id = versions['Versions'][0]['VersionId']
    #     else:
    #         raise Exception("versions empty")
    #     log.info(f"GetObjectVersion from bucket_owner")
    #     response = s3_client_bucket_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     content = response['Body'].read().decode('utf-8')
    #     log.info(f"GetObjectVersion succeeded for {OBJECT_KEY}: {content}")
    # except Exception as e:
    #     log.error(f"GetObjectVersion failed from bucket_owner: {e}")


def put_replication_configuration(s3, replication_role_arn, destination_bucket_arn):
    try:
        replication_config = {
            "Role": replication_role_arn,
            "Rules": [
                {
                    "ID": "replication-rule-1",
                    "Status": "Enabled",
                    "Priority": 1,
                    "Filter": {"Prefix": ""},
                    "Destination": {
                        "Bucket": destination_bucket_arn,
                        "StorageClass": "STANDARD",
                    },
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                }
            ],
        }

        response = s3.put_bucket_replication(
            Bucket=BUCKET, ReplicationConfiguration=replication_config
        )
        log.info(f"PutReplicationConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutReplicationConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_replication_configuration(s3):
    try:
        response = s3.get_bucket_replication(Bucket=BUCKET)
        log.info(f"GetReplicationConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"GetReplicationConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_replication_configuration(s3):
    try:
        s3.delete_bucket_replication(Bucket=BUCKET)
        log.info("DeleteReplicationConfiguration succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"DeleteReplicationConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_all_my_buckets(s3):
    try:
        response = s3.list_buckets()
        buckets = [b["Name"] for b in response["Buckets"]]
        log.info(f"ListAllMyBuckets succeeded: {buckets}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"ListAllMyBuckets failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_bucket_multipart_uploads(s3):
    try:
        response = s3.list_multipart_uploads(Bucket=BUCKET)
        log.info(f"ListBucketMultipartUploads succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"ListBucketMultipartUploads failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_bucket(s3):
    try:
        response = s3.list_objects_v2(Bucket=BUCKET)
        log.info(f"ListBucket succeeded: {response.get('Contents', [])}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"ListBucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_bucket_versions(s3):
    try:
        response = s3.list_object_versions(Bucket=BUCKET)
        log.info(f"ListBucketVersions succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"ListBucketVersions failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_multipart_upload_parts(s3_client):
    try:
        multipart_obj_name = f"{OBJECT_KEY}_multi2"
        upload = s3_client_bucket_owner.create_multipart_upload(
            Bucket=BUCKET, Key=multipart_obj_name
        )
        upload_id = upload["UploadId"]
        # Upload one part to generate a part listing
        s3_client_bucket_owner.upload_part(
            Bucket=BUCKET,
            Key=multipart_obj_name,
            PartNumber=1,
            UploadId=upload_id,
            Body="Part 1",
        )
        response = s3_client.list_parts(
            Bucket=BUCKET, Key=multipart_obj_name, UploadId=upload_id
        )
        log.info(f"ListMultipartUploadParts succeeded: {response}")
        # s3.abort_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name, UploadId=upload_id)
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"ListMultipartUploadParts failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_bucket_acl(s3):
    try:
        s3.put_bucket_acl(Bucket=BUCKET, ACL="private")
        log.info("PutBucketAcl succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_bucket_cors(s3):
    cors_config = {
        "CORSRules": [
            {
                "AllowedHeaders": ["*"],
                "AllowedMethods": ["GET", "PUT"],
                "AllowedOrigins": ["*"],
                "ExposeHeaders": ["ETag"],
                "MaxAgeSeconds": 3000,
            }
        ]
    }
    try:
        s3.put_bucket_cors(Bucket=BUCKET, CORSConfiguration=cors_config)
        log.info("PutBucketCORS succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketCORS failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutBucketCORS with bucket_owner")
        s3_client_bucket_owner.put_bucket_cors(
            Bucket=BUCKET, CORSConfiguration=cors_config
        )


def put_bucket_logging(s3):
    try:
        s3.put_bucket_logging(
            Bucket=BUCKET,
            BucketLoggingStatus={
                "LoggingEnabled": {"TargetBucket": BUCKET, "TargetPrefix": "logs/"}
            },
        )
        log.info("PutBucketLogging succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketLogging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_bucket_notification(s3):
    try:
        s3.put_bucket_notification_configuration(
            Bucket=BUCKET, NotificationConfiguration={"TopicConfigurations": []}
        )
        log.info("PutBucketNotification succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketNotification failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutBucketNotification with bucket_owner")
        s3_client_bucket_owner.put_bucket_notification_configuration(
            Bucket=BUCKET, NotificationConfiguration={"TopicConfigurations": []}
        )


def put_bucket_policy(s3):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{BUCKET}/*",
            }
        ],
    }
    try:
        s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
        log.info("PutBucketPolicy succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketPolicy failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutBucketPolicy with bucket_owner")
        s3_client_bucket_owner.put_bucket_policy(
            Bucket=BUCKET, Policy=json.dumps(policy)
        )


def put_bucket_tagging(s3):
    try:
        s3.put_bucket_tagging(
            Bucket=BUCKET, Tagging={"TagSet": [{"Key": "Environment", "Value": "Test"}]}
        )
        log.info("PutBucketTagging succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketTagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutBucketTagging with bucket_owner")
        s3_client_bucket_owner.put_bucket_tagging(
            Bucket=BUCKET, Tagging={"TagSet": [{"Key": "Environment", "Value": "Test"}]}
        )


def put_bucket_versioning(s3):
    try:
        s3.put_bucket_versioning(
            Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"}
        )
        log.info("PutBucketVersioning succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketVersioning failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutBucketVersioning with bucket_owner")
        s3_client_bucket_owner.put_bucket_versioning(
            Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"}
        )


def put_bucket_website(s3):
    try:
        s3.put_bucket_website(
            Bucket=BUCKET,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index_resource.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )
        log.info("PutBucketWebsite succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutBucketWebsite failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutBucketWebsite with bucket_owner")
        s3_client_bucket_owner.put_bucket_website(
            Bucket=BUCKET,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index_resource.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )


def put_lifecycle_configuration(s3):
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=BUCKET,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "ExpireOldObjects",
                        "Prefix": "",
                        "Status": "Enabled",
                        "Expiration": {"Days": 30},
                    }
                ]
            },
        )
        log.info("PutLifecycleConfiguration succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutLifecycleConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutLifecycleConfiguration with bucket_owner")
        s3_client_bucket_owner.put_bucket_lifecycle_configuration(
            Bucket=BUCKET,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "ExpireOldObjects",
                        "Prefix": "",
                        "Status": "Enabled",
                        "Expiration": {"Days": 30},
                    }
                ]
            },
        )


def put_object_acl(s3):
    try:
        s3.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL="private")
        log.info("PutObjectAcl succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("PutObjectAcl from object_owner")
        # s3_client_bucket_owner_object_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    except ClientError as e:
        log.error(f"PutObjectAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("PutObjectAcl from object_owner")
        # s3_client_bucket_owner_object_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    # try:
    #     log.info("PutObjectAcl from object_owner")
    #     s3_client_bucket_owner_object_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    #     log.info("PutObjectAcl succeeded")
    # except ClientError as e:
    #     log.error(f"PutObjectAcl failed from object_owner: {e}")
    # try:
    #     log.info("PutObjectAcl from bucket_owner")
    #     s3_client_bucket_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    #     log.info("PutObjectAcl succeeded")
    # except ClientError as e:
    #     log.error(f"PutObjectAcl failed from bucket_owner: {e}")


def put_object(s3):
    try:
        log.info(f"uploading object {OBJECT_KEY} into bucket {BUCKET}")
        s3.put_object(
            Bucket=BUCKET, Key=OBJECT_KEY, Body=open("/home/cephuser/obj9KB", "rb")
        )
        # s3_client_bucket_owner.put_object(Bucket=BUCKET, Key=OBJECT_KEY, Body='Sample content')
        log.info("PutObject succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutObject failed: {e}")
        log.info(f"uploading object with bucket owner")
        s3_client_bucket_owner.put_object(
            Bucket=BUCKET, Key=OBJECT_KEY, Body="Sample content"
        )
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_object_version_acl(s3):
    versions = s3_client_bucket_owner.list_object_versions(
        Bucket=BUCKET, Prefix=OBJECT_KEY
    )
    try:
        for version in versions.get("Versions", []):
            log.info(
                f"PutObjectVersionAcl for {version['Key']} for version {version['VersionId']}"
            )
            s3.put_object_acl(
                Bucket=BUCKET,
                Key=version["Key"],
                VersionId=version["VersionId"],
                ACL="private",
            )
        log.info(f"PutObjectVersionAcl succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutObjectVersionAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    # try:
    #     log.info(f"PutObjectVersionAcl from object_owner")
    #     for version in versions.get('Versions', []):
    #         log.info(f"PutObjectVersionAcl for {version['Key']} for version {version['VersionId']}")
    #         s3_client_bucket_owner_object_owner.put_object_acl(Bucket=BUCKET, Key=version['Key'], VersionId=version['VersionId'], ACL='private')
    #     log.info(f"PutObjectVersionAcl succeeded")
    # except ClientError as e:
    #     log.error(f"PutObjectVersionAcl failed from object_owner: {e}")
    # try:
    #     log.info(f"PutObjectVersionAcl from bucket_owner")
    #     for version in versions.get('Versions', []):
    #         log.info(f"PutObjectVersionAcl for {version['Key']} for version {version['VersionId']}")
    #         s3_client_bucket_owner.put_object_acl(Bucket=BUCKET, Key=version['Key'], VersionId=version['VersionId'], ACL='private')
    #     log.info(f"PutObjectVersionAcl succeeded")
    # except ClientError as e:
    #     log.error(f"PutObjectVersionAcl failed from bucket_owner: {e}")


def restore_object(s3):
    try:
        s3.restore_object(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Standard"}},
        )
        log.info("RestoreObject succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"RestoreObject failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def copy_object(s3):
    try:
        s3.copy_object(
            Bucket=BUCKET,
            CopySource={"Bucket": BUCKET, "Key": OBJECT_KEY},
            Key=f"{OBJECT_KEY}_copy",
        )
        log.info("copy_object succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"copy_object failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def multipart_upload(s3):
    multipart_obj_name = f"{OBJECT_KEY}_multi"
    try:
        response = s3.create_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name)
        upload_id = response["UploadId"]
        part1 = s3.upload_part(
            Bucket=BUCKET,
            Key=multipart_obj_name,
            PartNumber=1,
            UploadId=upload_id,
            Body=open("/home/cephuser/obj12MB.parts/aa", mode="rb"),
        )
        part2 = s3.upload_part(
            Bucket=BUCKET,
            Key=multipart_obj_name,
            PartNumber=2,
            UploadId=upload_id,
            Body=open("/home/cephuser/obj12MB.parts/ab", mode="rb"),
        )
        s3.complete_multipart_upload(
            Bucket=BUCKET,
            Key=multipart_obj_name,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"ETag": part1["ETag"], "PartNumber": 1},
                    {"ETag": part2["ETag"], "PartNumber": 2},
                ]
            },
        )
        log.info("multipart_upload succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"multipart_upload failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.error(f"multipart_upload with bucket owner")
        response = s3_client_bucket_owner.create_multipart_upload(
            Bucket=BUCKET, Key=multipart_obj_name
        )
        upload_id = response["UploadId"]
        part = s3_client_bucket_owner.upload_part(
            Bucket=BUCKET,
            Key=multipart_obj_name,
            PartNumber=1,
            UploadId=upload_id,
            Body="part1",
        )
        s3_client_bucket_owner.complete_multipart_upload(
            Bucket=BUCKET,
            Key=multipart_obj_name,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"ETag": part["ETag"], "PartNumber": 1}]},
        )


# def delete_objects(s3):
#     try:
#         s3.delete_objects(Bucket=BUCKET, Delete={'Objects': [{'Key': OBJECT_KEY},{'Key': f"{OBJECT_KEY}_copy"}, {'Key': f"{OBJECT_KEY}_multi"}]})
#         log.info("delete_objects succeeded")
#     except ClientError as e:
#         log.error(f"delete_objects failed: {e}")
#         FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_objects(s3):
    paginator = s3_client_bucket_owner.get_paginator("list_object_versions")
    delete_list = []
    time.sleep(3)

    for page in paginator.paginate(Bucket=BUCKET):
        versions = page.get("Versions", []) + page.get("DeleteMarkers", [])
        for version in versions:
            delete_list.append(
                {"Key": version["Key"], "VersionId": version["VersionId"]}
            )
    log.info(f"delete_list: {delete_list}")
    # raise Exception(f"\nstop the flow.")
    try:
        if delete_list:
            response = s3.delete_objects(
                Bucket=BUCKET, Delete={"Objects": delete_list, "Quiet": False}
            )
            if "Errors" in response and response["Errors"]:
                error_messages = [
                    f"Key: {error['Key']}, Code: {error['Code']}, Message: {error['Message']}"
                    for error in response["Errors"]
                ]
                raise Exception(
                    f"One or more object deletions failed: {'; '.join(error_messages)}"
                )
            log.info(
                f"Deleted {len(delete_list)} object versions from bucket '{BUCKET}'. response:{response}"
            )
        else:
            log.info("No object versions found to delete.")
        log.info("delete_objects succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except Exception as e:
        log.error(f"delete_objects failed: {e}")
        log.error(f"deleting objects with bucket owner")
        if delete_list:
            response = s3_client_bucket_owner.delete_objects(
                Bucket=BUCKET, Delete={"Objects": delete_list, "Quiet": False}
            )
            if "Errors" in response and response["Errors"]:
                error_messages = [
                    f"Key: {error['Key']}, Code: {error['Code']}, Message: {error['Message']}"
                    for error in response["Errors"]
                ]
                raise Exception(
                    f"One or more object deletions failed: {'; '.join(error_messages)}"
                )
            log.info(
                f"Deleted {len(delete_list)} object versions from bucket '{BUCKET}'. response:{response}"
            )
        else:
            log.info("No object versions found to delete.")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_bucket_encryption(s3):
    try:
        s3.put_bucket_encryption(
            Bucket=BUCKET,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        log.info("put_bucket_encryption succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"put_bucket_encryption failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("put_bucket_encryption with bucket_owner")
        s3_client_bucket_owner.put_bucket_encryption(
            Bucket=BUCKET,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )


def get_bucket_encryption(s3):
    try:
        response = s3.get_bucket_encryption(Bucket=BUCKET)
        log.info(f"get_bucket_encryption succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"get_bucket_encryption failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_bucket_encryption(s3):
    try:
        s3.delete_bucket_encryption(Bucket=BUCKET)
        log.info("delete_bucket_encryption succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"delete_bucket_encryption failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("delete_bucket_encryption with bucket_owner")
        s3_client_bucket_owner.delete_bucket_encryption(Bucket=BUCKET)


def put_public_access_block(s3):
    try:
        s3.put_public_access_block(
            Bucket=BUCKET,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        log.info("put_public_access_block succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"put_public_access_block failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("put_public_access_block with bucket_owner")
        s3_client_bucket_owner.put_public_access_block(
            Bucket=BUCKET,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )


def get_public_access_block(s3):
    try:
        response = s3.get_public_access_block(Bucket=BUCKET)
        log.info(f"get_public_access_block succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"get_public_access_block failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_public_access_block(s3):
    try:
        s3.delete_public_access_block(Bucket=BUCKET)
        log.info("delete_public_access_block succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"delete_public_access_block failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("delete_public_access_block with bucket_owner")
        s3_client_bucket_owner.delete_public_access_block(Bucket=BUCKET)


def head_bucket(s3):
    try:
        s3.head_bucket(Bucket=BUCKET)
        log.info("head_bucket succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"head_bucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def head_object(s3):
    try:
        s3.head_object(Bucket=BUCKET, Key=OBJECT_KEY)
        log.info("head_object succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"head_object failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_object_versions(s3):
    try:
        response = s3.list_object_versions(Bucket=BUCKET)
        log.info(f"list_object_versions succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"list_object_versions failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_objects(s3):
    try:
        response = s3.list_objects(Bucket=BUCKET)
        log.info(f"list_objects succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"list_objects failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def list_objects_v2(s3):
    try:
        response = s3.list_objects_v2(Bucket=BUCKET)
        log.info(f"list_objects_v2 succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"list_objects_v2 failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def select_object_content(s3):
    try:
        response = s3.select_object_content(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            ExpressionType="SQL",
            Expression="SELECT * FROM S3Object",
            InputSerialization={"CSV": {}, "CompressionType": "NONE"},
            OutputSerialization={"CSV": {}},
        )
        for event in response["Payload"]:
            if "Records" in event:
                log.info(
                    f"select_object_content succeeded: {event['Records']['Payload']}"
                )
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"select_object_content failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_object_tagging(s3_client):
    # Define the tags you want to apply
    tags = [
        {"Key": "Environment", "Value": "Development"},
        {"Key": "Project", "Value": "MyApplication"},
    ]

    try:
        response = s3_client.put_object_tagging(
            Bucket=BUCKET, Key=OBJECT_KEY, Tagging={"TagSet": tags}
        )
        log.info(f"put_object_tagging succeeded, response: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"put_object_tagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    # try:
    #     log.info(f"put_object_tagging from object_owner")
    #     response = s3_client_bucket_owner_object_owner.put_object_tagging(
    #         Bucket=BUCKET,
    #         Key=OBJECT_KEY,
    #         Tagging={
    #             'TagSet': tags
    #         }
    #     )
    #     log.info(f"put_object_tagging succeeded, response: {response}")
    # except ClientError as e:
    #     log.error(f"put_object_tagging failed from object_owner: {e}")
    # try:
    #     log.info(f"put_object_tagging from bucket_owner")
    #     response = s3_client_bucket_owner.put_object_tagging(
    #         Bucket=BUCKET,
    #         Key=OBJECT_KEY,
    #         Tagging={
    #             'TagSet': tags
    #         }
    #     )
    #     log.info(f"put_object_tagging succeeded, response: {response}")
    # except ClientError as e:
    #     log.error(f"put_object_tagging failed from bucket_owner: {e}")


def get_object_tagging(s3):
    try:
        response = s3.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
        log.info(f"get_object_tagging succeeded: {response['TagSet']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"get_object_tagging from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
        # log.info(f"get_object_tagging succeeded: {response}")
    except ClientError as e:
        log.error(f"get_object_tagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info(f"get_object_tagging from object_owner")
        # response = s3_client_bucket_owner_object_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
        # log.info(f"get_object_tagging succeeded: {response}")
    # try:
    #     log.info(f"get_object_tagging from object_owner")
    #     response = s3_client_bucket_owner_object_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
    #     log.info(f"get_object_tagging succeeded: {response['TagSet']}")
    # except ClientError as e:
    #     log.error(f"get_object_tagging failed from object_owner: {e}")
    # try:
    #     log.info(f"get_object_tagging from bucket_owner")
    #     response = s3_client_bucket_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
    #     log.info(f"get_object_tagging succeeded: {response['TagSet']}")
    # except ClientError as e:
    #     log.error(f"get_object_tagging failed from bucket_owner: {e}")


def get_object_attributes(s3):
    try:
        response = s3.get_object_attributes(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            ObjectAttributes=["ETag", "ObjectSize", "Size", "ObjectParts", "Checksum"],
        )
        log.info(f"get_object_attributes succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"get_object_attributes failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_object_lock_configuration(s3):
    try:
        response = s3.put_object_lock_configuration(
            Bucket=BUCKET,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 30}},
            },
        )
        log.info("PutObjectLockConfiguration succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"PutObjectLockConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        log.info("PutObjectLockConfiguration with bucket_owner")
        s3_client_bucket_owner.put_object_lock_configuration(
            Bucket=BUCKET,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 30}},
            },
        )


def get_object_lock_configuration(s3):
    try:
        response = s3.get_object_lock_configuration(Bucket=BUCKET)
        log.info(f"get_object_lock_configuration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"get_object_lock_configuration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_object_legal_hold(s3, hold_status="ON"):
    try:
        response = s3.put_object_legal_hold(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            LegalHold={"Status": hold_status},  # 'ON' or 'OFF'
        )
        log.info(f"put_object_legal_hold succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.info(f"put_object_legal_hold failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("put_object_legal_hold with bucket_owner")
        # s3_client_bucket_owner.put_object_legal_hold(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     LegalHold={
        #         'Status': hold_status  # 'ON' or 'OFF'
        #     }
        # )


def get_object_legal_hold(s3):
    try:
        response = s3.get_object_legal_hold(Bucket=BUCKET, Key=OBJECT_KEY)
        log.info(f"get_object_legal_hold succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"get_object_legal_hold failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def remove_object_legal_hold(s3):
    try:
        response = s3.put_object_legal_hold(
            Bucket=BUCKET, Key=OBJECT_KEY, LegalHold={"Status": "OFF"}
        )
        log.info(
            f"remove_object_legal_hold with put_object_legal_hold succeeded: {response}"
        )
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.info(f"remove_object_legal_hold with put_object_legal_hold failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("remove_object_legal_hold with bucket_owner")
        # s3_client_bucket_owner.put_object_legal_hold(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     LegalHold={
        #         'Status': 'OFF'
        #     }
        # )


def put_object_retention(s3, retention_mode="GOVERNANCE", days=30):
    retain_until = datetime.utcnow() + timedelta(days=days)
    try:
        response = s3.put_object_retention(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            Retention={
                "Mode": retention_mode,  # 'GOVERNANCE' or 'COMPLIANCE'
                "RetainUntilDate": retain_until,
            },
            BypassGovernanceRetention=False,  # Set to True if you have permission to bypass
        )
        log.info(f"put_object_retention succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.info(f"put_object_retention failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("put_object_retention with bucket_owner")
        # s3_client_bucket_owner.put_object_retention(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     Retention={
        #         'Mode': retention_mode,  # 'GOVERNANCE' or 'COMPLIANCE'
        #         'RetainUntilDate': retain_until
        #     },
        #     BypassGovernanceRetention=False  # Set to True if you have permission to bypass
        # )


def get_object_retention(s3):
    try:
        response = s3.get_object_retention(Bucket=BUCKET, Key=OBJECT_KEY)
        log.info(f"get_object_retention succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.error(f"get_object_retention failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def remove_object_retention(s3):
    try:
        response = s3.put_object_retention(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            Retention={
                "Mode": "GOVERNANCE",
                "RetainUntilDate": datetime.utcnow() + timedelta(seconds=3),
            },
            BypassGovernanceRetention=True,
        )
        log.info(
            f"remove_object_retention with put_object_retention succeeded: {response}"
        )
        time.sleep(3)
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        log.info(f"Error removing retention: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # log.info("remove_object_retention with bucket_owner")
        # s3_client_bucket_owner.put_object_retention(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     Retention={
        #         'Mode': 'GOVERNANCE',
        #         'RetainUntilDate': datetime.utcnow() + timedelta(seconds=3)
        #     },
        #     BypassGovernanceRetention=True
        # )
