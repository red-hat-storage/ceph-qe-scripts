import json
import logging
import random
import time

import v2.lib.resource_op as s3lib
from v2.lib.exceptions import TestExecError
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bucket_notification as notification
from v2.tests.s3_swift.reusables import server_side_encryption_s3 as sse_s3
from v2.utils.utils import HttpResponseParser

log = logging.getLogger()
topic_arn = None


# s3 actions verification


def classify_response(response):
    if response:
        resp = HttpResponseParser(response)
        if resp.status_code == 200 or resp.status_code == 204:
            return True
        else:
            return False
    else:
        return False


def AbortMultipartUpload(**kw):
    bucket_owner_rgw_client = kw.get("bucket_owner_rgw_client")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    object_name = f"{object_name}_verify_abort_multipart"
    out = CreateMultipartUpload(
        rgw_client=bucket_owner_rgw_client,
        bucket_name=bucket_name,
        object_name=object_name,
    )
    if classify_response(out) is False:
        raise TestExecError("Create Multipart upload failed with bucket owner client")
    upload_id = out["UploadId"]

    log.info("sleeping for 5 seconds")
    time.sleep(5)

    log.info("Aborting multipart upload")
    abort_multipart_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "abort_multipart_upload",
            "kwargs": dict(Bucket=bucket_name, Key=object_name, UploadId=upload_id),
        }
    )
    log.info(f"abort_multipart_status: {abort_multipart_status}")
    return abort_multipart_status


def CreateMultipartUpload(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")

    log.info("Creating multipart upload")
    response = rgw_client.create_multipart_upload(
        Bucket=bucket_name,
        Key=object_name,
    )
    log.info(f"response: {response}")
    return response


def DeleteBucketPolicy(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"deleting bucket policy for bucket: {bucket_name}")
    delete_policy_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "delete_bucket_policy",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"delete_policy_status: {delete_policy_status}")
    return delete_policy_status


def CreateBucket(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"creating bucket: {bucket_name}")
    create_bucket_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "create_bucket",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"create_bucket_status: {create_bucket_status}")
    return create_bucket_status


def DeleteBucket(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"deleting bucket: {bucket_name}")
    delete_bucket_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "delete_bucket",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"delete_bucket_status: {delete_bucket_status}")
    return delete_bucket_status


def DeleteObject(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_owner_rgw_client = kw.get("bucket_owner_rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    effect = kw.get("effect")
    log.info(f"s3 object name to delete: {object_name}")
    object_delete_response = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "delete_object",
            "kwargs": dict(Bucket=bucket_name, Key=object_name),
        }
    )
    log.info(f"object_delete_response: {object_delete_response}")
    object_delete_status = classify_response(object_delete_response)

    list_objects_response = ListBucket(
        rgw_client=bucket_owner_rgw_client, bucket_name=bucket_name
    )
    if classify_response(list_objects_response) is False:
        raise TestExecError("list objects failed with bucket owner client")
    objects_dict = {"Objects": []}
    objects_count = 0
    for key in list_objects_response["Contents"]:
        key_dict = {"Key": key["Key"]}
        objects_dict["Objects"].append(key_dict)
        objects_count = objects_count + 1

    log.info(f"s3 objects to delete: {objects_dict}")
    objects_delete_response = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "delete_objects",
            "kwargs": dict(Bucket=bucket_name, Delete=objects_dict),
        }
    )
    log.info(f"objects_delete_response: {objects_delete_response}")
    objects_delete_status = classify_response(objects_delete_response)
    if effect == "Allow":
        if objects_delete_response:
            objects_deleted_count = len(objects_delete_response["Deleted"])
            log.error(f"expected number of objects deleted: {objects_count}")
            log.error(f"actual number of objects deleted: {objects_deleted_count}")
            objects_delete_status = (
                False if objects_deleted_count != objects_count else True
            )
        return object_delete_status and objects_delete_status
    else:
        if objects_delete_response:
            deletion_error_count = len(objects_delete_response["Errors"])
            log.error(f"expected number of object deletion errors: {objects_count}")
            log.error(
                f"actual number of object deletion errors: {deletion_error_count}"
            )
            objects_delete_status = (
                True if deletion_error_count != objects_count else False
            )
        return object_delete_status or objects_delete_status


def GetBucketPolicy(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"getting bucket policy for bucket: {bucket_name}")
    get_policy_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "get_bucket_policy",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"get_policy_status: {get_policy_status}")
    return get_policy_status


def GetBucketVersioning(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"getting bucket versioning status for bucket: {bucket_name}")
    get_versioning_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "get_bucket_versioning",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"get_versioning_status: {get_versioning_status}")
    return get_versioning_status


def GetObject(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    log.info(f"s3 object name to download: {object_name}")
    object_get_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "get_object",
            "kwargs": dict(Bucket=bucket_name, Key=object_name),
        }
    )
    log.info(f"object_get_status: {object_get_status}")
    return object_get_status


def ListBucket(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    prefix = kw.get("prefix")
    max_keys = kw.get("max-keys")
    kwargs = {"Bucket": bucket_name}
    if prefix:
        kwargs["Prefix"] = prefix
    if max_keys:
        kwargs["MaxKeys"] = max_keys
    objects = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "list_objects",
            "kwargs": kwargs,
        }
    )
    log.info(f"list objects response: {objects}")
    return objects


def PutBucketPolicy(**kw):
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"put bucket policy for bucket: {bucket_name}")
    policy = json.dumps(
        kw.get("policy_document", config.test_ops.get("policy_document", {}))
    )
    policy_put_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "put_bucket_policy",
            "kwargs": dict(Bucket=bucket_name, Policy=policy),
        }
    )
    log.info(f"policy_put_status: {policy_put_status}")
    return policy_put_status


def PutBucketVersioning(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"put bucket versioning for bucket: {bucket_name}")
    versioning_configuration = {"MFADelete": "Disabled", "Status": "Enabled"}
    put_versioning_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "put_bucket_versioning",
            "kwargs": dict(
                Bucket=bucket_name, VersioningConfiguration=versioning_configuration
            ),
        }
    )
    log.info(f"put_versioning_status: {put_versioning_status}")
    return put_versioning_status


def PutObject(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    log.info(f"s3 object name to upload: {object_name}")
    object_put_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "put_object",
            "kwargs": dict(
                Bucket=bucket_name,
                Key=object_name,
                Body="Test bucket policy action s3:PutObject",
            ),
        }
    )
    log.info(f"object_put_status: {object_put_status}")
    return object_put_status


def CreateTopic(**kw):
    global topic_arn
    config = kw.get("config")
    sns_client = kw.get("sns_client")
    topic_name = kw.get("topic_name")
    log.info(f"creating topic with name: {topic_name}")
    try:
        topic_arn_resp = notification.create_topic(
            sns_client,
            config.test_ops.get("endpoint", "kafka"),
            config.test_ops.get("ack_type", "broker"),
            topic_name,
        )
        topic_arn = topic_arn_resp
        log.info("sleeping for 5 seconds")
        time.sleep(5)
    except Exception as e:
        log.error(f"create topic failed with error {e}")
        return False
    return True


def DeleteTopic(**kw):
    global topic_arn
    sns_client = kw.get("sns_client")
    log.info(f"deleting topic with arn: {topic_arn}")
    delete_topic_resp = s3lib.resource_op(
        {
            "obj": sns_client,
            "resource": "delete_topic",
            "kwargs": dict(TopicArn=topic_arn),
        }
    )
    log.info(f"delete_topic_resp: {delete_topic_resp}")
    return delete_topic_resp


def PutBucketNotification(**kw):
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    sns_client = kw.get("sns_client")
    bucket_name = kw.get("bucket_name")
    topic_name = kw.get("topic_name")
    notification_name = kw.get("notification_name")
    events = kw.get("events")

    # we need to create topic with bucket owner sts client here
    # but for bucket policy tests with tenanted user, it fails because of cross tenanted topic access is not supported
    # refer bz: https://bugzilla.redhat.com/show_bug.cgi?id=2238814
    log.info(f"creating topic with name: {topic_name}")
    topic_arn = notification.create_topic(
        sns_client,
        config.test_ops.get("endpoint", "kafka"),
        config.test_ops.get("ack_type", "broker"),
        topic_name,
    )
    log.info("sleeping for 5 seconds")
    time.sleep(5)

    try:
        notification.put_bucket_notification(
            rgw_client,
            bucket_name,
            notification_name,
            topic_arn,
            events,
            config,
        )
    except Exception as e:
        log.error(f"put bucket notification failed with error {e}")
        return False
    return True


def GetBucketNotification(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    try:
        notification.get_bucket_notification(rgw_client, bucket_name)
    except Exception as e:
        log.error(f"get bucket notification failed with error {e}")
        return False
    return True


def PutBucketEncryption(**kw):
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    try:
        sse_s3.put_bucket_encryption(
            rgw_client,
            bucket_name,
            config.encryption_keys,
            config.test_ops.get("encrypt_decrypt_key", "testKey01"),
        )
    except Exception as e:
        log.error(f"put bucket encryption failed with error {e}")
        return False
    return True


def GetBucketEncryption(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    get_bucket_encryption_result = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "get_bucket_encryption",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"get_bucket_encryption_result: {get_bucket_encryption_result}")
    return get_bucket_encryption_result


def PutLifecycleConfiguration(**kw):
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    put_bkt_lc_config_result = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "put_bucket_lifecycle_configuration",
            "kwargs": dict(
                Bucket=bucket_name,
                LifecycleConfiguration={"Rules": config.lifecycle_conf},
            ),
        }
    )
    log.info(f"put_bkt_lc_config_result: {put_bkt_lc_config_result}")
    return put_bkt_lc_config_result


def GetLifecycleConfiguration(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    get_bkt_lc_config_result = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "get_bucket_lifecycle_configuration",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"get_bkt_lc_config_result: {get_bkt_lc_config_result}")
    return get_bkt_lc_config_result


def PutBucketWebsite(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    try:
        reusable.put_bucket_website(rgw_client, bucket_name)
        return True
    except Exception as e:
        log.error(f"put bucket website failed with error {e}")
        return False


def GetBucketWebsite(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    try:
        reusable.get_bucket_website(rgw_client, bucket_name)
        return True
    except Exception as e:
        log.error(f"get bucket website failed with error {e}")
        return False


def PutBucketTagging(**kw):
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    put_bkt_tagging_result = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "put_bucket_tagging",
            "kwargs": dict(
                Bucket=bucket_name,
                Tagging={"TagSet": config.test_ops.get("bucket_tags")},
            ),
        }
    )
    log.info(f"put_bkt_tagging_result: {put_bkt_tagging_result}")
    return put_bkt_tagging_result


def GetBucketTagging(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    get_bkt_tagging_result = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "get_bucket_tagging",
            "kwargs": dict(Bucket=bucket_name),
        }
    )
    log.info(f"get_bkt_tagging_result: {get_bkt_tagging_result}")
    return get_bkt_tagging_result


# fetch condition key value pairs
def get_condition_keys(condition_dict):
    condition_keys = {}
    for condition, s3_condition_keys in condition_dict.items():
        for s3_condition_key, val in s3_condition_keys.items():
            c_key = s3_condition_key.split(":")[-1]
            if condition in [
                "StringEquals",
                "NumericEquals",
                "NumericLessThanEquals",
                "NumericGreaterThanEquals",
            ]:
                condition_keys[c_key] = val
            elif condition == "StringNotEquals":
                condition_keys[c_key] = f"modified-{val}"
            elif condition in ["NumericNotEquals", "NumericLessThan"]:
                condition_keys[c_key] = val - 1
            elif condition in ["NumericGreaterThan"]:
                condition_keys[c_key] = val + 1
    return condition_keys


# bucket policy verification
def verify_policy(**kw):
    log.info("Verifying all statements in Bucket Policy")
    config = kw.get("config")
    policy_doc = kw.get("policy_document", config.test_ops.get("policy_document", {}))
    bucket_owner_rgw_client = kw.get("bucket_owner_rgw_client")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    rgw_s3_resource = kw.get("rgw_s3_resource")
    sns_client = kw.get("sns_client")
    random_suffix = random.randint(1, 10000)
    topic_name = kw.get("topic_name", f"rgw_topic_{random_suffix}")
    notification_name = kw.get("topic_name", f"rgw_notif_{random_suffix}")
    events = kw.get("events", ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"])

    conflicting_statements = config.test_ops.get("conflicting_statements", False)
    log.info(f"Conflicting Statements: {conflicting_statements}")
    statements = policy_doc.get("Statement", [])
    for statement in statements:
        effect = statement.get("Effect", "Allow")
        actions = statement.get("Action", [])
        condition_block = statement.get("Condition", {})
        condition_keys = get_condition_keys(condition_block)
        if type(actions) is str:
            actions = [actions]
        for action in actions:
            log.info(f"Action is {action}. Effect is {effect}")
            method_name = action.split(":")[1]
            method = globals()[method_name]

            out = method(
                bucket_owner_rgw_client=bucket_owner_rgw_client,
                rgw_client=rgw_client,
                bucket_name=bucket_name,
                object_name=object_name,
                rgw_s3_resource=rgw_s3_resource,
                sns_client=sns_client,
                topic_name=topic_name,
                notification_name=notification_name,
                events=events,
                config=config,
                policy_document=policy_doc,
                effect=effect,
                **condition_keys,
            )
            if out is False:
                if effect == "Deny":
                    log.info(
                        f"{action} is denied as expected because of deny statement"
                    )
                elif conflicting_statements:
                    log.info(
                        f"{action} is denied as expected because of conflict between allow and deny"
                    )
                else:
                    raise TestExecError(
                        f"{action} is denied after setting bucket policy"
                    )
            elif out is True:
                if effect == "Allow":
                    log.info(
                        f"{action} is allowed as expected because of allow statement"
                    )
                elif conflicting_statements:
                    raise TestExecError(
                        f"{effect} {action} is allowed with conflicting statements in policy,"
                        + "ideally it should deny object get from other tenanted user"
                    )
                elif effect == "Deny":
                    raise TestExecError(
                        f"{action} is allowed even if effect is deny in policy"
                    )
            elif out is not None:
                response = HttpResponseParser(out)
                if response.status_code == 200 or response.status_code == 204:
                    if effect == "Allow":
                        log.info(
                            f"{action} is allowed as expected because of allow statement"
                        )
                    elif conflicting_statements:
                        raise TestExecError(
                            f"{effect} {action} is allowed with conflicting statements in policy,"
                            + "ideally it should deny object get from other tenanted user"
                        )
                    else:
                        raise TestExecError(f"Verification of {effect} {action} failed")
                else:
                    if effect == "Deny":
                        log.info(
                            f"{action} is denied as expected because of deny statement"
                        )
                    elif conflicting_statements:
                        log.info(
                            f"{action} is denied as expected because of conflict between allow and deny"
                        )
                    else:
                        raise TestExecError(
                            f"{action} is denied after setting bucket policy. status code is {response.status_code}"
                        )
            log.info(f"{effect} {action} verified successfully")
            log.info("sleeping for 3 seconds before verifying next action")
            time.sleep(3)
