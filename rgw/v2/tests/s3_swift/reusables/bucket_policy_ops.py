import json
import logging

import v2.lib.resource_op as s3lib
from v2.lib.exceptions import TestExecError
from v2.utils.utils import HttpResponseParser

log = logging.getLogger()


def AbortMultipartUpload(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    object_name = f"{object_name}_verify_abort_multipart"
    out = CreateMultipartUpload(
        rgw_client=rgw_client,
        bucket_name=bucket_name,
        object_name=object_name,
    )
    if out:
        response = HttpResponseParser(out)
        if response.status_code != 200 and response.status_code != 204:
            raise TestExecError("Create Multipart upload failed")
    else:
        raise TestExecError("Create Multipart upload failed")
    upload_id = out["UploadId"]

    log.info("Aborting multipart upload")
    abort_multipart_status = rgw_client.abort_multipart_upload(
        Bucket=bucket_name,
        Key=object_name,
        UploadId=upload_id,
    )
    log.info(abort_multipart_status)
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
    log.info(response)
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
    log.info(delete_policy_status)
    return delete_policy_status


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
    log.info(delete_bucket_status)
    return delete_bucket_status


def DeleteObject(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    log.info(f"s3 object name to delete: {object_name}")
    object_get_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "delete_object",
            "kwargs": dict(Bucket=bucket_name, Key=object_name),
        }
    )
    log.info(object_get_status)
    return object_get_status


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
    log.info(get_policy_status)
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
    log.info(get_versioning_status)
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
    log.info(object_get_status)
    return object_get_status


def PutBucketPolicy(**kw):
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    log.info(f"put bucket policy for bucket: {bucket_name}")
    policy = json.dumps(config.test_ops["policy_document"])
    policy_put_status = s3lib.resource_op(
        {
            "obj": rgw_client,
            "resource": "put_bucket_policy",
            "kwargs": dict(Bucket=bucket_name, Policy=policy),
        }
    )
    log.info(policy_put_status)
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
    log.info(put_versioning_status)
    return put_versioning_status


def PutObject(**kw):
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    object_name = f"{object_name}_policy_verify"
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
    log.info(object_put_status)
    return object_put_status


def verify_policy(**kw):
    log.info("Verifying all statements in Bucket Policy")
    config = kw.get("config")
    rgw_client = kw.get("rgw_client")
    bucket_name = kw.get("bucket_name")
    object_name = kw.get("object_name")
    conflicting_statements = config.test_ops.get("conflicting_statements", False)
    log.info(f"Conflicting Statements: {conflicting_statements}")
    statements = config.test_ops.get("policy_document", {}).get("Statement", [])
    for statement in statements:
        effect = statement.get("Effect", "Allow")
        actions = statement.get("Action", [])
        if type(actions) is str:
            actions = [actions]
        for action in actions:
            log.info(f"Action is {action}. Effect is {effect}")
            method_name = action.split(":")[1]
            method = globals()[method_name]

            out = method(
                rgw_client=rgw_client,
                bucket_name=bucket_name,
                object_name=object_name,
                config=config,
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
                        f"{action} is denied from other tenanted user after setting bucket policy"
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
                    raise TestExecError(
                        f"Verification of {effect} {action} failed with status code {response.status_code}"
                    )
            log.info(f"{effect} {action} verified successfully")
