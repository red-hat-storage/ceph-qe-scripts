import json
import logging
import re
import shlex
import time

import botocore.exceptions
import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError, TestExecError
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bucket_policy_ops
from v2.tests.s3_swift.reusables import rgw_accounts as accounts
from v2.tests.s3_swift.reusables import server_side_encryption_s3 as sse

log = logging.getLogger()

# Expected AWS operation names for server access logging (BZ 2372311)
EXPECTED_OPERATION_NAMES = {
    "get-bucket-notification-configuration": "REST.GET.NOTIFICATION",
    "get-bucket-encryption": "REST.GET.ENCRYPTION",
    "get-public-access-block": "REST.GET.PUBLIC_ACCESS_BLOCK",
    "get-bucket-policy": "REST.GET.BUCKETPOLICY",
    "get-bucket-tagging": "REST.GET.TAGGING",
    "get-bucket-replication": "REST.GET.REPLICATION",
    "get-bucket-request-payment": "REST.GET.REQUEST_PAYMENT",
    "get-bucket-versioning": "REST.GET.VERSIONING",
    "get-bucket-website": "REST.GET.WEBSITE",
    "get-bucket-location": "REST.GET.LOCATION",
    "get-bucket-logging": "REST.GET.LOGGING",
    "get-bucket-acl": "REST.GET.ACL",
    "get-bucket-cors": "REST.GET.CORS",
    "get-bucket-lifecycle": "REST.GET.LIFECYCLE",
    "get-bucket-uploads": "REST.GET.UPLOADS",
    "get-bucket": "REST.GET.BUCKET",
    "head-bucket": "REST.HEAD.stat_bucket",
    "put-bucket-encryption": "REST.PUT.ENCRYPTION",
    "put-public-access-block": "REST.PUT.PUBLIC_ACCESS_BLOCK",
    "put-bucket-policy": "REST.PUT.BUCKETPOLICY",
    "put-bucket-tagging": "REST.PUT.TAGGING",
    "put-bucket-versioning": "REST.PUT.VERSIONING",
    "put-bucket-lifecycle": "REST.PUT.LIFECYCLE",
    "put-bucket-notification": "REST.PUT.NOTIFICATION",
    "put-bucket-acl": "REST.PUT.ACL",
    "put-bucket-cors": "REST.PUT.CORS",
    "put-bucket-object-lock": "REST.PUT.OBJECT_LOCK",
    "put-bucket-logging": "REST.PUT.LOGGING",
    "delete-bucket-encryption": "REST.DELETE.ENCRYPTION",
    "delete-public-access-block": "REST.DELETE.PUBLIC_ACCESS_BLOCK",
    "delete-bucket-policy": "REST.DELETE.BUCKETPOLICY",
    "delete-bucket-replication": "REST.DELETE.REPLICATION",
    "put-object": "REST.PUT.OBJECT",
    "get-object": "REST.GET.OBJECT",
    "head-object": "REST.HEAD.OBJECT",
    "delete-object": "REST.DELETE.OBJECT",
    "copy-object": "REST.COPY.OBJECT_GET",
    "post-object-restore": "REST.POST.RESTORE",
    "get-object-tagging": "REST.GET.OBJECT_TAGGING",
    "get-object-attributes": "REST.GET.OBJECT_ATTRIBUTES",
    "get-object-lock": "REST.GET.OBJECT_LOCK",
    "put-object-lock": "REST.PUT.OBJECT_LOCK",
    "put-object-acl": "REST.PUT.ACL",
    "get-object-acl": "REST.GET.ACL",
    "create-multipart-upload": "REST.POST.UPLOADS",
    "upload-part": "REST.PUT.PART",
    "complete-multipart-upload": "REST.POST.UPLOAD",
    "abort-multipart-upload": "REST.DELETE.UPLOAD",
    "list-multipart-uploads": "REST.GET.UPLOADS",
    "list-parts": "REST.GET.UPLOAD",
    "delete-multiple-objects": "REST.POST.DELETE_MULTI_OBJECT",
    "select-object-content": "REST.POST.OBJECT",
}


def parse_log_record(record):
    """
    Parse a log record and extract operation name.
    Returns: (operation_name, request_uri, key)
    """
    try:
        fields = shlex.split(record)
        if len(fields) < 10:
            log.warning("Log record has fewer fields than expected: %s", record)
            return None, None, None
        operation_name = fields[7]
        key = fields[8]
        request_uri = fields[9]
        return operation_name, request_uri, key
    except Exception as e:
        log.error("Error parsing log record: %s", e)
        log.error("Record: %s", record)
        return None, None, None


def verify_operation_name_in_logs(log_records, operation_mapping):
    """
    Verify that operation names in log records match expected AWS operation names.
    operation_mapping: dict mapping operation description to expected operation name.
    """
    log.info("Verifying operation names in log records...")
    found_operations = {}
    operation_errors = []
    all_operations_in_logs = set()

    for record in log_records:
        if not record.strip():
            continue
        operation_name, request_uri, key = parse_log_record(record)
        if operation_name:
            all_operations_in_logs.add(operation_name)

    log.info("Unique operation names found in logs: %s", sorted(all_operations_in_logs))

    for record in log_records:
        if not record.strip():
            continue
        operation_name, request_uri, key = parse_log_record(record)
        if operation_name is None:
            continue
        for op_desc, expected_op_name in operation_mapping.items():
            if expected_op_name == operation_name:
                if op_desc not in found_operations:
                    found_operations[op_desc] = {
                        "expected": expected_op_name,
                        "actual": operation_name,
                        "request_uri": request_uri,
                        "key": key,
                    }
                    log.info(
                        "✓ Found operation: %s -> %s (matches expected %s)",
                        op_desc,
                        operation_name,
                        expected_op_name,
                    )
                break

    log.info("%s", "=" * 80)
    log.info("Operation Name Verification Results:")
    log.info("%s", "=" * 80)
    log.info("Total operations found: %s", len(found_operations))
    log.info("Total operations expected: %s", len(operation_mapping))

    for op_desc, expected_op_name in operation_mapping.items():
        if op_desc in found_operations:
            details = found_operations[op_desc]
            if details["actual"] == expected_op_name:
                log.info("✓ %s: %s (VERIFIED)", op_desc, expected_op_name)
            else:
                error_msg = "Operation %s: Expected %s, but found %s" % (
                    op_desc,
                    expected_op_name,
                    details["actual"],
                )
                log.error(error_msg)
                operation_errors.append(error_msg)
        else:
            log.warning("✗ %s: %s (NOT FOUND)", op_desc, expected_op_name)

    unexpected_operations = []
    for op_name in all_operations_in_logs:
        is_expected = op_name in operation_mapping.values()
        matches_aws_format = (
            op_name.startswith("REST.")
            or op_name.startswith("WEBSITE.")
            or op_name.startswith("REST.HEAD.")
        )
        if not is_expected and matches_aws_format:
            log.info("  Found AWS-formatted operation (not tested): %s", op_name)
        elif (
            op_name not in ["REST.GET.BUCKET", "REST.HEAD.stat_bucket"]
            and not matches_aws_format
        ):
            unexpected_operations.append(op_name)

    if unexpected_operations:
        log.warning(
            "Found operations that may not match AWS format: %s", unexpected_operations
        )
    if operation_errors:
        raise TestExecError(
            "Operation name verification failed:\n" + "\n".join(operation_errors)
        )
    log.info("%s", "=" * 80)
    log.info("Operation name verification completed!")
    log.info(
        "Found %s out of %s expected operations",
        len(found_operations),
        len(operation_mapping),
    )
    return found_operations


def rgw_admin_logging_info(bucket_name, tenant_name=None):
    """
    Perform radosgw-admin bucket logging info --bucket <bucket_name>
    For tenanted buckets, bucket_name should be in format tenant/bucket-name
    """
    if tenant_name:
        bucket_name = f"{tenant_name}/{bucket_name}"
    cmd = f"radosgw-admin bucket logging info --bucket {bucket_name}"
    out = utils.exec_shell_cmd(cmd)
    log.info(out)
    if out is False:
        log.info(f"bucket logging info failed")
        return False
    if out:
        out = json.loads(out)
    return out


def put_bucket_logging(rgw_s3_client, src_bucket, dest_bucket, config):
    """
    put bucket logging on a given bucket
    """
    target_prefix = config.test_ops.get("target_prefix", f"{src_bucket}-logs")
    logging_conf = {
        "LoggingEnabled": {
            "TargetBucket": dest_bucket,
            "TargetPrefix": target_prefix,
            "TargetObjectKeyFormat": {
                config.test_ops.get("target_obj_key_format", "SimplePrefix"): {}
            },
            "ObjectRollTime": config.test_ops.get("obj_roll_time", 300),
            "LoggingType": config.test_ops.get("logging_type", "Standard"),
        }
    }

    log.info(
        f"put bucket logging for the bucket {src_bucket} with logging conf:{logging_conf}"
    )
    put_bkt_logging_response = rgw_s3_client.put_bucket_logging(
        Bucket=src_bucket, BucketLoggingStatus=logging_conf
    )
    log.info(f"put bucket logging response: {put_bkt_logging_response}")
    return True


def get_bucket_logging(rgw_s3_client, bucket_name):
    """
    get bucket logging for a given bucket
    """
    get_bkt_logging = rgw_s3_client.get_bucket_logging(Bucket=bucket_name)
    if get_bkt_logging is False:
        raise TestExecError(f"failed to get bucket logging for bucket : {bucket_name}")
    get_bucket_logging_json = json.dumps(get_bkt_logging, indent=2)
    log.info(f"bucket logging for bucket: {bucket_name} is {get_bkt_logging}")


def post_bucket_logging(rgw_s3_client, bucket_name):
    """
    perform post-bucket-logging for a given bucket to flush out the log records as an object to target bucket
    """
    post_bkt_logging = rgw_s3_client.post_bucket_logging(Bucket=bucket_name)
    log.info(f"post_bucket_logging response: {post_bkt_logging}")
    if post_bkt_logging is False:
        raise TestExecError(f"post_bucket_logging failed for bucket : {bucket_name}")
    log.info(post_bkt_logging)
    return post_bkt_logging["FlushedLoggingObject"]


def rgw_admin_logging_flush(bucket_name, tenant_name=None, uid=None):
    """
    Perform radosgw-admin bucket logging flush --bucket <bucket_name>
    For tenanted buckets, bucket_name should be in format tenant/bucket-name
    """
    cmd = f"radosgw-admin bucket logging flush --bucket {bucket_name}"
    if tenant_name:
        cmd = f"{cmd} --tenant {tenant_name} --uid {uid}"
    out = utils.exec_shell_cmd(cmd)
    log.info(out)
    if out is False:
        log.info(f"bucket logging flush failed")
        return False
    strings_list = out.split()
    log_object_name = strings_list[
        4
    ]  # fifth string in the response is the log object name
    log_object_name = log_object_name[1:-1]  # remove quotes
    return log_object_name


def verify_log_object_name(log_object_name, src_user_name, src_bucket_name, config):
    """
    verify if log object name format is correct or not for simple or partitioned prefix
    """
    log.info(f"Verifying log object name {log_object_name} format")
    target_prefix = config.test_ops.get("target_prefix", f"{src_bucket_name}-logs")

    if config.test_ops.get("target_obj_key_format") == "SimplePrefix":
        if not log_object_name.startswith(target_prefix):
            raise Exception(
                f"log object name does not start with expected prefix. expected prefix: {target_prefix}"
            )
        simple_prefix_regex = re.compile(
            rf"{target_prefix}"
            + r"[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-0000000000[A-Za-z0-9]{6}"
        )
        if not simple_prefix_regex.match(log_object_name):
            raise Exception(f"log object not matched with simple prefix format")
    elif config.test_ops.get("target_obj_key_format") == "PartitionedPrefix":
        out = utils.exec_shell_cmd("radosgw-admin zonegroup get")
        zonegroup_json = json.loads(out)
        zonegroup_name = zonegroup_json["name"]
        if not log_object_name.startswith(
            f"{target_prefix}{src_user_name}/{zonegroup_name}/{src_bucket_name}"
        ):
            raise Exception(
                f"log object name does not start with expected prefix. expected prefix: {target_prefix}"
            )
        partitioned_prefix_regex = re.compile(
            r".*[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-0000000000[A-Za-z0-9]{6}"
        )
        if not partitioned_prefix_regex.match(log_object_name):
            raise Exception(f"log object not matched with partitioned prefix format")
    log.info(
        f"log object name {log_object_name} matched with {config.test_ops.get('target_obj_key_format')} format"
    )


def verify_journal_logs(
    log_records, src_user_name, src_bucket_name, config, tenant_name
):
    """
    verify log records which are in journal mode format
    """
    put_count = mpu_count = copy_count = delete_count = 0
    for record in log_records:
        log.info(f"verifying record: {record}")
        fields = record.split(" ")
        bucket_owner = fields[0]
        bucket_name = fields[1]
        timestamp = f"{fields[2]} {fields[3]}"
        op = fields[4]
        key = fields[5]
        size = fields[6]
        version_id = fields[7]
        etag = fields[8]

        if op == "REST.PUT.OBJECT":
            put_count = put_count + 1
        elif op == "REST.POST.UPLOAD":
            mpu_count = mpu_count + 1
        elif op == "REST.DELETE.OBJECT" or op == "REST.POST.DELETE_MULTI_OBJECT":
            delete_count = delete_count + 1
        elif op == "REST.COPY.OBJECT_GET":
            copy_count = copy_count + 1
        else:
            raise Exception(
                f"log record not expected for operation {op} in Journal mode"
            )

        if key == "-":
            raise Exception("object name not populated")
        if tenant_name:
            if bucket_owner != f"{tenant_name}${src_user_name}":
                raise Exception("bucket_owner not matched")
            if bucket_name != f"{tenant_name}:{src_bucket_name}":
                raise Exception("bucket_name not matched")
        else:
            if bucket_owner != src_user_name:
                raise Exception("bucket_owner not matched")
            if bucket_name != src_bucket_name:
                raise Exception("bucket_name not matched")
        timestamp_regex = re.compile(
            r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [-+]\d{4}\]"
        )
        if not timestamp_regex.match(timestamp):
            raise Exception(f"timestamp {timestamp} format not matched")

        if (size == "-" or int(size) == 0) and op != "REST.POST.UPLOAD":
            raise Exception("object size not populated")
        if config.test_ops.get("enable_version") and op != "REST.POST.UPLOAD":
            if version_id == "-":
                raise Exception("version id not populated")
        if etag == "-" and op != "REST.POST.UPLOAD":
            raise Exception("etag not populated")

    objects_count = config.objects_count
    log.info(f"delete_count: {delete_count}")
    log.info(f"put_count: {put_count}")
    log.info(f"mpu_count: {mpu_count}")
    # log.info(f"copy_count: {copy_count}")
    # if copy_count != objects_count:
    #     raise Exception(
    #         "expected number of log records not populated for copy operation"
    #     )
    if delete_count != (objects_count * 2):
        raise Exception(
            "expected number of log records not populated for delete operation"
        )
    if config.test_ops.get("upload_type") == "normal":
        if put_count != (objects_count * 2):
            raise Exception(
                "expected number of log records not populated for put object operation"
            )
    if config.test_ops.get("upload_type") == "multipart":
        if mpu_count != objects_count:
            raise Exception(
                "expected number of log records not populated for multipart object upload operation"
            )


def verify_standard_logs(log_records, src_user_name, src_bucket_name, config):
    """
    verify log records which are in standard mode format
    """
    put_count = (
        create_mpu_count
    ) = (
        complete_mpu_count
    ) = part_upload_count = copy_count = delete_count = other_ops_count = 0
    _, local_ip = utils.get_hostname_ip()
    for record in log_records:
        log.info(f"verifying record: {record}")
        # fields = record.split(" ")
        # fields = re.split(r'"([^"]*)"', record)
        fields = shlex.split(record)
        log.info(f"fields: {fields}")
        bucket_owner = fields[0]
        bucket_name = fields[1]
        timestamp = f"{fields[2]} {fields[3]}"
        client_ip = fields[4]
        user_name_or_account = fields[5]
        request_id = fields[6]
        op = fields[7]
        key = fields[8]
        request_uri = fields[9]
        http_status = fields[10]
        error_code = fields[11]
        bytes_sent = fields[12]
        size = fields[13]
        total_time = fields[14]
        turnaround_time = fields[15]
        referer = fields[16]
        user_agent = fields[17]
        version_id = fields[18]
        host_id = fields[19]
        signature_version = fields[20]
        cipher_suite = fields[21]
        authentication_type = fields[22]
        host_header = fields[23]
        tls_version = fields[24]
        access_point_arn = fields[25]
        acl_flag = fields[26]

        if bucket_owner != src_user_name:
            raise Exception(
                f"bucket_owner not matched. Expected {src_user_name}, received {bucket_owner}"
            )
        if bucket_name != src_bucket_name:
            raise Exception(
                f"bucket_name not matched. Expected {src_bucket_name}, received {bucket_name}"
            )

        timestamp_regex = re.compile(
            r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [-+]\d{4}\]"
        )
        if not timestamp_regex.match(timestamp):
            raise Exception("timestamp format not matched")

        if client_ip != local_ip:
            raise Exception(
                f"client_ip not matched. Expected {local_ip}, received {client_ip}"
            )

        if user_name_or_account != src_user_name:
            raise Exception(
                f"user field who performed the operation not matched. . Expected {src_user_name}, received {user_name_or_account}"
            )

        if request_id == "-":
            raise Exception("request_id not populated")

        if op == "REST.PUT.OBJECT":
            put_count = put_count + 1
        elif op == "REST.POST.UPLOADS":
            create_mpu_count = create_mpu_count + 1
        elif op == "REST.PUT.PART":
            part_upload_count = part_upload_count + 1
        elif op == "REST.POST.UPLOAD":
            complete_mpu_count = complete_mpu_count + 1
        elif op == "REST.DELETE.OBJECT":
            delete_count = delete_count + 1
        elif op == "REST.POST.DELETE_MULTI_OBJECT" and key != "-":
            delete_count = delete_count + 1
        elif op == "REST.COPY.OBJECT_GET":
            copy_count = copy_count + 1
        else:
            other_ops_count = other_ops_count + 1

        if key == "-" and ("OBJECT" in op or "UPLOAD" in op):
            if op == "REST.POST.DELETE_MULTI_OBJECT":
                log.info(
                    f"one extra log record is sent for REST.POST.DELETE_MULTI_OBJECT operation without object name populated. ignoring it.."
                )
            else:
                raise Exception("object name not populated")

        if request_uri == "-":
            raise Exception("request_uri not populated")

        if not http_status.startswith("20"):
            raise Exception(
                f"http_status received is {http_status}, its not in success range"
            )

        if (size == "-" or int(size) == 0) and "OBJECT" in op:
            if op == "REST.POST.DELETE_MULTI_OBJECT":
                log.info(
                    f"one extra log record is sent for REST.POST.DELETE_MULTI_OBJECT operation without object size populated. ignoring it.."
                )
            else:
                raise Exception(f"object size not populated for {op}")

        if total_time != "-":
            raise Exception(f"unsupported field total_time populated with {total_time}")

        if turnaround_time == "-":
            raise Exception(f"unsupported field total_time populated with {total_time}")

        if user_agent == "-":
            raise Exception(f"user_agent not populated")

        if config.test_ops.get("enable_version") and ("UPLOAD" in op or "OBJECT" in op):
            if version_id == "-":
                raise Exception("version id not populated")

        if signature_version != "SigV4":
            raise Exception(
                f"signature_version received {signature_version}, but expected SigV4"
            )

        if cipher_suite == "TLS_AES_256_GCM_SHA384":
            log.info(
                "cipher suite is populated with TLS_AES_256_GCM_SHA384 as the endpoint is ssl"
            )
        elif cipher_suite == "-":
            log.info("cipher suite is not populated as the endpoint is non-ssl")
        else:
            raise Exception(
                f"cipher_suite received {cipher_suite}, but expected TLS_AES_256_GCM_SHA384 or -"
            )

        if authentication_type != "AuthHeader":
            raise Exception(
                f"authentication_type received {authentication_type}, but expected  AuthHeader"
            )

        # todo: host_header field verification

        if tls_version == "TLSv1.3":
            log.info(f"tls_version received {tls_version} as the endpoint is ssl")
        elif cipher_suite == "-":
            log.info(f"tls_version not populated as the endpoint is non-ssl")
        else:
            raise Exception(
                f"tls_version received {tls_version}, but expected TLSv1.3 or -"
            )

        if access_point_arn != "-":
            raise Exception(
                f"unsupported access_point_arn total_time populated with {access_point_arn}"
            )

        # if etag == "-" and ("UPLOAD" in op or "OBJECT" in op):
        #     raise Exception("etag not populated")

        # error_code, bytes_sent, referer, host_id, acl_flag may or may not be populated hence not checking them

    objects_count = config.objects_count
    log.info(f"copy_count: {copy_count}")
    log.info(f"delete_count: {delete_count}")
    log.info(f"put_count: {put_count}")
    log.info(f"create_mpu_count: {create_mpu_count}")
    log.info(f"part_upload_count: {part_upload_count}")
    log.info(f"complete_mpu_count: {complete_mpu_count}")
    log.info(f"other_ops_count: {other_ops_count}")
    if copy_count != objects_count:
        raise Exception(
            f"expected number of log records not populated for copy operation. expected {objects_count}, received {copy_count}"
        )
    if delete_count != (objects_count * 2):
        raise Exception(
            f"expected number of log records not populated for delete operation. expected {objects_count * 2}, received {delete_count}"
        )
    if config.test_ops.get("upload_type") == "normal":
        if put_count != (objects_count * 2):
            raise Exception(
                f"expected number of log records not populated for put object operation. expected {objects_count * 2}, received {put_count}"
            )
    if config.test_ops.get("upload_type") == "multipart":
        if create_mpu_count != objects_count or complete_mpu_count != objects_count:
            raise Exception(
                f"expected number of log records not populated for multipart object upload operation. expected create_mpu_count is {objects_count}, received {create_mpu_count}. expected complete_mpu_count is {objects_count}, received {complete_mpu_count}"
            )
        min_parts_for_each_object = int(
            config.objects_size_range["min"][:-1]
        ) / config.test_ops.get(
            "split_size", 5
        )  # remove M in 6M(for eg in min size) and dividie it by split size
        expected_part_uploads = objects_count * min_parts_for_each_object
        if part_upload_count < expected_part_uploads:
            raise Exception(
                f"expected number of log records not populated for multipart object upload_part operation. expected upoad_part_count is {expected_part_uploads}, received {part_upload_count}"
            )


def verify_log_records(
    rgw_s3_client,
    src_user_name,
    src_bucket_name,
    dest_bucket_name,
    config=None,
    tenant_name=None,
):
    """
    verify log records
    """
    if config.test_ops.get("rest_api_flush"):
        flushed_log_object_name = post_bucket_logging(rgw_s3_client, src_bucket_name)
    elif config.test_ops.get("rgw_admin_flush"):
        flushed_log_object_name = rgw_admin_logging_flush(src_bucket_name, tenant_name)

    verify_log_object_name(
        flushed_log_object_name, src_user_name, src_bucket_name, config
    )

    log.info(
        "sleeping for 5 seconds so that the log object is flushed to target bucket"
    )
    time.sleep(5)
    log.info("sleeping for 5 seconds so that log object is flushed")
    objects_list = reusable.list_bucket_objects(rgw_s3_client, dest_bucket_name)
    total_log_records = []
    log.info("fetching all log objects content")
    for obj in objects_list:
        key = obj["Key"]
        if key != flushed_log_object_name:
            raise Exception(
                f"flushed response log object name '{flushed_log_object_name}' not matched with actual log object name '{key}'"
            )
        response = rgw_s3_client.get_object(Bucket=dest_bucket_name, Key=key)
        content = response["Body"].read().decode("utf-8").strip()
        log.info(f"log object {key} content: {content}")
        obj_records = content.split("\n")
        total_log_records.extend(obj_records)

    if config.test_ops.get("logging_type") == "Standard":
        verify_standard_logs(total_log_records, src_user_name, src_bucket_name, config)
    elif config.test_ops.get("logging_type") == "Journal":
        verify_journal_logs(
            total_log_records, src_user_name, src_bucket_name, config, tenant_name
        )


def perform_operation_names_operations(rgw_s3_client, src_bucket_name, config):
    """
    Perform all bucket/object operations used to verify server access logging
    operation names (BZ 2372311). Returns a dict of operation description ->
    expected operation name for use with verify_operation_name_in_logs().
    """
    operations_performed = {}
    log.info("Performing bucket operations to generate log records...")

    log.info("1. Put bucket encryption")
    sse.put_bucket_encryption(rgw_s3_client, src_bucket_name, "AES256")
    operations_performed["put-bucket-encryption"] = EXPECTED_OPERATION_NAMES[
        "put-bucket-encryption"
    ]

    log.info("2. Get bucket encryption")
    bucket_policy_ops.GetBucketEncryption(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name
    )
    operations_performed["get-bucket-encryption"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-encryption"
    ]

    log.info("3. Delete bucket encryption")
    try:
        rgw_s3_client.delete_bucket_encryption(Bucket=src_bucket_name)
        operations_performed["delete-bucket-encryption"] = EXPECTED_OPERATION_NAMES[
            "delete-bucket-encryption"
        ]
    except Exception as e:
        log.warning("Delete bucket encryption failed (may not be supported): %s", e)

    log.info("4. Put public access block")
    try:
        rgw_s3_client.put_public_access_block(
            Bucket=src_bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        operations_performed["put-public-access-block"] = EXPECTED_OPERATION_NAMES[
            "put-public-access-block"
        ]
    except Exception as e:
        log.warning("Put public access block failed: %s", e)

    log.info("5. Get public access block")
    try:
        rgw_s3_client.get_public_access_block(Bucket=src_bucket_name)
        operations_performed["get-public-access-block"] = EXPECTED_OPERATION_NAMES[
            "get-public-access-block"
        ]
    except Exception as e:
        log.warning("Get public access block failed: %s", e)

    log.info("6. Delete public access block")
    try:
        rgw_s3_client.delete_public_access_block(Bucket=src_bucket_name)
        operations_performed["delete-public-access-block"] = EXPECTED_OPERATION_NAMES[
            "delete-public-access-block"
        ]
    except Exception as e:
        log.warning("Delete public access block failed: %s", e)

    log.info("7. Put bucket policy")
    test_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::%s/*" % src_bucket_name,
            }
        ],
    }
    rgw_s3_client.put_bucket_policy(
        Bucket=src_bucket_name, Policy=json.dumps(test_policy)
    )
    operations_performed["put-bucket-policy"] = EXPECTED_OPERATION_NAMES[
        "put-bucket-policy"
    ]

    log.info("8. Get bucket policy")
    bucket_policy_ops.GetBucketPolicy(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name
    )
    operations_performed["get-bucket-policy"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-policy"
    ]

    log.info("9. Put bucket tagging")
    config.test_ops["bucket_tags"] = [{"Key": "test-key", "Value": "test-value"}]
    bucket_policy_ops.PutBucketTagging(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name, config=config
    )
    operations_performed["put-bucket-tagging"] = EXPECTED_OPERATION_NAMES[
        "put-bucket-tagging"
    ]

    log.info("10. Get bucket tagging")
    bucket_policy_ops.GetBucketTagging(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name
    )
    operations_performed["get-bucket-tagging"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-tagging"
    ]

    log.info("11. Put bucket versioning")
    bucket_policy_ops.PutBucketVersioning(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name
    )
    operations_performed["put-bucket-versioning"] = EXPECTED_OPERATION_NAMES[
        "put-bucket-versioning"
    ]

    log.info("12. Get bucket versioning")
    bucket_policy_ops.GetBucketVersioning(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name
    )
    operations_performed["get-bucket-versioning"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-versioning"
    ]

    log.info("13. Put bucket lifecycle")
    config.lifecycle_conf = [
        {
            "ID": "test-rule",
            "Status": "Enabled",
            "Filter": {"Prefix": "test"},
            "Expiration": {"Days": 30},
        }
    ]
    bucket_policy_ops.PutLifecycleConfiguration(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name, config=config
    )
    operations_performed["put-bucket-lifecycle"] = EXPECTED_OPERATION_NAMES[
        "put-bucket-lifecycle"
    ]

    log.info("14. Get bucket lifecycle")
    bucket_policy_ops.GetLifecycleConfiguration(
        rgw_client=rgw_s3_client, bucket_name=src_bucket_name
    )
    operations_performed["get-bucket-lifecycle"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-lifecycle"
    ]

    log.info("15. Put bucket notification")
    try:
        rgw_s3_client.put_bucket_notification_configuration(
            Bucket=src_bucket_name,
            NotificationConfiguration={
                "TopicConfigurations": [
                    {
                        "Id": "test-notification",
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ]
            },
        )
        operations_performed["put-bucket-notification"] = EXPECTED_OPERATION_NAMES[
            "put-bucket-notification"
        ]
    except Exception as e:
        log.warning("Put bucket notification failed: %s", e)

    log.info("16. Get bucket notification")
    try:
        bucket_policy_ops.GetBucketNotification(
            rgw_client=rgw_s3_client, bucket_name=src_bucket_name
        )
        operations_performed[
            "get-bucket-notification-configuration"
        ] = EXPECTED_OPERATION_NAMES["get-bucket-notification-configuration"]
    except Exception as e:
        log.warning("Get bucket notification failed: %s", e)

    log.info("17. Get bucket location")
    rgw_s3_client.get_bucket_location(Bucket=src_bucket_name)
    operations_performed["get-bucket-location"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-location"
    ]

    log.info("18. Get bucket logging")
    rgw_s3_client.get_bucket_logging(Bucket=src_bucket_name)
    operations_performed["get-bucket-logging"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-logging"
    ]

    log.info("19. Get bucket ACL")
    rgw_s3_client.get_bucket_acl(Bucket=src_bucket_name)
    operations_performed["get-bucket-acl"] = EXPECTED_OPERATION_NAMES["get-bucket-acl"]

    log.info("20. Put bucket ACL")
    rgw_s3_client.put_bucket_acl(Bucket=src_bucket_name, ACL="private")
    operations_performed["put-bucket-acl"] = EXPECTED_OPERATION_NAMES["put-bucket-acl"]

    log.info("21. Get bucket CORS")
    try:
        rgw_s3_client.get_bucket_cors(Bucket=src_bucket_name)
        operations_performed["get-bucket-cors"] = EXPECTED_OPERATION_NAMES[
            "get-bucket-cors"
        ]
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchCORSConfiguration":
            raise
        log.info("No CORS configuration found (expected)")

    log.info("22. Put bucket CORS")
    rgw_s3_client.put_bucket_cors(
        Bucket=src_bucket_name,
        CORSConfiguration={
            "CORSRules": [
                {
                    "AllowedMethods": ["GET", "PUT"],
                    "AllowedOrigins": ["*"],
                    "AllowedHeaders": ["*"],
                }
            ]
        },
    )
    operations_performed["put-bucket-cors"] = EXPECTED_OPERATION_NAMES[
        "put-bucket-cors"
    ]

    log.info("23. Head bucket")
    rgw_s3_client.head_bucket(Bucket=src_bucket_name)
    operations_performed["head-bucket"] = EXPECTED_OPERATION_NAMES["head-bucket"]

    log.info("24. List bucket")
    bucket_policy_ops.ListBucket(rgw_client=rgw_s3_client, bucket_name=src_bucket_name)
    operations_performed["get-bucket"] = EXPECTED_OPERATION_NAMES["get-bucket"]

    test_object_name = "test-object-1"
    log.info("25. Put object")
    bucket_policy_ops.PutObject(
        rgw_client=rgw_s3_client,
        bucket_name=src_bucket_name,
        object_name=test_object_name,
    )
    operations_performed["put-object"] = EXPECTED_OPERATION_NAMES["put-object"]

    log.info("26. Get object")
    bucket_policy_ops.GetObject(
        rgw_client=rgw_s3_client,
        bucket_name=src_bucket_name,
        object_name=test_object_name,
    )
    operations_performed["get-object"] = EXPECTED_OPERATION_NAMES["get-object"]

    log.info("27. Head object")
    rgw_s3_client.head_object(Bucket=src_bucket_name, Key=test_object_name)
    operations_performed["head-object"] = EXPECTED_OPERATION_NAMES["head-object"]

    log.info("28. Get object tagging")
    try:
        rgw_s3_client.get_object_tagging(Bucket=src_bucket_name, Key=test_object_name)
        operations_performed["get-object-tagging"] = EXPECTED_OPERATION_NAMES[
            "get-object-tagging"
        ]
    except Exception as e:
        log.warning("Get object tagging failed: %s", e)

    log.info("29. Get object attributes")
    try:
        rgw_s3_client.get_object_attributes(
            Bucket=src_bucket_name,
            Key=test_object_name,
            ObjectAttributes=["ETag", "Size"],
        )
        operations_performed["get-object-attributes"] = EXPECTED_OPERATION_NAMES[
            "get-object-attributes"
        ]
    except Exception as e:
        log.warning("Get object attributes failed: %s", e)

    log.info("30. Put object ACL")
    rgw_s3_client.put_object_acl(
        Bucket=src_bucket_name, Key=test_object_name, ACL="private"
    )
    operations_performed["put-object-acl"] = EXPECTED_OPERATION_NAMES["put-object-acl"]

    log.info("31. Get object ACL")
    rgw_s3_client.get_object_acl(Bucket=src_bucket_name, Key=test_object_name)
    operations_performed["get-object-acl"] = EXPECTED_OPERATION_NAMES["get-object-acl"]

    log.info("32. Copy object")
    rgw_s3_client.copy_object(
        Bucket=src_bucket_name,
        CopySource={"Bucket": src_bucket_name, "Key": test_object_name},
        Key="test-object-copy",
    )
    operations_performed["copy-object"] = EXPECTED_OPERATION_NAMES["copy-object"]

    log.info("33. Create multipart upload")
    mpu_response = bucket_policy_ops.CreateMultipartUpload(
        rgw_client=rgw_s3_client,
        bucket_name=src_bucket_name,
        object_name="test-multipart-object",
    )
    upload_id = mpu_response["UploadId"]
    operations_performed["create-multipart-upload"] = EXPECTED_OPERATION_NAMES[
        "create-multipart-upload"
    ]

    log.info("34. Upload part")
    part_response = rgw_s3_client.upload_part(
        Bucket=src_bucket_name,
        Key="test-multipart-object",
        PartNumber=1,
        UploadId=upload_id,
        Body=b"part data",
    )
    etag = part_response["ETag"]
    operations_performed["upload-part"] = EXPECTED_OPERATION_NAMES["upload-part"]

    log.info("35. Complete multipart upload")
    rgw_s3_client.complete_multipart_upload(
        Bucket=src_bucket_name,
        Key="test-multipart-object",
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]},
    )
    operations_performed["complete-multipart-upload"] = EXPECTED_OPERATION_NAMES[
        "complete-multipart-upload"
    ]

    log.info("36. List multipart uploads")
    rgw_s3_client.list_multipart_uploads(Bucket=src_bucket_name)
    operations_performed["list-multipart-uploads"] = EXPECTED_OPERATION_NAMES[
        "get-bucket-uploads"
    ]

    log.info("37. Delete object")
    rgw_s3_client.delete_object(Bucket=src_bucket_name, Key=test_object_name)
    operations_performed["delete-object"] = EXPECTED_OPERATION_NAMES["delete-object"]

    log.info("38. Delete bucket policy")
    try:
        bucket_policy_ops.DeleteBucketPolicy(
            rgw_client=rgw_s3_client, bucket_name=src_bucket_name
        )
        operations_performed["delete-bucket-policy"] = EXPECTED_OPERATION_NAMES[
            "delete-bucket-policy"
        ]
    except Exception as e:
        log.warning("Delete bucket policy failed: %s", e)

    return operations_performed
