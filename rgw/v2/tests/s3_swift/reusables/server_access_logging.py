import json
import logging
import re
import shlex
import time

import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError, TestExecError
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import rgw_accounts as accounts

log = logging.getLogger()


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


def rgw_admin_logging_flush(bucket_name, tenant_name=None):
    """
    Perform radosgw-admin bucket logging flush --bucket <bucket_name>
    For tenanted buckets, bucket_name should be in format tenant/bucket-name
    """
    if tenant_name:
        bucket_name = f"{tenant_name}/{bucket_name}"
    cmd = f"radosgw-admin bucket logging flush --bucket {bucket_name}"
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


def verify_journal_logs(log_records, src_user_name, src_bucket_name, config):
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
    rgw_s3_client, src_user_name, src_bucket_name, dest_bucket_name, config=None, tenant_name=None
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
        verify_journal_logs(total_log_records, src_user_name, src_bucket_name, config)
