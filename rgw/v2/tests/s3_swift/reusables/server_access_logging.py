import json
import logging
import os
import random
import time
import timeit
import uuid
import re
from urllib import parse as urlparse

import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError, TestExecError
from v2.tests.s3_swift.reusables import rgw_accounts as accounts
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def rgw_admin_logging_info(bucket_name):
    """
    Perform radosgw-admin topic/notification operation with arguments passed.

    Args:
        config: Test configuration object.
        op: One of get, list, rm.
        args: Arguments for the command.
        sub_command: "topic" or "notification" (default: "topic").
    """

    if config.test_ops.get("test_via_rgw_accounts", False):
        # Fetch RGW account ID
        rgw_account_id = accounts.get_rgw_account()
        log.info(f"Testing topic {op} with RGW account: {rgw_account_id}")
        cmd = f"radosgw-admin --account-id {rgw_account_id} {sub_command} {op}"
    else:
        cmd = f"radosgw-admin {sub_command} {op}"

    # Modify bucket_name_to_create if tenant_name is present
    if config.test_ops.get("tenant_name") and "bucket" in args:
        tenant_name = config.test_ops.get("tenant_name")
        args["bucket"] = f"{tenant_name}/{args['bucket']}"

    for arg, val in args.items():
        cmd = f"{cmd} --{arg} {val}"

    out = utils.exec_shell_cmd(cmd)
    log.info(out)

    if out is False:
        log.info(f"{sub_command} {op} using rgw CLI failed")
        return False

    log.info(f"{sub_command} {op} using rgw CLI is successful")

    if out:
        out = json.loads(out)

    return out


def put_bucket_logging(rgw_s3_client, src_bucket, dest_bucket, config):
    if config.test_ops.get("target_prefix") is None:
        target_prefix = f"{src_bucket}-logs"
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

    log.info(f"put bucket logging for the bucket {src_bucket}")
    put_bkt_logging_response = rgw_s3_client.put_bucket_logging(
        Bucket=src_bucket, BucketLoggingStatus=logging_conf
    )
    log.info(f"put bucket logging response: {put_bkt_logging_response}")
    return True


def get_bucket_logging(rgw_s3_client, bucket_name):
    """
    get bucket notification for a given bucket
    """
    get_bkt_logging = rgw_s3_client.get_bucket_logging(Bucket=bucket_name)
    if get_bkt_logging is False:
        raise TestExecError(f"failed to get bucket logging for bucket : {bucket_name}")
    get_bucket_logging_json = json.dumps(get_bkt_logging, indent=2)
    log.info(f"bucket logging for bucket: {bucket_name} is {get_bkt_logging}")


def post_bucket_logging(rgw_s3_client, bucket_name):
    """
    post bucket logging for a given bucket to flush out the log records as an object to target bucket
    """
    post_bkt_logging = rgw_s3_client.get_bucket_logging(Bucket=bucket_name)
    log.info(f"post_bucket_logging response: {post_bkt_logging}")
    if post_bkt_logging is False:
        raise TestExecError(f"failed to post bucket logging for bucket : {bucket_name}")
    log.info(
        "sleeping for 5 seconds so that the log object is flushed to target bucket"
    )
    time.sleep(5)


def verify_journal_logs(log_records, src_user_name, src_bucket_name, config):
    put_count = mpu_count = copy_count = delete_count = 0
    for record in log_records:
        log.info(f"verifying record: {record}")
        fields = record.split(" ")
        bucket_owner = fields[0]
        bucket_name = fields[1]
        timestamp = fields[2] + fields[3]
        key = fields[4]
        op = fields[5]
        size = fields[6]
        version_id = fields[7]
        etag = fields[8]

        if op == "REST.PUT.OBJECT":
            put_count = put_count + 1
        elif op == "REST.POST.UPLOAD":
            mpu_count = mpu_count + 1
        elif op == "REST.DELETE.OBJECT":
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
            raise Exception("timestamp format not matched")

        if size == "-" and op != "REST.POST.UPLOAD":
            raise Exception("object size not populated")
        if config.test_ops.get("enable_version") and op != "REST.POST.UPLOAD":
            if version_id == "-":
                raise Exception("version id not populated")
        if etag == "-" and op != "REST.POST.UPLOAD":
            raise Exception("etag not populated")

    objects_count = config.objects_count
    log.info(f"copy_count: {copy_count}")
    log.info(f"delete_count: {delete_count}")
    log.info(f"put_count: {put_count}")
    log.info(f"mpu_count: {mpu_count}")
    if copy_count != objects_count:
        raise Exception(
            "expected number of log records not populated for copy operation"
        )
    if delete_count != objects_count:
        raise Exception(
            "expected number of log records not populated for delete operation"
        )
    if config.test_ops.get("upload_type") == "normal":
        if put_count != objects_count:
            raise Exception(
                "expected number of log records not populated for put object operation"
            )
    if config.test_ops.get("upload_type") == "multipart":
        if mpu_count != objects_count:
            raise Exception(
                "expected number of log records not populated for multipart object upload operation"
            )


def verify_standard_logs(log_records, src_user_name, src_bucket_name, config):
    put_count = (
        create_mpu_count
    ) = complete_mpu_count = copy_count = delete_count = other_ops_count = 0
    _, local_ip = utils.get_hostname_ip()
    for record in log_records:
        # fields = record.split(" ")
        fields = re.split(r'"([^"]*)"', record)
        bucket_owner = fields[0]
        bucket_name = fields[1]
        timestamp = fields[2] + fields[3]
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
            raise Exception("bucket_owner not matched")
        if bucket_name != src_bucket_name:
            raise Exception("bucket_name not matched")

        timestamp_regex = re.compile(
            r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [-+]\d{4}\]"
        )
        if not timestamp_regex.match(timestamp):
            raise Exception("timestamp format not matched")

        if client_ip != local_ip:
            raise Exception("client_ip not matched")

        if user_name_or_account != src_user_name:
            raise Exception("user field who performed the operation not matched")

        if request_id == "-":
            raise Exception("request_id not populated")

        if op == "REST.PUT.OBJECT":
            put_count = put_count + 1
        elif op == "REST.POST.UPLOADS":
            create_mpu_count = create_mpu_count + 1
        elif op == "REST.POST.UPLOAD":
            complete_mpu_count = complete_mpu_count + 1
        elif op == "REST.DELETE.OBJECT":
            delete_count = delete_count + 1
        elif op == "REST.COPY.OBJECT_GET":
            copy_count = copy_count + 1
        else:
            other_ops = other_ops + 1

        if key == "-":
            raise Exception("object name not populated")

        if request_uri == "-":
            raise Exception("request_uri not populated")

        if http_status.startswith("20"):
            raise Exception("http_status is not success")

        if size == "-" and op != "REST.POST.UPLOAD":
            raise Exception("object size not populated")

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
            raise Exception(f"signature_version not equal to SigV4")

        if cipher_suite != "TLS_AES_256_GCM_SHA384":
            raise Exception(f"cipher_suite not equal to TLS_AES_256_GCM_SHA384")

        if authentication_type != "TLS_AES_256_GCM_SHA384":
            raise Exception(f"authentication_type not equal to TLS_AES_256_GCM_SHA384")

        # todo: host_header field verification

        if tls_version != "TLSv1.3":
            raise Exception(f"tls_version not equal to TLSv1.3")

        if access_point_arn == "-":
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
    log.info(f"complete_mpu_count: {complete_mpu_count}")
    log.info(f"other_ops_count: {other_ops_count}")
    if copy_count != objects_count:
        raise Exception(
            "expected number of log records not populated for copy operation"
        )
    if delete_count != objects_count:
        raise Exception(
            "expected number of log records not populated for delete operation"
        )
    if config.test_ops.get("upload_type") == "normal":
        if put_count != objects_count:
            raise Exception(
                "expected number of log records not populated for put object operation"
            )
    if config.test_ops.get("upload_type") == "multipart":
        if create_mpu_count != objects_count and complete_mpu_count != objects_count:
            raise Exception(
                "expected number of log records not populated for multipart object upload operation"
            )


def verify_log_records(
    rgw_s3_client, src_user_name, src_bucket_name, dest_bucket_name, config=None
):
    """
    verify log records
    """
    post_bucket_logging(rgw_s3_client, src_bucket_name)

    objects_list = reusable.list_bucket_objects(rgw_s3_client, dest_bucket_name)
    total_log_records = []
    for obj in objects_list:
        response = rgw_s3_client.get_object(Bucket=dest_bucket_name, Key=obj)
        content = response["Body"].read()
        obj_records = content.split("\n")
        total_log_records.append(obj_records)

    if config.test_ops.get("logging_type") is "Standard":
        verify_standard_logs(total_log_records, src_user_name, src_bucket_name, config)
    elif config.test_ops.get("logging_type") is "Journal":
        verify_journal_logs(total_log_records, src_user_name, src_bucket_name, config)
