"""
Reusable methods for S3CMD
"""

import datetime
import json
import logging
import os
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as xml
from pathlib import Path

import boto
import boto.s3.connection

log = logging.getLogger()

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../../")))

from v2.lib.exceptions import (
    DefaultDatalogBackingError,
    MFAVersionError,
    S3CommandExecError,
    TestExecError,
)
from v2.lib.manage_data import io_generator
from v2.lib.s3cmd.resource_op import S3CMD
from v2.utils import utils
from v2.utils.utils import RGWService, exec_shell_cmd

home_path = os.path.expanduser("~cephuser")
s3cmd_path = home_path + "/venv/bin/s3cmd"


def create_bucket(bucket_name, ssl=None):
    """
    Creates bucket
    Args:
        bucket_name(str): Name of the bucket to be created
    """
    mb_method = S3CMD(operation="mb")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = " "
    command = mb_method.command(params=[f"s3://{bucket_name}", ssl_param])
    try:
        mb_response = exec_shell_cmd(command)
        log.debug(f"Response for create bucket command: {mb_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = f"Bucket 's3://{bucket_name}/' created"
    error_message = f"Expected: {expected_response}, Actual: {mb_response}"
    assert expected_response in mb_response, error_message


def set_lc_lifecycle(lifecycle_rule, config, bucket_name):
    """
    Set lifecycle policy for a bucket
    Args:
        lifecycle_rule(str): Path where lc_config xml is created/present
        config(str): configuration of cluster
        bucket_name(str): Name of the bucket where policy needs to be set
    """
    log.info("Generate a LC rule xml file")
    Generate_LC_xml(lifecycle_rule, config)
    log.info(f"Apply the LC rule via the xml file on bucket {bucket_name}")
    utils.exec_shell_cmd(
        f"{s3cmd_path} setlifecycle {lifecycle_rule} s3://{bucket_name}"
    )

    utils.exec_shell_cmd(f"{s3cmd_path} getlifecycle s3://{bucket_name}")


def enable_versioning_for_a_bucket(user_info, bucket_name, ip_and_port, ssl=None):
    """
    Enable versioning for existing bucket
    Args:
        user_info : User details json
        bucket_name(str): Name of the bucket to be created
        ip_and_port (str) : hostname and port where rgw daemon is running
    """
    port = int(ip_and_port.split(":")[1])
    conn = boto.connect_s3(
        aws_access_key_id=user_info["access_key"],
        aws_secret_access_key=user_info["secret_key"],
        host=ip_and_port.split(":")[0],
        port=port,
        is_secure=False,  # Change it to True if RGW running using SSL
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
    )
    bucket = conn.get_bucket(bucket_name)
    bucket.configure_versioning(versioning=True)


def create_versioned_bucket(user_info, bucket_name, ip_and_port, ssl=None):
    """
    Creates bucket
    Args:
        user_info : User details json
        bucket_name(str): Name of the bucket to be created
        ip_and_port (str) : hostname and port where rgw daemon is running
    """
    port = int(ip_and_port.split(":")[1])
    conn = boto.connect_s3(
        aws_access_key_id=user_info["access_key"],
        aws_secret_access_key=user_info["secret_key"],
        host=ip_and_port.split(":")[0],
        port=port,
        is_secure=False,  # Change it to True if RGW running using SSL
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
    )
    bucket = conn.create_bucket(bucket_name)
    bucket.configure_versioning(versioning=True)


def upload_file(bucket_name, file_name=None, file_size=1024, test_data_path=None):
    """
    Uploads file to the bucket
    Args:
        bucket_name(str): Name of the bucket
        file_name(str): Name of the file to be uploaded
        file_size(int): Size of the file to be uploaded, defaults to 1024
        test_data_path(str): Local test data path
    Returns: File information
    """
    # If no file_name passed, it generates file_name and returns in file information
    # It is to have support for file which is already created
    if file_name is None:
        file_name = utils.gen_s3_object_name(bucket_name, 1)

    local_file_path = test_data_path + "/" + file_name
    file_info = io_generator(local_file_path, file_size)
    file_info["name"] = file_name

    upload_file_method = S3CMD(operation="put")
    remote_s3_path = f"s3://{bucket_name}/{file_name}"
    command = upload_file_method.command(params=[local_file_path, remote_s3_path])
    try:
        upload_file_response = exec_shell_cmd(command)
        log.debug(f"Response for upload file command: {upload_file_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "100%" in str(upload_file_response), "upload file operation not succeeded"
    return file_info


def download_file(
    bucket_name, remote_file_name, local_file_name=None, test_data_path=None
):
    """
    Downloads file from the bucket
    Args:
        bucket_name(str): Name of the bucket
        remote_file_name(str): Name of the remote file
        local_file_name(str): Name of the local file to be set
        test_data_path(str): Local test data path
    Returns: Name with path of the downloaded file
    """
    if local_file_name is None:
        local_file_name = "test_s3cmd.txt"

    download_file_method = S3CMD(operation="get", options=["--force"])
    remote_s3_path = f"s3://{bucket_name}/{remote_file_name}"
    local_file_path = test_data_path + "/" + local_file_name
    command = download_file_method.command(params=[remote_s3_path, local_file_path])
    try:
        download_file_response = exec_shell_cmd(command)
        log.debug(f"Response for upload file command: {download_file_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "100%" in str(
        download_file_response
    ), "download file operation not succeeded"
    return local_file_path


def delete_file(bucket_name, file_name):
    """
    Deletes file from bucket
    Args:
        bucket_name(str): Name of the bucket
        file_name(str): Name of the file to be deleted
    """
    delete_file_method = S3CMD(operation="del")
    remote_s3_path = f"s3://{bucket_name}/{file_name}"
    command = delete_file_method.command(params=[remote_s3_path])
    try:
        delete_file_response = exec_shell_cmd(command)
        log.debug(f"Response for delete file command: {delete_file_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = f"delete: '{remote_s3_path}'"
    error_message = f"Expected: {expected_response}, Actual: {delete_file_response}"
    assert expected_response in delete_file_response, error_message


def delete_bucket(bucket_name):
    """
    Deletes the bucket
    Args:
        bucket_name(str): Name of the bucket to deleted
    """
    delete_bucket_method = S3CMD(operation="rb")
    command = delete_bucket_method.command(params=[f"s3://{bucket_name}"])
    try:
        delete_bucket_response = exec_shell_cmd(command)
        log.debug(f"Response for delete bucket command: {delete_bucket_response}")
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    expected_response = f"Bucket 's3://{bucket_name}/' removed"
    error_message = f"Expected: {expected_response}, Actual: {delete_bucket_response}"
    assert expected_response in delete_bucket_response, error_message


def create_local_file(file_size, file_name):
    """
    Creates a local file with specified size
    Args:
        file_size(int): Size of the file to be created
        file_name(str): Name of the file to be created
    """
    exec_shell_cmd(f"sudo fallocate -l {file_size} {file_name}")


def get_file_size(file_name):
    """
    Returns size of the file in bytes
    Args:
        file_name(str): Name of the file to be created
    Returns: File size in bytes
    """
    return os.path.getsize(file_name)


def get_rgw_ip_and_port(ssh_con=None):
    """
    Returns RGW ip and port in <ip>:<port> format
    Returns: RGW ip and port
    """

    if ssh_con:
        _, stdout, _ = ssh_con.exec_command("hostname")
        hostname = stdout.readline().strip()
        ip = socket.gethostbyname(str(hostname))
        port = utils.get_radosgw_port_no(ssh_con)
    else:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = utils.get_radosgw_port_no()
    ip_and_port = f"{ip}:{port}"
    return ip_and_port


def rgw_service_restart(ssh_con):
    """
    Restart Rgw services
    """
    log.info("trying to restart services")
    rgw_service = RGWService()
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")


def run_subprocess(cmd):
    """
    :param cmd: command to run
    :return: stdout, stderr
    """
    try:
        rc = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    return stdout, stderr


def rate_limit_set_enable(
    scope,
    max_read_ops,
    max_read_bytes,
    max_write_ops,
    max_write_bytes,
    global_scope=None,
    uid=None,
):
    """Set and enable rate limits for the scope mentioned"""
    if uid is None:
        limset = utils.exec_shell_cmd(
            f"radosgw-admin {global_scope} ratelimit set --ratelimit-scope={scope}"
            + f" --max-read-ops={max_read_ops} --max-read-bytes={max_read_bytes}"
            + f" --max-write-bytes={max_write_bytes} --max-write-ops={max_write_ops}"
        )
        limenable = utils.exec_shell_cmd(
            f"radosgw-admin {global_scope} ratelimit enable --ratelimit-scope={scope}"
        )
    else:
        limset = utils.exec_shell_cmd(
            f"radosgw-admin ratelimit set --ratelimit-scope={scope} --uid {uid}"
            + f" --max-read-ops={max_read_ops} --max-read-bytes={max_read_bytes}"
            + f" --max-write-bytes={max_write_bytes} --max-write-ops={max_write_ops}"
        )
        limenable = utils.exec_shell_cmd(
            f"radosgw-admin ratelimit enable --ratelimit-scope={scope} --uid {uid}"
        )
    log.info(f"Rate limits set and enabled on {scope}")


def rate_limit_read(bucket, max_read_ops, ssl=None, file=None):
    """
    max_read_ops: Loop until the max_read_ops value to check for a 503
    slowdown warning
    """
    # increment max_read_ops to induce warning
    if "/" in bucket:
        bucket = bucket.split("/")[1]
    max_read_ops += 1
    range_val = f"1..{max_read_ops}"
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = ""
    cmd = (
        f"for i in {{{range_val}}}; do /home/cephuser/venv/bin/s3cmd ls "
        f"s3://{bucket}/{file} {ssl_param};done;"
    )
    stdout, stderr = run_subprocess(cmd)
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"


def rate_limit_write(bucket, max_write_ops, ssl=None):
    """
    :param bucket: bucket to write
    :param max_write_ops: Loop until the max write opsto check for 503
    :param file: file to write
    """
    # increment max_write_ops to induce warning
    if "/" in bucket:
        bucket = bucket.split("/")[1]
    max_write_ops += 1
    create_local_file("1k", "file1")
    range_val = f"1..{max_write_ops}"
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = ""
    cmd = (
        f"for i in {{{range_val}}}; do /home/cephuser/venv/bin/s3cmd "
        f"put file1 s3://{bucket}/file$i {ssl_param};done;"
    )
    stdout, stderr = run_subprocess(cmd)
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"


def debt_ratelimit(bucket, debt_limit, ssl=None):
    """
    :param bucket: bucket to write
    :param debt_limit: data to write to test the debt limit
    """
    if "/" in bucket:
        bucket = bucket.split("/")[1]
    create_local_file(str(debt_limit) + "k", "file2")
    if ssl:
        ssl_param = "-s"
    else:
        ssl_param = ""
    cmd = f"/home/cephuser/venv/bin/s3cmd put file2 s3://{bucket}/file1 {ssl_param}"
    stdout, stderr = run_subprocess(cmd)
    assert "503" not in str(stderr), "Rate limit slowdown observed, failing!"


def remote_zone_bucket_stats(bucket_name, config):
    """
    get bucket stats at the remote zone
    """
    zone_name = config.remote_zone
    if config.full_sync_test:
        bucket_name = f"tenant/{bucket_name}"
    else:
        bucket_name = f"{bucket_name}"
    log.info(f"remote zone is {zone_name}")
    remote_ip = utils.get_rgw_ip_zone(zone_name)
    remote_site_ssh_con = utils.connect_remote(remote_ip)
    log.info(f"collect bucket stats for {bucket_name} at remote site {zone_name}")
    if config.full_sync_test:
        log.info("Wait for the sync lease period + 10 minutes")
        time.sleep(1800)
    else:
        log.info(f"Wait for sometime for the objects to sync.")
        time.sleep(300)
    cmd_bucket_stats = f"radosgw-admin bucket stats --bucket {bucket_name}"
    stdin, stdout, stderr = remote_site_ssh_con.exec_command(cmd_bucket_stats)
    cmd_output = stdout.read().decode()
    stats_remote = json.loads(cmd_output)
    log.info(
        f"bucket stats at remote site {zone_name} for {bucket_name} is {stats_remote}"
    )
    log.info("Verify num_objects and size is consistent across local and remote site")
    remote_num_objects = stats_remote["usage"]["rgw.main"]["num_objects"]
    remote_size = stats_remote["usage"]["rgw.main"]["size"]
    return remote_size, remote_num_objects


def local_zone_bucket_stats(bucket_name, config):
    """
    get bucket stats at the local zone
    """
    zone_name = config.local_zone
    if config.full_sync_test:
        bucket_name = f"tenant/{bucket_name}"
    else:
        bucket_name = f"{bucket_name}"
    cmd_bucket_stats = f"radosgw-admin bucket stats --bucket {bucket_name}"
    log.info(f"collect bucket stats for {bucket_name} at local site {zone_name}")
    local_bucket_stats = json.loads(utils.exec_shell_cmd(cmd_bucket_stats))
    local_num_objects = local_bucket_stats["usage"]["rgw.main"]["num_objects"]
    local_size = local_bucket_stats["usage"]["rgw.main"]["size"]
    return local_size, local_num_objects


def test_full_sync_at_archive(bucket_name, config):
    """
    test_full_sync_at_archive zone for a bucket
    """
    local_zone_name = config.local_zone
    remote_zone_name = config.remote_zone
    log.info(f"local zone is {local_zone_name} and remote zone is {remote_zone_name}")
    remote_ip = utils.get_rgw_ip_zone(remote_zone_name)
    remote_site_ssh_con = utils.connect_remote(remote_ip)
    log.info(f"Restart the gateways at the {remote_zone_name} site")
    remote_site_ssh_con.exec_command("ceph orch restart rgw.shared.arc")
    log.info("Verify num_objects and size is consistent across local and remote site")
    remote_size, remote_num_objects = remote_zone_bucket_stats(bucket_name, config)
    local_size, local_num_objects = local_zone_bucket_stats(bucket_name, config)
    if remote_size == local_size and remote_num_objects == local_num_objects:
        log.info(f"Data is consistent for bucket {bucket_name}")
    else:
        raise TestExecError(f"Data is inconsistent for {bucket_name} across sites")


def Generate_LC_xml(fileName, config):
    """
    Generate an LC xml file
    """
    lifecycle_configuration = xml.Element("LifecycleConfiguration")
    lc_rule = xml.Element("Rule")
    lifecycle_configuration.append(lc_rule)
    rule_id = xml.SubElement(lc_rule, "ID")
    rule_id.text = "Test LC expiration at archive zone"
    rule_status = xml.SubElement(lc_rule, "Status")
    rule_status.text = "Enabled"
    rule_filter = xml.SubElement(lc_rule, "Filter")
    if config.test_ops.get("test_lc_objects_size"):
        filter_and = xml.SubElement(rule_filter, "And")
        if config.test_ops.get("test_lc_archive_zone"):
            and_archive_zone = xml.SubElement(filter_and, "ArchiveZone")
        and_prefix = xml.SubElement(filter_and, "Prefix")
        and_ObjectSizeGreaterThan = xml.SubElement(filter_and, "ObjectSizeGreaterThan")
        and_ObjectSizeLessThan = xml.SubElement(filter_and, "ObjectSizeLessThan")
        and_ObjectSizeLessThan.text = "64000"
        and_ObjectSizeGreaterThan.text = "500"
        and_prefix.text = "tax"
    else:
        filter_prefix = xml.SubElement(rule_filter, "Prefix")
        filter_prefix.text = "tax"
    if config.test_ops.get("test_lc_archive_zone"):
        filter_archive_zone = xml.SubElement(rule_filter, "ArchiveZone")
    if config.test_ops.get("test_current_expiration"):
        rule_Expiration = xml.SubElement(lc_rule, "Expiration")
        Days = xml.SubElement(rule_Expiration, "Days")
        Days.text = str(config.test_ops.get("days"))
    if config.test_ops.get("test_noncurrent_expiration"):
        rule_NoncurrentVersionExpiration = xml.SubElement(
            lc_rule, "NoncurrentVersionExpiration"
        )
        Noncurrentdays = xml.SubElement(
            rule_NoncurrentVersionExpiration, "NoncurrentDays"
        )
        Noncurrentdays.text = str(config.test_ops.get("days"))
        if config.test_ops.get("test_newer_noncurrent_expiration"):
            NewerNoncurrentVersions = xml.SubElement(
                rule_NoncurrentVersionExpiration, "NewerNoncurrentVersions"
            )
            NewerNoncurrentVersions.text = str(config.test_ops.get("newernoncurrent"))
    if config.test_ops.get("test_lc_transition"):
        rule_transition = xml.SubElement(lc_rule, "Transition")
        Days = xml.SubElement(rule_transition, "Days")
        Days.text = config.test_ops.get["days"]
        if config.test_ops.get("test_noncurrent_transition"):
            rule_NoncurrentVersionTransition = xml.SubElement(
                lc_rule, "NoncurrentVersionTransition"
            )
            Noncurrentdays = xml.SubElement(
                rule_NoncurrentVersionTransition, "NoncurrentDays"
            )
            Noncurrentdays.text = config.test_ops.get["days"]

    tree = xml.ElementTree(lifecycle_configuration)
    tree.write(fileName)


def lc_validation_at_archive_zone(bucket_name, config):
    log.info("Lifecycle validation will start, verify the objects")
    objects_count = config.objects_count
    objs_total = (config.version_count) * (config.objects_count)
    objs_ncurr = objs_total - (config.objects_count)
    log.info(f"total noncurrent objects are {objs_ncurr}")
    objs_diff = objs_total - objs_ncurr
    if config.test_ops.get("test_lc_expiration"):
        validation_time = int(config.test_ops["days"] * 40)
        log.info(f"wait for the lc validation time {validation_time}")
        time.sleep(validation_time)
        if config.test_ops.get("test_lc_local_zone", False):
            object_size, objects_number = local_zone_bucket_stats(bucket_name, config)
        else:
            object_size, objects_number = remote_zone_bucket_stats(bucket_name, config)
        if config.test_ops.get("test_current_expiration"):
            if not objects_number == objs_total:
                raise TestExecError(
                    "Test failed for LC current version expiration at archive zone."
                )
            log.info("current_expiration is validated at the archive zone")
        if config.test_ops.get("test_noncurrent_expiration"):
            if config.test_ops.get("test_newer_noncurrent_expiration"):
                newer_noncurrent_objects = int(
                    (config.test_ops["newernoncurrent"]) * (config.objects_count)
                    + config.objects_count
                )
                log.info(
                    f" the newer noncurrent objects remaining will be {newer_noncurrent_objects}"
                )
                if not objects_number == newer_noncurrent_objects:
                    raise TestExecError(
                        "Test failed for LC newer-noncurrent version expiration at archive zone."
                    )
            elif config.test_ops.get("test_lc_objects_size"):
                log.info("Assuming the rule is applied for noncurrentversionexpiration")
                if not objects_number == objs_diff:
                    raise TestExecError(
                        "Test failed for LC expiration based on object size."
                    )
            else:
                if not objects_number == objs_diff:
                    raise TestExecError(
                        "Test failed for LC noncurrent version expiration at archive zone."
                    )
                log.info("non_current_expiration is validated at the archive zone")


def upload_objects_via_s3cmd(bucket_name, config):
    s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
    if config.objects_count >= 20:
        obj_count_4Kb = config.objects_count - 2
        obj_count_64Kb = config.objects_count - obj_count_4Kb
        utils.exec_shell_cmd(f"fallocate -l 4k obj4k")
        utils.exec_shell_cmd(f"fallocate -l 64k obj64k")
        if config.version_enable:
            version_count = config.version_count
            for versions in range(config.version_count):
                for sobj in range(obj_count_4Kb):
                    log.info(
                        f"upload 4Kb objects on versioned bucket {bucket_name} for {versions} version"
                    )
                    cmd = f"{s3cmd_path} put obj4k s3://{bucket_name}/tax-4k-obj-{sobj}"
                    utils.exec_shell_cmd(cmd)
                for sobj in range(obj_count_64Kb):
                    log.info(
                        f"upload 64Kb objects on versioned bucket {bucket_name} for {versions} version"
                    )
                    cmd = (
                        f"{s3cmd_path} put obj4k s3://{bucket_name}/tax-64k-obj-{sobj}"
                    )
                    utils.exec_shell_cmd(cmd)
        else:
            for sobj in range(obj_count_4Kb):
                log.info(f"Upload 4Kb objects to the {bucket_name}")
                cmd = f"{s3cmd_path} put obj4k s3://{bucket_name}/tax-4k-obj-{sobj}"
                utils.exec_shell_cmd(cmd)
            for sobj in range(obj_count_64Kb):
                log.info(f"Upload 64Kb objects to the {bucket_name}")
                cmd = f"{s3cmd_path} put obj4k s3://{bucket_name}/tax-64k-obj-{sobj}"
                utils.exec_shell_cmd(cmd)
    if config.test_ops.get("large_multipart_upload"):
        obj_count = config.objects_count
        log.info(f"uploading some large objects to bucket {bucket_name}")
        utils.exec_shell_cmd(f"fallocate -l 20m obj20m")
        for mobj in range(obj_count):
            cmd = f"{s3cmd_path} put obj20m s3://{bucket_name}/multipart-object-{mobj}"
            utils.exec_shell_cmd(cmd)
