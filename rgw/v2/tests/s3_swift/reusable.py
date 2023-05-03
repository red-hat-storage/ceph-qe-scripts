import glob
import json
import os
import random
import subprocess
import sys

import boto3

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import logging
import math
import time
import timeit

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import DefaultDatalogBackingError, MFAVersionError, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import (
    AddUserInfo,
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.lib.sync_status import sync_status
from v2.utils.utils import HttpResponseParser, RGWService

rgw_service = RGWService()

log = logging.getLogger()


def create_bucket(bucket_name, rgw, user_info, location=None):
    log.info("creating bucket with name: %s" % bucket_name)
    # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)
    bucket = s3lib.resource_op(
        {"obj": rgw, "resource": "Bucket", "args": [bucket_name]}
    )
    kw_args = None
    if location is not None:
        kw_args = dict(CreateBucketConfiguration={"LocationConstraint": location})
    created = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "create",
            "args": None,
            "kwargs": kw_args,
            "extra_info": {"access_key": user_info["access_key"]},
        }
    )
    log.info(f"bucket creation data: {created}")
    if created is False:
        raise TestExecError("Resource execution failed: bucket creation failed")
    if created is not None:
        response = HttpResponseParser(created)
        if response.status_code == 200:
            log.info("bucket created")
        else:
            raise TestExecError("bucket creation failed")
    else:
        raise TestExecError("bucket creation failed")
    return bucket


def upload_object(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    append_data=False,
    append_msg=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    if append_data is True:
        data_info = manage_data.io_generator(
            s3_object_path,
            s3_object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    log.info("uploading s3 object: %s" % s3_object_path)
    upload_info = dict({"access_key": user_info["access_key"]}, **data_info)
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )
    object_uploaded_status = s3lib.resource_op(
        {
            "obj": s3_obj,
            "resource": "upload_file",
            "args": [s3_object_path],
            "extra_info": upload_info,
        }
    )
    if object_uploaded_status is False:
        raise TestExecError("Resource execution failed: object upload failed")
    if object_uploaded_status is None:
        log.info("object uploaded")


def failed_upload_object(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    append_data=False,
    append_msg=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    if append_data is True:
        data_info = manage_data.io_generator(
            s3_object_path,
            s3_object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    log.info("uploading s3 object: %s" % s3_object_path)
    upload_info = dict({"access_key": user_info["access_key"]}, **data_info)
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )
    object_uploaded_status = s3lib.resource_op(
        {
            "obj": s3_obj,
            "resource": "upload_file",
            "args": [s3_object_path],
            "extra_info": upload_info,
        }
    )
    if object_uploaded_status is None:
        raise TestExecError("Resource execution failed: object upload failed")
    if object_uploaded_status is False:
        log.info("failed to uploaded the object as access is denied")


def upload_version_object(
    config, user_info, rgw_conn, s3_object_name, object_size, bucket, TEST_DATA_PATH
):
    # versioning upload
    log.info("versioning count: %s" % config.version_count)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    original_data_info = manage_data.io_generator(s3_object_path, object_size)
    if original_data_info is False:
        TestExecError("data creation failed")
    created_versions_count = 0
    for vc in range(config.version_count):
        log.info("version count for %s is %s" % (s3_object_name, str(vc)))
        log.info("modifying data: %s" % s3_object_name)
        modified_data_info = manage_data.io_generator(
            s3_object_path,
            object_size,
            op="append",
            **{"message": "\nhello for version: %s\n" % str(vc)},
        )
        if modified_data_info is False:
            TestExecError("data modification failed")
        log.info("uploading s3 object: %s" % s3_object_path)
        upload_info = dict(
            {
                "access_key": user_info["access_key"],
                "versioning_status": "enabled",
                "version_count_no": vc,
            },
            **modified_data_info,
        )
        s3_obj = s3lib.resource_op(
            {
                "obj": bucket,
                "resource": "Object",
                "args": [s3_object_name],
                "extra_info": upload_info,
            }
        )
        object_uploaded_status = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "upload_file",
                "args": [modified_data_info["name"]],
                "extra_info": upload_info,
            }
        )
        if object_uploaded_status is False:
            raise TestExecError("Resource execution failed: object upload failed")
        if object_uploaded_status is None:
            log.info("object uploaded")
            s3_obj = rgw_conn.Object(bucket.name, s3_object_name)
            log.info("current_version_id: %s" % s3_obj.version_id)
            basic_io_structure = BasicIOInfoStructure()
            key_version_info = basic_io_structure.version_info(
                **{
                    "version_id": s3_obj.version_id,
                    "md5_local": upload_info["md5"],
                    "count_no": vc,
                    "size": upload_info["size"],
                }
            )
            log.info("key_version_info: %s" % key_version_info)
            write_key_io_info = KeyIoInfo()
            write_key_io_info.add_versioning_info(
                user_info["access_key"], bucket.name, s3_object_path, key_version_info
            )
            created_versions_count += 1
            log.info("created_versions_count: %s" % created_versions_count)
            log.info("adding metadata")
            metadata1 = {"m_data1": "this is the meta1 for this obj"}
            s3_obj.metadata.update(metadata1)
            metadata2 = {"m_data2": "this is the meta2 for this obj"}
            s3_obj.metadata.update(metadata2)
            log.info("metadata for this object: %s" % s3_obj.metadata)
            log.info("metadata count for object: %s" % (len(s3_obj.metadata)))
            if not s3_obj.metadata:
                raise TestExecError("metadata not created even adding metadata")
            versions = bucket.object_versions.filter(Prefix=s3_object_name)
            created_versions_count_from_s3 = len([v.version_id for v in versions])
            log.info(
                "created versions count on s3: %s" % created_versions_count_from_s3
            )
            if created_versions_count is created_versions_count_from_s3:
                log.info("no new versions are created when added metadata")
            else:
                raise TestExecError(
                    "version count mismatch, "
                    "possible creation of version on adding metadata"
                )
        s3_object_download_path = os.path.join(
            TEST_DATA_PATH, s3_object_name + ".download"
        )
        object_downloaded_status = s3lib.resource_op(
            {
                "obj": bucket,
                "resource": "download_file",
                "args": [s3_object_name, s3_object_download_path],
            }
        )
        if object_downloaded_status is False:
            raise TestExecError("Resource execution failed: object download failed")
        if object_downloaded_status is None:
            log.info("object downloaded")
        # checking md5 of the downloaded file
        s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
        log.info("downloaded_md5: %s" % s3_object_downloaded_md5)
        log.info("uploaded_md5: %s" % modified_data_info["md5"])
        log.info("deleting downloaded version file")
        utils.exec_shell_cmd("sudo rm -rf %s" % s3_object_download_path)
    log.info("all versions for the object: %s\n" % s3_object_name)


def download_object(s3_object_name, bucket, TEST_DATA_PATH, s3_object_path, config):
    log.info("s3 object name to download: %s" % s3_object_name)
    s3_object_download_name = s3_object_name + "." + "download"
    s3_object_download_path = os.path.join(TEST_DATA_PATH, s3_object_download_name)
    object_downloaded_status = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "download_file",
            "args": [s3_object_name, s3_object_download_path],
        }
    )
    if object_downloaded_status is False:
        raise TestExecError("Resource execution failed: object download failed")
    if object_downloaded_status is None:
        log.info("object downloaded")

    s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
    s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
    log.info("s3_object_downloaded_md5: %s" % s3_object_downloaded_md5)
    log.info("s3_object_uploaded_md5: %s" % s3_object_uploaded_md5)
    if str(s3_object_uploaded_md5) == str(s3_object_downloaded_md5):
        log.info("md5 match")
        utils.exec_shell_cmd("rm -rf %s" % s3_object_download_path)
    else:
        raise TestExecError("md5 mismatch")
    if config.local_file_delete is True:
        log.info("deleting local file created after the upload")
        utils.exec_shell_cmd("rm -rf %s" % s3_object_path)


def upload_object_with_tagging(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    obj_tag,
    append_data=False,
    append_msg=None,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    if append_data is True:
        data_info = manage_data.io_generator(
            s3_object_path,
            s3_object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    log.info("uploading s3 object with object tagging enabled: %s" % s3_object_path)
    bucket.put_object(Key=s3_object_name, Body=s3_object_path, Tagging=obj_tag)


def upload_mutipart_object(
    s3_object_name,
    bucket,
    TEST_DATA_PATH,
    config,
    user_info,
    append_data=False,
    append_msg=None,
    abort_multipart=False,
):
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    split_size = config.split_size if hasattr(config, "split_size") else 5
    log.info("split size: %s" % split_size)
    if append_data is True:
        data_info = manage_data.io_generator(
            s3_object_path,
            s3_object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    mp_dir = os.path.join(TEST_DATA_PATH, s3_object_name + ".mp.parts")
    log.info("mp part dir: %s" % mp_dir)
    log.info("making multipart object part dir")
    mkdir = utils.exec_shell_cmd("sudo mkdir %s" % mp_dir)
    if mkdir is False:
        raise TestExecError("mkdir failed creating mp_dir_name")
    utils.split_file(s3_object_path, split_size, mp_dir + "/")
    parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
    log.info("parts_list: %s" % parts_list)
    log.info("uploading s3 object: %s" % s3_object_path)
    upload_info = dict(
        {"access_key": user_info["access_key"], "upload_type": "multipart"}, **data_info
    )
    s3_obj = s3lib.resource_op(
        {
            "obj": bucket,
            "resource": "Object",
            "args": [s3_object_name],
        }
    )
    log.info("initiating multipart upload")
    mpu = s3lib.resource_op(
        {
            "obj": s3_obj,
            "resource": "initiate_multipart_upload",
            "args": None,
            "extra_info": upload_info,
        }
    )
    part_number = 1
    parts_info = {"Parts": []}
    log.info("no of parts: %s" % len(parts_list))
    abort_part_no = random.randint(1, len(parts_list) - 1)
    log.info(f"abort part no is: {abort_part_no}")
    for each_part in parts_list:
        log.info("trying to upload part: %s" % each_part)
        part = mpu.Part(part_number)
        # part_upload_response = part.upload(Body=open(each_part))
        part_upload_response = s3lib.resource_op(
            {
                "obj": part,
                "resource": "upload",
                "kwargs": dict(Body=open(each_part, mode="rb")),
            }
        )
        if part_upload_response is not False:
            response = HttpResponseParser(part_upload_response)
            if response.status_code == 200:
                log.info("part uploaded")
            else:
                raise TestExecError("part uploading failed")
        part_info = {"PartNumber": part_number, "ETag": part_upload_response["ETag"]}
        parts_info["Parts"].append(part_info)
        if each_part != parts_list[-1]:
            # increase the part number only if the current part is not the last part
            part_number += 1
        log.info("curr part_number: %s" % part_number)

        if abort_multipart and part_number == abort_part_no:
            log.info(f"aborting multi part {part_number}")
            return

    if config.local_file_delete is True:
        log.info("deleting local file part")
        utils.exec_shell_cmd(f"rm -rf {mp_dir}")
    # log.info('parts_info so far: %s'% parts_info)
    if len(parts_list) == part_number:
        log.info("all parts upload completed")
        mpu.complete(MultipartUpload=parts_info)
        log.info("multipart upload complete for key: %s" % s3_object_name)


def enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info):
    log.info("bucket versioning test on bucket: %s" % bucket.name)
    # bucket_versioning = s3_ops.resource_op(rgw_conn, 'BucketVersioning', bucket.name)
    bucket_versioning = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "BucketVersioning", "args": [bucket.name]}
    )
    # checking the versioning status
    # version_status = s3_ops.resource_op(bucket_versioning, 'status')
    version_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "status", "args": None}
    )
    if version_status is None:
        log.info("bucket versioning still not enabled")
    # enabling bucket versioning
    # version_enable_status = s3_ops.resource_op(bucket_versioning, 'enable')
    version_enable_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "enable", "args": None}
    )
    response = HttpResponseParser(version_enable_status)
    if response.status_code == 200:
        log.info("version enabled")
        write_bucket_io_info.add_versioning_status(
            user_info["access_key"], bucket.name, "enabled"
        )
    else:
        raise TestExecError("version enable failed")


def generate_totp(seed):
    cmd = "oathtool -d6 --totp %s" % seed
    totp_token = utils.exec_shell_cmd(cmd)
    return totp_token.rstrip("\n")


def enable_mfa_versioning(
    bucket, rgw_conn, SEED, serial, user_info, write_bucket_io_info
):
    log.info("bucket MFA and versioning test on bucket: %s" % bucket.name)
    bucket_versioning = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "BucketVersioning", "args": [bucket.name]}
    )
    # checking the versioning status
    version_status = s3lib.resource_op(
        {"obj": bucket_versioning, "resource": "status", "args": None}
    )
    if version_status is None:
        log.info("bucket mfa and versioning still not enabled")

    # generate MFA token to authenticate
    token = generate_totp(SEED)
    mfa_token = serial + " " + token

    # put mfa and bucket versioning
    mfa_version_put = s3lib.resource_op(
        {
            "obj": bucket_versioning,
            "resource": "put",
            "kwargs": dict(
                MFA=(mfa_token),
                VersioningConfiguration={"MFADelete": "Enabled", "Status": "Enabled"},
                ExpectedBucketOwner=user_info["user_id"],
            ),
        }
    )

    if mfa_version_put is False:
        return token, mfa_version_put

    response = HttpResponseParser(mfa_version_put)
    if response.status_code == 200:
        log.info("MFA and version enabled")
    else:
        raise MFAVersionError("bucket mfa and versioning enable failed")


def put_get_bucket_lifecycle_test(
    bucket,
    rgw_conn,
    rgw_conn2,
    life_cycle_rule,
    config,
    upload_start_time=None,
    upload_end_time=None,
):
    bucket_life_cycle = s3lib.resource_op(
        {
            "obj": rgw_conn,
            "resource": "BucketLifecycleConfiguration",
            "args": [bucket.name],
        }
    )
    put_bucket_life_cycle = s3lib.resource_op(
        {
            "obj": bucket_life_cycle,
            "resource": "put",
            "kwargs": dict(LifecycleConfiguration=life_cycle_rule),
        }
    )
    log.info("put bucket life cycle:\n%s" % put_bucket_life_cycle)
    if put_bucket_life_cycle is False:
        raise TestExecError("Resource execution failed: put bucket lifecycle failed")
    if put_bucket_life_cycle is not None:
        response = HttpResponseParser(put_bucket_life_cycle)
        if response.status_code == 200:
            log.info("bucket life cycle added")
        else:
            raise TestExecError("bucket lifecycle addition failed")
    log.info("trying to retrieve bucket lifecycle config")
    get_bucket_life_cycle_config = s3lib.resource_op(
        {
            "obj": rgw_conn2,
            "resource": "get_bucket_lifecycle_configuration",
            "kwargs": dict(Bucket=bucket.name),
        }
    )
    if get_bucket_life_cycle_config is False:
        raise TestExecError("bucket lifecycle config retrieval failed")
    if get_bucket_life_cycle_config is not None:
        response = HttpResponseParser(get_bucket_life_cycle_config)
        if response.status_code == 200:
            log.info("bucket life cycle retrieved")
        else:
            raise TestExecError("bucket lifecycle config retrieval failed")
    else:
        raise TestExecError("bucket life cycle retrieved")
    objs_total = (config.test_ops["version_count"]) * (config.objects_count)
    if not upload_start_time:
        upload_start_time = time.time()
    if not upload_end_time:
        upload_end_time = time.time()
    time_diff = math.ceil(upload_end_time - upload_start_time)
    time_limit = upload_start_time + (config.rgw_lc_debug_interval * 20)
    for rule in config.lifecycle_conf:
        if rule.get("Expiration", {}).get("Date", False):
            # todo: need to get the interval value from yaml file
            log.info("wait for 60 seconds")
            time.sleep(60)
        else:
            while time.time() < time_limit:
                bucket_stats_op = utils.exec_shell_cmd(
                    "radosgw-admin bucket stats --bucket=%s" % bucket.name
                )
                json_doc1 = json.loads(bucket_stats_op)
                obj_pre_lc = json_doc1["usage"]["rgw.main"]["num_objects"]
                if obj_pre_lc == objs_total or config.test_lc_transition:
                    time.sleep(config.rgw_lc_debug_interval)
                else:
                    raise TestExecError("Objects expired before the expected days")
            time.sleep(time_diff + 60)

            if config.test_ops.get("conflict_exp_days"):
                bucket_stats_op = utils.exec_shell_cmd(
                    "radosgw-admin bucket stats --bucket=%s" % bucket.name
                )
                json_doc1 = json.loads(bucket_stats_op)
                obj_post_lc = json_doc1["usage"]["rgw.main"]["num_objects"]
                if obj_post_lc == objs_total:
                    raise TestExecError(
                        "S3 Lifecycle should choose the path that is least expensive. "
                        + "But lc expiration is takin more time than least expiration days "
                        + "when conflict between expiration days exist"
                    )

    log.info("testing if lc is applied via the radosgw-admin cli")
    op = utils.exec_shell_cmd("radosgw-admin lc list")
    json_doc = json.loads(op)
    for i, entry in enumerate(json_doc):
        print(i)
        print(entry["status"])
        if entry["status"] == "COMPLETE" or entry["status"] == "PROCESSING":
            log.info("LC is applied on the bucket")
        else:
            raise TestExecError("LC is not applied")
    op_lc_get = utils.exec_shell_cmd(f"radosgw-admin lc get --bucket {bucket.name}")
    json_doc = json.loads(op_lc_get)
    rule_map = json_doc["rule_map"][0]["rule"]
    if not rule_map:
        raise TestExecError(
            f"radosgw-admin lc get is not applied on bucket {bucket.name}"
        )


def remove_user(user_info, cluster_name="ceph", tenant=False):
    log.info("Removing user")
    if tenant:
        cmd = "radosgw-admin user rm --purge-keys --purge-data --uid=%s --tenant=%s" % (
            user_info["user_id"],
            tenant,
        )
    else:
        cmd = "radosgw-admin user rm --purge-keys --purge-data --uid=%s" % (
            user_info["user_id"]
        )
    out = utils.exec_shell_cmd(cmd)
    if out is not False:
        write_user_data = AddUserInfo()
        write_user_data.set_user_deleted(user_info["access_key"])
    return out


def rename_user(old_username, new_username, tenant=False):
    """"""
    if tenant:
        cmd = "radosgw-admin user rename --uid=%s --new-uid=%s --tenant=%s" % (
            old_username,
            new_username,
            tenant,
        )
    else:
        cmd = "radosgw-admin user rename --uid=%s --new-uid=%s" % (
            old_username,
            new_username,
        )
    out = utils.exec_shell_cmd(cmd)
    log.info("Renamed user %s to %s" % (old_username, new_username))
    return out


def rename_bucket(old_bucket, new_bucket, userid, tenant=False):
    """"""
    validate = "radosgw-admin bucket list"
    if tenant:
        old_bucket = str(tenant) + "/" + old_bucket
        new_bucket = str(tenant) + "/" + new_bucket
        cmd = (
            f"radosgw-admin bucket link --bucket={old_bucket} "
            f"--bucket-new-name={new_bucket} --uid={userid} --tenant={tenant}"
        )
    else:
        cmd = "radosgw-admin bucket link --bucket=%s --bucket-new-name=%s --uid=%s" % (
            "/" + old_bucket,
            new_bucket,
            userid,
        )
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW Bucket rename error")
    response = utils.exec_shell_cmd(validate)
    if old_bucket in json.loads(response):
        raise TestExecError("RGW Bucket rename validation error")
    log.info("Renamed bucket %s to %s" % (old_bucket, new_bucket))
    return out


def get_multisite_info():
    cmd = "radosgw-admin period get"
    period_list = utils.exec_shell_cmd(cmd)
    period_list = json.loads(period_list)
    zone_names = ""
    for i in range(len(period_list.get("period_map")["zonegroups"][0]["zones"])):
        zone_name = period_list.get("period_map")["zonegroups"][0]["zones"][i]["name"]
        zone_names = zone_names + zone_name
        if i != len(period_list.get("period_map")["zonegroups"][0]["zones"]) - 1:
            zone_names = zone_names + ","
    realm_name = period_list.get("realm_name")
    return zone_names, realm_name


def update_commit():
    _, realm_name = get_multisite_info()
    cmd_realm = f"radosgw-admin period update --rgw-realm={realm_name} --commit"
    utils.exec_shell_cmd(cmd_realm)


def unlink_bucket(curr_uid, bucket, tenant=False):
    """"""
    if tenant:
        cmd = "radosgw-admin bucket unlink --bucket=%s --uid=%s --tenant=%s" % (
            bucket,
            curr_uid,
            tenant,
        )
    else:
        cmd = "radosgw-admin bucket unlink --bucket=%s --uid=%s" % (bucket, curr_uid)
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError("RGW Bucket unlink error")
    return out


def link_chown_to_tenanted(new_uid, bucket, tenant):
    """"""
    cmd = "radosgw-admin bucket link --bucket=%s --uid=%s --tenant=%s" % (
        "/" + bucket,
        new_uid,
        tenant,
    )
    out1 = utils.exec_shell_cmd(cmd)
    if out1 is False:
        raise TestExecError("RGW Bucket link error")
    log.info("output :%s" % out1)
    cmd1 = "radosgw-admin bucket chown --bucket=%s --uid=%s --tenant=%s" % (
        bucket,
        new_uid,
        tenant,
    )
    out2 = utils.exec_shell_cmd(cmd1)
    if out2 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info("output :%s" % out2)
    return


def link_chown_to_nontenanted(new_uid, bucket, tenant):
    """"""
    cmd2 = "radosgw-admin bucket link --bucket=%s --uid=%s" % (
        tenant + "/" + bucket,
        new_uid,
    )
    out3 = utils.exec_shell_cmd(cmd2)
    if out3 is False:
        raise TestExecError("RGW Bucket link error")
    log.info("output :%s" % out3)
    cmd3 = "radosgw-admin bucket chown --bucket=%s --uid=%s" % (bucket, new_uid)
    out4 = utils.exec_shell_cmd(cmd3)
    if out4 is False:
        raise TestExecError("RGW Bucket chown error")
    log.info("output :%s" % out4)
    return


def delete_objects(bucket):
    """
    deletes the objects in a given bucket
    :param bucket: S3Bucket object
    """
    log.info("listing all objects in bucket: %s" % bucket.name)
    objects = s3lib.resource_op({"obj": bucket, "resource": "objects", "args": None})
    log.info("objects :%s" % objects)
    all_objects = s3lib.resource_op({"obj": objects, "resource": "all", "args": None})
    log.info("all objects: %s" % all_objects)
    for obj in all_objects:
        log.info("object_name: %s" % obj.key)
    log.info("deleting all objects in bucket")
    objects_deleted = s3lib.resource_op(
        {"obj": objects, "resource": "delete", "args": None}
    )
    log.info("objects_deleted: %s" % objects_deleted)
    if objects_deleted is False:
        raise TestExecError("Resource execution failed: Object deletion failed")
    if objects_deleted is not None:
        response = HttpResponseParser(objects_deleted[0])
        if response.status_code == 200:
            log.info("objects deleted ")
            write_key_info = KeyIoInfo()
            for obj in all_objects:
                log.info(f"writing log for delete object {obj.key}")
                write_key_info.set_key_deleted(obj.bucket_name, obj.key)
        else:
            raise TestExecError("objects deletion failed")
    else:
        raise TestExecError("objects deletion failed")


def list_objects(bucket):
    """
    list the objects in a given bucket
    :param bucket: S3Bucket object
    """
    log.info("listing all objects in bucket: %s" % bucket.name)
    objects = s3lib.resource_op({"obj": bucket, "resource": "objects", "args": None})
    log.info("objects :%s" % objects)
    all_objects = s3lib.resource_op({"obj": objects, "resource": "all", "args": None})
    log.info("all objects: %s" % all_objects)
    for obj in all_objects:
        log.info("object_name: %s" % obj.key)


def list_versioned_objects(bucket, s3_object_name, s3_object_path=None, rgw_conn=None):
    """
    list all versions of the objects in a given bucket
    :param bucket: S3Bucket object
    """
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    log.info(f"listing all the versions of objects {s3_object_name}")
    for version in versions:
        log.info(f"key_name: {version.object_key} --> version_id: {version.version_id}")


def delete_version_object(
    bucket,
    s3_object_name,
    s3_object_path,
    rgw_conn,
    user_info,
):
    """
    deletes single object and its versions
    :param bucket: S3bucket object
    :param s3_object_name: s3 object name
    :param s3_object_path: path of the object created in the client
    :param rgw_conn: rgw connection
    :param user_info: user info dict containing access_key, secret_key and user_id
    """
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    log.info("deleting s3_obj keys and its versions")
    s3_obj = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "Object", "args": [bucket.name, s3_object_name]}
    )
    log.info("deleting versions for s3 obj: %s" % s3_object_name)
    for version in versions:
        log.info("trying to delete obj version: %s" % version.version_id)
        del_obj_version = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "delete",
                "kwargs": dict(VersionId=version.version_id),
            }
        )
        log.info("response:\n%s" % del_obj_version)
        if del_obj_version is not None:
            response = HttpResponseParser(del_obj_version)
            if response.status_code == 204:
                log.info("version deleted ")
                write_key_io_info = KeyIoInfo()
                write_key_io_info.delete_version_info(
                    user_info["access_key"],
                    bucket.name,
                    s3_object_path,
                    version.version_id,
                )
            else:
                raise TestExecError("version  deletion failed")
        else:
            raise TestExecError("version deletion failed")
    log.info("available versions for the object")
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    for version in versions:
        log.info(
            "key_name: %s --> version_id: %s" % (version.object_key, version.version_id)
        )


def delete_versioned_object(
    bucket,
    s3_object_name,
    rgw_conn,
    s3_object_path=None,
    user_info=None,
    return_status=False,
):
    """
    deletes single object and its versions
    :param bucket: S3bucket object
    :param s3_object_name: s3 object name
    :param s3_object_path: path of the object created in the client
    :param rgw_conn: rgw connection
    :param user_info: user info dict containing access_key, secret_key and user_id
    """
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    log.info("deleting s3_obj keys and its versions")
    not_deleted = False
    s3_obj = s3lib.resource_op(
        {"obj": rgw_conn, "resource": "Object", "args": [bucket.name, s3_object_name]}
    )
    log.info("deleting versions for s3 obj: %s" % s3_object_name)
    for version in versions:
        log.info("trying to delete obj version: %s" % version.version_id)
        del_obj_version = s3lib.resource_op(
            {
                "obj": s3_obj,
                "resource": "delete",
                "kwargs": dict(VersionId=version.version_id),
            }
        )
        log.info("response:\n%s" % del_obj_version)
        if (del_obj_version is not None) and (del_obj_version != False):
            response = HttpResponseParser(del_obj_version)
            if return_status:
                return response
            if response.status_code == 204:
                log.info("version deleted ")
            else:
                raise TestExecError("version  deletion failed")
        else:
            not_deleted = True
            if return_status:
                return not_deleted
            raise TestExecError("version deletion failed")
    log.info("available versions for the object")
    versions = bucket.object_versions.filter(Prefix=s3_object_name)
    for version in versions:
        log.info(
            "key_name: %s --> version_id: %s" % (version.object_key, version.version_id)
        )


def delete_bucket(bucket):
    """
    deletes a given bucket
    :param bucket: s3Bucket object
    """
    for retry_count in range(4):
        log.info("listing objects if any")
        objs = bucket.objects.all()
        count = sum(1 for _ in bucket.objects.all())
        if count > 0:
            log.info(f"objects not deleted, count is:{count}")
            for ob in objs:
                log.info(f"object: {ob.key}")
        else:
            log.info("No objects in bucket")
            break
        time.sleep(10)
    log.info("deleting bucket: %s" % bucket.name)
    bucket_deleted_response = s3lib.resource_op(
        {"obj": bucket, "resource": "delete", "args": None}
    )
    log.info("bucket_deleted_status: %s" % bucket_deleted_response)
    if bucket_deleted_response is not None and isinstance(
        bucket_deleted_response, dict
    ):
        response = HttpResponseParser(bucket_deleted_response)
        if response.status_code == 204:
            log.info("bucket deleted ")
            write_bucket_info = BucketIoInfo()
            log.info("adding io info of delete bucket")
            write_bucket_info.set_bucket_deleted(bucket.name)
        else:
            raise TestExecError("bucket deletion failed")
    else:
        raise TestExecError("bucket deletion failed")


def set_gc_conf(ceph_conf, conf):
    log.info("making changes to ceph.conf")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.bluestore_block_size,
        str(conf.get("bluestore_block_size", 1549267441664)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_max_queue_size,
        str(conf.get("rgw_gc_max_queue_size", 367788)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_processor_max_time,
        str(conf.get("rgw_gc_processor_max_time", 3600)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_max_concurrent_io,
        str(conf.get("rgw_gc_max_concurrent_io", 10)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_objexp_gc_interval,
        str(conf.get("rgw_objexp_gc_interval", 10)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_max_trim_chunk,
        str(conf.get("rgw_gc_max_trim_chunk", 32)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_obj_min_wait,
        str(conf.get("rgw_gc_obj_min_wait", 10)),
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_processor_period,
        str(conf.get("rgw_gc_processor_period", 10)),
    )
    log.info("trying to restart services")
    srv_restarted = rgw_service.restart()
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")
    # Delete gc queue
    pool_name = utils.exec_shell_cmd("ceph df |awk '{ print $1 }'| grep rgw.log")
    pool_name = pool_name.replace("\n", "")
    for i in range(0, 32):
        utils.exec_shell_cmd("rados rm gc.%d -p %s -N gc" % (i, pool_name))


def verify_gc():
    op = utils.exec_shell_cmd("radosgw-admin gc list")
    # op variable will capture command output such as entire gc list or error like ERROR: failed to list objs: (22) Invalid argument
    final_op = op.find("ERROR") or op.find("Invalid argument")
    return final_op


def check_for_crash():
    """
    check for crash on cluster
    """
    ceph_version_id, ceph_version_name = utils.get_ceph_version()
    if ceph_version_name != "luminous":
        log.info("check for any new crashes on the ceph cluster ")
        ceph_crash = utils.exec_shell_cmd("ceph crash ls-new")
        if ceph_crash:
            ceph_crash_all = ceph_crash.split()
            no_of_crashes = len(ceph_crash_all)
            for i in range(3, no_of_crashes):
                if i % 3 == 0:
                    ceph_crash_id, ceph_crash_entity = (
                        ceph_crash_all[i],
                        ceph_crash_all[i + 1],
                    )
                    log.info(f"ceph daemon {ceph_crash_entity} crashed!")
                    crash_info = utils.exec_shell_cmd(
                        "ceph crash info %s" % ceph_crash_id
                    )
            log.info(
                "archiving the crashes to silence health warnings! to view the crashes use the command: ceph crash ls"
            )
            utils.exec_shell_cmd("ceph crash archive-all")
        else:
            log.info("No ceph daemon crash found")
        return ceph_crash


def time_to_list_via_radosgw(bucket_name, listing):
    """
    Time taken to list via radosgw-admin command.
    :param bucket: s3Bucket object
    :param listing: ordered or unordered listing
    """
    if listing == "ordered":
        log.info("listing via radosgw-admin bucket list --max-entries=.. --bucket <>")
        cmd = "radosgw-admin bucket list --max-entries=100000 --bucket=%s " % (
            bucket_name
        )
        time_taken = timeit.timeit(utils.exec_shell_cmd(cmd), globals=globals())
        return time_taken

    if listing == "unordered":
        log.info(
            "listing via radosgw-admin bucket list --max-entries=.. --bucket <> --allow-unordered"
        )
        cmd = (
            "radosgw-admin bucket list --max-entries=100000 --bucket=%s --allow-unordered"
            % (bucket_name)
        )
        time_taken = timeit.timeit(utils.exec_shell_cmd(cmd), globals=globals())
        return time_taken


def time_to_list_via_boto(bucket_name, rgw):
    """
    Time taken to list via boto
    :param bucket: s3Bucket object
    """
    bucket = s3lib.resource_op(
        {"obj": rgw, "resource": "Bucket", "args": [bucket_name]}
    )

    log.info("listing all objects in bucket: %s" % bucket)
    objects = s3lib.resource_op({"obj": bucket, "resource": "objects", "args": None})
    time_taken = timeit.timeit(lambda: bucket.objects.all(), globals=globals())
    return time_taken


def check_sync_status(retry=None, delay=None):
    """
    Check sync status if its a multisite cluster
    """
    is_multisite = utils.is_cluster_multisite()
    if is_multisite:
        sync_status()


def check_bucket_sync_status(bkt=None):
    bucket_sync_status = utils.exec_shell_cmd(
        f"radosgw-admin bucket sync status --bucket {bkt}"
    )
    return bucket_sync_status


def get_default_datalog_type():
    """
    get the default datalog type i.e. omap or fifo
    """
    cmd = "ceph config get mon.* rgw_default_data_log_backing"
    default_datalog_type = utils.exec_shell_cmd(cmd)
    if default_datalog_type is False:
        raise DefaultDatalogBackingError(
            "Error in getting the default datalog backing type"
        )
    return default_datalog_type


def check_datalog_list():
    """
    check datalog list
    """
    cmd = "radosgw-admin datalog list"
    datalog_list = utils.exec_shell_cmd(cmd)
    if "ERROR" in datalog_list or "failed" in datalog_list:
        return True
    else:
        return False


def get_datalog_marker():
    """
    check the datalog marker
    """
    # changing the value of rgw_data_log_num_shards is not supported. Ref: https://bugzilla.redhat.com/show_bug.cgi?id=1938105#c7
    log.info("get the value of rgw_data_log_num_shards")
    cmd = "ceph config get mon.* rgw_data_log_num_shards"
    datalog_num_shards = utils.exec_shell_cmd(cmd)
    log.info(f"datalog_num_shards: {datalog_num_shards}")

    # check for marker in datalog status
    cmd = "radosgw-admin datalog status"
    datalog_status_cmd = utils.exec_shell_cmd(cmd)
    datalog_status = json.loads(datalog_status_cmd)

    # fetch the first occurance of marker
    get_datalog_marker = ""
    shard_id = -1
    datalog_num_shards = int(datalog_num_shards) - 1
    for i in range(datalog_num_shards):
        if datalog_status[i]["marker"] is "":
            continue
        else:
            get_datalog_marker = datalog_status[i]["marker"]
            shard_id = i
            break

    # return shard_id and datalog_mark, Ref BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1981860
    return shard_id, get_datalog_marker


def check_datalog_marker():
    """
    check the datalog marker
    """
    _, marker = get_datalog_marker()
    if "1_" in marker:
        return "omap"
    if ":" in marker:
        return "fifo"
    raise TestExecError(f"No known identifiers found in datalog marker \n {marker}")


def put_bucket_lifecycle(bucket, rgw_conn, rgw_conn2, life_cycle_rule):
    """
    Set/Put lifecycle to provided bucket
    """
    bucket_life_cycle = s3lib.resource_op(
        {
            "obj": rgw_conn,
            "resource": "BucketLifecycleConfiguration",
            "args": [bucket.name],
        }
    )
    put_bucket_life_cycle = s3lib.resource_op(
        {
            "obj": bucket_life_cycle,
            "resource": "put",
            "kwargs": dict(LifecycleConfiguration=life_cycle_rule),
        }
    )
    log.info(f"put bucket life cycle:\n{put_bucket_life_cycle}")
    if not put_bucket_life_cycle:
        raise TestExecError("Resource execution failed: put bucket lifecycle failed")
    if put_bucket_life_cycle:
        response = HttpResponseParser(put_bucket_life_cycle)
        if response.status_code == 200:
            log.info("bucket life cycle added")
        else:
            raise TestExecError("bucket lifecycle addition failed")
    log.info("trying to retrieve bucket lifecycle config")
    get_bucket_life_cycle_config = s3lib.resource_op(
        {
            "obj": rgw_conn2,
            "resource": "get_bucket_lifecycle_configuration",
            "kwargs": dict(Bucket=bucket.name),
        }
    )
    if not get_bucket_life_cycle_config:
        raise TestExecError("bucket lifecycle config retrieval failed")
    if get_bucket_life_cycle_config:
        response = HttpResponseParser(get_bucket_life_cycle_config)
        if response.status_code == 200:
            log.info("bucket life cycle retrieved")
        else:
            raise TestExecError("bucket lifecycle config retrieval failed")
    else:
        raise TestExecError("bucket life cycle retrieved")
    lc_data = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
    log.info(f"lc data is {lc_data}")


def get_radoslist():
    """
    get radoslist of all buckets
    """
    cmd = "radosgw-admin bucket radoslist | grep -i ERROR"
    _, err = subprocess.getstatusoutput(cmd)
    if err:
        log.error(f"ERROR in radoslist command! {err}")
        get_bucket_stats()
    else:
        return True


def get_bucket_stats():
    """
    get bucket stats of all buckets
    """
    log.info("check bucket stats of all the buckets in the cluster")
    cmd = "radosgw-admin bucket stats| egrep -i 'error|ret=-'"
    _, err = subprocess.getstatusoutput(cmd)
    if err:
        raise TestExecError(f"bucket stats on all buckets failed! {err}")
    else:
        return True


def get_s3_client(access_key, secret_key, endpoint):
    """
    Returns s3 client
    """
    s3_conn_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url=endpoint,
    )
    return s3_conn_client


def is_bucket_exists(bucket_name, s3_conn_client):
    """
    Returns true if bucket exists in endpoint
    """
    bucket_resp = s3_conn_client.list_buckets()
    log.info(bucket_resp["Buckets"])
    bucket_list = [di["Name"] for di in bucket_resp["Buckets"]]
    return bucket_name in bucket_list


def get_object_list(bucket_name, s3_conn_client, prefix=None):
    """
    Returns object list for the given bucket
    """
    object_resp = s3_conn_client.list_objects(Bucket=bucket_name)
    log.info(object_resp)
    if "Contents" not in object_resp.keys():
        log.info("Objects do not exist in the bucket")
        return []
    object_list = [di["Key"] for di in object_resp["Contents"]]
    if prefix is not None:
        object_list_with_prefix = []
        for obj in object_list:
            if obj.startswith(prefix):
                object_list_with_prefix.append(obj)
        return object_list_with_prefix
    return object_list


def get_object_list_etag(bucket_name, s3_conn_client):
    """
    Returns object Key,Etag for the given bucket
    """
    object_resp = s3_conn_client.list_objects(Bucket=bucket_name)
    if "Contents" not in object_resp.keys():
        log.info("Objects do not exist in the bucket")
        return []
    object_dict = {}
    for di in object_resp["Contents"]:
        object_dict.update({di["Key"]: di["ETag"]})
    log.info(object_dict)
    return object_dict


def add_zonegroup_placement(
    storage_class=None,
    tier_type=None,
    rgw_zonegroup="default",
    placement_id="default-placement",
):
    """
    Adds zonegroup placement
    """
    command = (
        f"radosgw-admin zonegroup placement add --rgw-zonegroup={rgw_zonegroup}"
        f"--placement-id={placement_id} "
    )
    if storage_class:
        command += f"--storage-class={storage_class} "
    if tier_type:
        command += f"--tier-type={tier_type}"
    log.info("Executing command: %s" % command)
    utils.exec_shell_cmd(command)


def modify_zonegroup_placement(
    rgw_zonegroup="default",
    placement_id="default-placement",
    storage_class=None,
    tier_type=None,
    tier_config=None,
):
    """
    Modifies zonegroup placement
    """
    command = (
        f"radosgw-admin zonegroup placement modify --rgw-zonegroup={rgw_zonegroup}"
        f"--placement-id={placement_id} "
    )
    if storage_class:
        command += f"--storage-class={storage_class} "
    if tier_type:
        command += f"--tier-type={tier_type}"
    if tier_config:
        command += f"--tier-type={tier_config}"
    log.info("Executing command: %s" % command)
    utils.exec_shell_cmd(command)


def get_zg_endpoint_creds():
    """
    Returns zonegroup endpoint credentials
    """
    endpoint_details = {}
    command = "radosgw-admin zonegroup get"
    zg_details = json.loads(utils.exec_shell_cmd(command))
    s3_details = zg_details["placement_targets"][0]["tier_targets"][0]["val"]["s3"]
    log.info(s3_details)
    log.info(type(s3_details))
    endpoint_details["access_key"] = s3_details["access_key"]
    endpoint_details["secret_key"] = s3_details["secret"]
    endpoint_details["endpoint"] = s3_details["endpoint"]
    endpoint_details["bucket_name"] = s3_details["target_path"]
    return endpoint_details


def get_object_upload_type(s3_object_name, bucket, TEST_DATA_PATH, config, user_info):
    """
    choose or select type of object upload normal or multipart for an object.
    """
    log.info("get the object upload type: multipart or normal")
    if config.test_ops.get("upload_type") == "multipart":
        log.info("upload type: multipart")
        upload_mutipart_object(
            s3_object_name,
            bucket,
            TEST_DATA_PATH,
            config,
            user_info,
        )
    else:
        log.info("upload type: normal")
        upload_object(
            s3_object_name,
            bucket,
            TEST_DATA_PATH,
            config,
            user_info,
        )


def prepare_for_bucket_lc_transition(config):
    """
    This function is to set the prereqs for LC transiton testing

    Parameters:
        config(list): config
    """
    pool_name = config.pool_name
    storage_class = config.storage_class
    ec_pool_name = config.ec_pool_name
    ec_storage_class = config.ec_storage_class
    if config.ec_pool_transition:
        utils.exec_shell_cmd(
            f"radosgw-admin zonegroup placement add  --rgw-zonegroup default --placement-id default-placement --storage-class {ec_storage_class}"
        )
        utils.exec_shell_cmd(
            f"radosgw-admin zone placement add --rgw-zone default --placement-id default-placement --storage-class {ec_storage_class} --data-pool {ec_pool_name}"
        )
        utils.exec_shell_cmd(
            "ceph osd erasure-code-profile set rgwec01 k=4 m=2 crush-failure-domain=host crush-device-class=hdd"
        )
        utils.exec_shell_cmd(
            f"ceph osd pool create {ec_pool_name} 32 32 erasure rgwec01"
        )
        utils.exec_shell_cmd(f"ceph osd pool application enable {ec_pool_name} rgw")
    else:
        utils.exec_shell_cmd(
            f"radosgw-admin zonegroup placement add  --rgw-zonegroup default --placement-id default-placement --storage-class {storage_class}"
        )
        utils.exec_shell_cmd(
            f"radosgw-admin zone placement add --rgw-zone default --placement-id default-placement --storage-class {storage_class} --data-pool {pool_name}"
        )
        utils.exec_shell_cmd(f"ceph osd pool create {pool_name}")
        utils.exec_shell_cmd(f"ceph osd pool application enable {pool_name} rgw")
        if config.multiple_transitions:
            second_pool_name = config.second_pool_name
            second_storage_class = config.second_storage_class
            utils.exec_shell_cmd(f"ceph osd pool create {second_pool_name}")
            utils.exec_shell_cmd(
                f"ceph osd pool application enable {second_pool_name} rgw"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin zonegroup placement add  --rgw-zonegroup default --placement-id default-placement --storage-class {second_storage_class}"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin zone placement add --rgw-zone default --placement-id default-placement --storage-class {second_storage_class} --data-pool {second_pool_name}"
            )


def bucket_reshard_manual(bucket, config):
    cmd = utils.exec_shell_cmd(
        f"radosgw-admin bucket reshard --bucket {bucket.name} --num-shards {config.shards}"
    )
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    shards = json_doc["num_shards"]
    if shards == config.shards:
        log.info(f"num_shards for bucket {bucket.name} after reshard are {shards}")
    else:
        raise TestExecError(f"Bucket {bucket.name} not resharded to {config.shards}")
    verify_attrs_after_resharding(bucket)


def test_log_trimming(bucket, config):
    log.info("Choose the type of log trimming to test.")
    if config.log_trimming == "mdlog":
        period_op = json.loads(utils.exec_shell_cmd(f"radosgw-admin period get"))
        period_id = period_op["id"]
        cmd = f"radosgw-admin mdlog list --period {period_id}"
    elif config.log_trimming == "datalog":
        for i in range(0, 128):
            shard_id = i
            cmd = f"radosgw-admin datalog list --shard-id {shard_id}"
            output1 = json.loads(utils.exec_shell_cmd(cmd))
            if len(output1) > 0:
                break
    else:
        cmd = f"radosgw-admin bilog list --bucket {bucket.name}"

    output1 = json.loads(utils.exec_shell_cmd(cmd))
    if len(output1) > 0:
        log.info(f"{config.log_trimming} log is not empty")
    else:
        raise TestExecError(f"{config.log_trimming} log is empty")
    log.info("Sleep for log_trim_interval of 20mins")
    time.sleep(1260)
    output2 = json.loads(utils.exec_shell_cmd(cmd))
    if len(output2) == 0:
        log.info(f"{config.log_trimming} log is empty after the interval")
    else:
        raise TestExecError(
            f"{config.log_trimming} log is not empty after the interval"
        )
    if config.test_bilog_trim_on_non_existent_bucket:
        utils.exec_shell_cmd(
            f"radosgw-admin bucket rm --purge-objects --bucket {bucket.name}"
        )
        cmd = "radosgw-admin bilog trim --bucket {bucket.name} | egrep -i 'error|ret=-'"
        _, err = subprocess.getstatusoutput(cmd)
        if not err:
            raise TestExecError(
                f"Test failure, bilog trim should fail for a non-existent bucket with no such file or directory"
            )
        else:
            log.info(f"Bilog trim for a non-existent bucket fails with {err}")


def set_dynamic_reshard_ceph_conf(config, ssh_con):
    ceph_conf = CephConfOp(ssh_con)
    log.info("sharding type is dynamic. setting ceph conf parameters")
    time.sleep(15)
    log.info("making changes to ceph.conf")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_max_objs_per_shard,
        str(config.max_objects_per_shard),
        ssh_con,
    )

    ceph_conf.set_to_ceph_conf(
        "global", ConfigOpts.rgw_dynamic_resharding, "True", ssh_con
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_max_dynamic_shards,
        str(config.max_rgw_dynamic_shards),
        ssh_con,
    )

    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_reshard_thread_interval,
        str(config.rgw_reshard_thread_interval),
        ssh_con,
    )


def bucket_reshard_dynamic(bucket, config):
    # for dynamic,
    # the number of shards  should be greater than   [ (no of objects)/(max objects per shard) ]
    # example: objects = 500 ; max object per shard = 10
    # then no of shards should be at least 50 or more
    resharding_sleep_time = config.rgw_reshard_thread_interval
    log.info(
        "verification of dynamic resharding starts after waiting for reshard_thread_interval:"
        + f"{resharding_sleep_time} seconds"
    )
    time.sleep(resharding_sleep_time)

    num_shards_expected = config.objects_count / config.max_objects_per_shard
    log.info("num_shards_expected: %s" % num_shards_expected)
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket %s" % bucket.name)
    json_doc = json.loads(op)
    bucket_id = json_doc["id"]
    num_shards_created = json_doc["num_shards"]
    log.info("no_of_shards_created: %s" % num_shards_created)
    log.info("Verify if resharding list is empty")
    reshard_list_op = json.loads(utils.exec_shell_cmd("radosgw-admin reshard list"))
    if not reshard_list_op:
        log.info(
            "for dynamic number of shards created should be greater than or equal to number of expected shards"
        )
        log.info("no_of_shards_expected: %s" % num_shards_expected)
        if int(num_shards_created) >= int(num_shards_expected):
            log.info("Expected number of shards created")
        else:
            raise TestExecError("Expected number of shards not created")
    else:
        raise TestExecError("reshard list is still not empty")
    verify_attrs_after_resharding(bucket)


def verify_attrs_after_resharding(bucket):
    log.info("Test acls are preserved after a resharding operation.")
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    bucket_id = json_doc["id"]
    cmd = utils.exec_shell_cmd(
        f"radosgw-admin metadata get bucket.instance:{bucket.name}:{bucket_id}"
    )
    json_doc = json.loads(cmd)
    log.info("The attrs field should not be empty.")
    attrs = json_doc["data"]["attrs"][0]
    if not attrs["key"]:
        raise TestExecError("Acls lost after bucket resharding, test failure.")
    return True


def group_operation(group_id, group_op, group_status="enabled", bucket_name=None):
    if bucket_name is not None:
        bkt = f" --bucket={bucket_name}"
    else:
        bkt = ""
    cmd = (
        f"radosgw-admin sync group {group_op} --group-id={group_id} --status={group_status}"
        + bkt
    )
    utils.exec_shell_cmd(cmd)


def flow_operation(group_id, flow_op, flow_type="symmetrical"):
    flow_id = group_id + "flow"
    zone_names, _ = get_multisite_info()
    cmd = f"radosgw-admin sync group flow {flow_op} --group-id={group_id} --flow-id={flow_id} --flow-type={flow_type} --zones={zone_names}"
    utils.exec_shell_cmd(cmd)
    return zone_names


def pipe_operation(
    group_id, pipe_op, zone_names=None, bucket_name=None, policy_detail=None
):
    pipe_id = group_id + "pipe"
    if zone_names is not None:
        zone_name = zone_names.split(",")
        zn = f" --source-zones={zone_name[0]} --dest-zones={zone_name[1]}"
    else:
        zn = " --source-zones='*' --dest-zones='*'"
    if bucket_name is not None:
        bkt = f" --bucket={bucket_name}"
    else:
        bkt = ""

    cmd = (
        f"radosgw-admin sync group pipe {pipe_op} --group-id={group_id} --pipe-id={pipe_id}"
        + zn
        + bkt
    )
    if policy_detail is not None:
        cmd = cmd + policy_detail

    utils.exec_shell_cmd(cmd)
    update_commit()
    return pipe_id


def object_put_hold(client, body, bucket, key, LegalHold):
    # boto3 put object with object legal hold ON or OFF
    client.put_object(
        Body=body,
        Bucket=bucket,
        Key=key,
        ObjectLockLegalHoldStatus=LegalHold,
    )


def object_lock_retention(client, bucket, key, body, lock_mode, retain_until):
    # boto3 put object with retention policy set at object level
    client.put_object(
        Body=body,
        Bucket=bucket,
        Key=key,
        ObjectLockMode=lock_mode,
        ObjectLockRetainUntilDate=retain_until,
    )


def object_lock_put(client, bucket, lock_configuration):
    # boto3 put object lock configuration on bucket
    client.put_object_lock_configuration(
        Bucket=bucket, ObjectLockConfiguration=lock_configuration
    )
