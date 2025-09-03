""" test_versioning_with_objects - Tests versioned and non-versionsed buckets.

Usage: test_versioning_with_objects.py -c <input_yaml>

<input_yaml>
	Note: Any one of these yamls can be used
	test_versioning_objects_copy.yaml
	test_versioning_objects_delete.yaml
	test_versioning_objects_delete_from_another_user.yaml
	test_versioning_objects_enable.yaml
	test_versioning_objects_suspend.yaml
	test_versioning_objects_suspend_from_another_user.yaml
	test_versioning_objects_suspend_re-upload.yaml
	test_versioning_suspend.yaml
	test_versioning_objects_suspended_delete.yaml
Operation:
	Create a bucket and enable versioning. Verify object versioning after copy operation 
	Create a bucket and enable versioning. Verify deletion of versioned objects succeeds
	Create a bucket and enable versioning. Verify deletion of versioned objects does not succeed from another user.
	Create a bucket and enable versioning. Verify versioning is enabled on the bucket.	
	Create a bucket and enable versioning. Suspend versioning. Verify versioning is suspended.
	Create a bucket and enable versioning. Verfiy versioning is not suspended from another user.
	Create a bucket and enable versioning. Verify versions are not created after versioning.
	Create a bucket and enable versioning. Verify versioning is suspended on the bucket.
	Create a bucket and enable versioning. Verify versioning is suspended on the bucket verify delete.
"""
# test basic bucket versioning with objects
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import traceback

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import (
    BasicIOInfoStructure,
    BucketIoInfo,
    IOInfoInitialize,
    KeyIoInfo,
)
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser

log = logging.getLogger()

TEST_DATA_PATH = None

VERSIONING_STATUS = {
    "ENABLED": "enabled",
    "DISABLED": "disabled",
    "SUSPENDED": "suspended",
}


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    write_key_io_info = KeyIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    extra_user = s3lib.create_users(1)[0]
    extra_user_auth = reusable.get_auth(extra_user, ssh_con, config.ssl, config.haproxy)
    extra_user_conn = extra_user_auth.do_auth()
    for each_user in all_users_info:
        # authenticate
        auth = reusable.get_auth(each_user, ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        s3_object_names = []
        # create buckets
        log.info("no of buckets to create: %s" % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            log.info("creating bucket with name: %s" % bucket_name_to_create)
            # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)
            bucket = reusable.create_bucket(
                bucket_name_to_create, rgw_conn, each_user, ip_and_port
            )
            # getting bucket version object
            if config.test_ops["enable_version"] is True:
                log.info("bucket versioning test on bucket: %s" % bucket.name)
                # bucket_versioning = s3_ops.resource_op(rgw_conn, 'BucketVersioning', bucket.name)
                bucket_versioning = s3lib.resource_op(
                    {
                        "obj": rgw_conn,
                        "resource": "BucketVersioning",
                        "args": [bucket.name],
                    }
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
                    {
                        "obj": bucket_versioning,
                        "resource": "enable",
                        "args": None,
                    }
                )
                response = HttpResponseParser(version_enable_status)
                if response.status_code == 200:
                    log.info("version enabled")
                    write_bucket_io_info.add_versioning_status(
                        each_user["access_key"],
                        bucket.name,
                        VERSIONING_STATUS["ENABLED"],
                    )

                else:
                    raise TestExecError("version enable failed")
                if config.objects_count > 0:
                    log.info("s3 objects to create: %s" % config.objects_count)
                    for oc, s3_object_size in list(config.mapped_sizes.items()):
                        # versioning upload
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, str(oc)
                        )
                        s3_object_names.append(s3_object_name)
                        log.info("s3 object name: %s" % s3_object_name)
                        log.info("versioning count: %s" % config.version_count)
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, str(oc)
                        )
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        original_data_info = manage_data.io_generator(
                            s3_object_path, s3_object_size
                        )
                        if original_data_info is False:
                            TestExecError("data creation failed")
                        created_versions_count = 0
                        md5_dict = {}
                        for vc in range(config.version_count):
                            log.info(
                                "version count for %s is %s" % (s3_object_name, str(vc))
                            )
                            log.info("modifying data: %s" % s3_object_name)
                            modified_data_info = manage_data.io_generator(
                                s3_object_path,
                                s3_object_size,
                                op="append",
                                **{"message": "\nhello for version: %s\n" % str(vc)},
                            )
                            if modified_data_info is False:
                                TestExecError("data modification failed")
                            log.info("uploading s3 object: %s" % s3_object_path)
                            upload_info = dict(
                                {
                                    "access_key": each_user["access_key"],
                                    "versioning_status": VERSIONING_STATUS["ENABLED"],
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
                                raise TestExecError(
                                    "Resource execution failed: object upload failed"
                                )
                            if object_uploaded_status is None:
                                log.info("object uploaded")
                                s3_obj = rgw_conn.Object(bucket.name, s3_object_name)
                                log.info("current_version_id: %s" % s3_obj.version_id)
                                key_version_info = basic_io_structure.version_info(
                                    **{
                                        "version_id": s3_obj.version_id,
                                        "md5_local": upload_info["md5"],
                                        "count_no": vc,
                                        "size": upload_info["size"],
                                    }
                                )
                                log.info("key_version_info: %s" % key_version_info)
                                write_key_io_info.add_versioning_info(
                                    each_user["access_key"],
                                    bucket.name,
                                    s3_object_path,
                                    key_version_info,
                                )
                                created_versions_count += 1
                                log.info(
                                    "created_versions_count: %s"
                                    % created_versions_count
                                )
                                log.info("adding metadata")
                                metadata1 = {
                                    "m_data1": "this is the meta1 for this obj"
                                }
                                s3_obj.metadata.update(metadata1)
                                metadata2 = {
                                    "m_data2": "this is the meta2 for this obj"
                                }
                                s3_obj.metadata.update(metadata2)
                                log.info(
                                    "metadata for this object: %s" % s3_obj.metadata
                                )
                                log.info(
                                    "metadata count for object: %s"
                                    % (len(s3_obj.metadata))
                                )
                                if not s3_obj.metadata:
                                    raise TestExecError(
                                        "metadata not created even adding metadata"
                                    )
                                versions = bucket.object_versions.filter(
                                    Prefix=s3_object_name
                                )
                                created_versions_count_from_s3 = len(
                                    [v.version_id for v in versions]
                                )
                                log.info(
                                    "created versions count on s3: %s"
                                    % created_versions_count_from_s3
                                )
                                if (
                                    created_versions_count
                                    is created_versions_count_from_s3
                                ):
                                    log.info(
                                        "no new versions are created when added metdata"
                                    )
                                else:
                                    raise TestExecError(
                                        "version count missmatch, "
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
                                raise TestExecError(
                                    "Resource execution failed: object download failed"
                                )
                            if object_downloaded_status is None:
                                log.info("object downloaded")
                            # checking md5 of the downloaded file
                            s3_object_downloaded_md5 = utils.get_md5(
                                s3_object_download_path
                            )
                            log.info("downloaded_md5: %s" % s3_object_downloaded_md5)
                            log.info("uploaded_md5: %s" % modified_data_info["md5"])
                            md5_dict[s3_obj.version_id] = modified_data_info["md5"]
                            log.info(f"md5_dict: {md5_dict}")
                            # tail_op = utils.exec_shell_cmd('tail -l %s' % s3_object_download_path)
                        log.info("all versions for the object: %s\n" % s3_object_name)
                        versions = bucket.object_versions.filter(Prefix=s3_object_name)
                        for version in versions:
                            log.info(
                                "key_name: %s --> version_id: %s"
                                % (version.object_key, version.version_id)
                            )
                        if (
                            config.test_ops.get("access_versioned_object", False)
                            is True
                        ):
                            versions = bucket.object_versions.filter(
                                Prefix=s3_object_name
                            )
                            for version in versions:
                                version_id = version.version_id
                                log.info(
                                    f"downloading {version_id}: version of object {s3_object_name}"
                                )
                                s3_ver_object_download_path = os.path.join(
                                    TEST_DATA_PATH,
                                    s3_object_name + version_id + ".download",
                                )
                                object_ver_downloaded_status = s3lib.resource_op(
                                    {
                                        "obj": bucket,
                                        "resource": "download_file",
                                        "args": [
                                            s3_object_name,
                                            s3_ver_object_download_path,
                                            {"VersionId": version_id},
                                        ],
                                    }
                                )
                                if object_ver_downloaded_status is False:
                                    raise TestExecError(
                                        "Resource execution failed: object download failed"
                                    )
                                if object_ver_downloaded_status is None:
                                    log.info("object downloaded")
                                    log.info(
                                        f"downloaded path: {s3_ver_object_download_path}"
                                    )
                                    s3_object_downloaded_md5 = utils.get_md5(
                                        s3_ver_object_download_path
                                    )
                                    log.info(
                                        f"downloaded_md5 for version-id {version_id} is {s3_object_downloaded_md5}"
                                    )
                                    if s3_object_downloaded_md5 != md5_dict[version_id]:
                                        raise AssertionError(
                                            f"MD5 mismatched for the object version:{version_id}"
                                        )
                                    else:
                                        log.info(
                                            f"MD5 matched for the object version:{version_id}"
                                        )

                        if config.test_ops.get("set_acl", None) is True:
                            s3_obj_acl = s3lib.resource_op(
                                {
                                    "obj": rgw_conn,
                                    "resource": "ObjectAcl",
                                    "args": [bucket.name, s3_object_name],
                                }
                            )
                            # setting acl to private, just need to set to any acl and
                            # check if its set - check by response code
                            acls_set_status = s3_obj_acl.put(ACL="private")
                            response = HttpResponseParser(acls_set_status)
                            if response.status_code == 200:
                                log.info("ACLs set")
                            else:
                                raise TestExecError("Acls not Set")
                            # get obj details based on version id
                            for version in versions:
                                log.info(
                                    "getting info for version id: %s"
                                    % version.version_id
                                )
                                obj = s3lib.resource_op(
                                    {
                                        "obj": rgw_conn,
                                        "resource": "Object",
                                        "args": [bucket.name, s3_object_name],
                                    }
                                )
                                log.info(
                                    "obj get details :%s\n"
                                    % (obj.get(VersionId=version.version_id))
                                )
                        if config.test_ops["copy_to_version"] is True:
                            # reverting object to one of the versions ( randomly chosen )
                            version_id_to_copy = random.choice(
                                [v.version_id for v in versions]
                            )
                            log.info("version_id_to_copy: %s" % version_id_to_copy)
                            s3_obj = rgw_conn.Object(bucket.name, s3_object_name)
                            log.info("current version_id: %s" % s3_obj.version_id)
                            copy_response = s3_obj.copy_from(
                                CopySource={
                                    "Bucket": bucket.name,
                                    "Key": s3_object_name,
                                    "VersionId": version_id_to_copy,
                                }
                            )
                            log.info("copy_response: %s" % copy_response)
                            if copy_response is None:
                                raise TestExecError(
                                    "copy object from version id failed"
                                )
                            # current_version_id = copy_response['VersionID']
                            log.info("current_version_id: %s" % s3_obj.version_id)
                            # delete the version_id_to_copy object
                            s3_obj.delete(VersionId=version_id_to_copy)
                            log.info(
                                "all versions for the object after the copy operation: %s\n"
                                % s3_object_name
                            )
                            for version in versions:
                                log.info(
                                    "key_name: %s --> version_id: %s"
                                    % (version.object_key, version.version_id)
                                )
                            # log.info('downloading current s3object: %s' % s3_object_name)
                            # s3_obj.download_file(s3_object_name + ".download")
                        if config.delete_object_current_versions:
                            log.info("deleting current version of s3_obj")
                            s3_obj = s3lib.resource_op(
                                {
                                    "obj": rgw_conn,
                                    "resource": "Object",
                                    "args": [bucket.name, s3_object_name],
                                }
                            )
                            version_ids = []
                            all_versions = bucket.object_versions.filter(
                                Prefix=s3_object_name
                            )
                            for ver in all_versions:
                                version_ids.append(ver.version_id)
                            current_version_id = s3_obj.version_id
                            log.info(f"all old versions {version_ids}")
                            log.info(f"current_version_id:{current_version_id}")
                            log.info(
                                f"deleting current version for s3 obj:{s3_object_name}"
                            )
                            del_obj_curr_version = s3lib.resource_op(
                                {
                                    "obj": s3_obj,
                                    "resource": "delete",
                                    "kwargs": dict(VersionId=current_version_id),
                                }
                            )
                            if del_obj_curr_version is None:
                                raise AssertionError(
                                    "current version deletion failed for version-id {current_version_id}"
                                )
                            s3_obj = s3lib.resource_op(
                                {
                                    "obj": rgw_conn,
                                    "resource": "Object",
                                    "args": [bucket.name, s3_object_name],
                                }
                            )
                            new_current_version_id = s3_obj.version_id
                            all_new_versions = bucket.object_versions.filter(
                                Prefix=s3_object_name
                            )
                            new_version_ids = []
                            for ver in all_new_versions:
                                new_version_ids.append(ver.version_id)
                            log.info(
                                f"new current_version_id: {new_current_version_id}"
                            )
                            log.info(f"all new versions {new_version_ids}")
                            if current_version_id == new_current_version_id:
                                raise AssertionError(
                                    "current version deletion failed for version-id {current_version_id}"
                                )
                            version_ids.remove(current_version_id)
                            for ver in version_ids:
                                if ver not in new_version_ids:
                                    raise AssertionError(
                                        "older version of object is not present!!"
                                    )

                        if config.test_ops["delete_object_versions"] is True:
                            log.info("deleting s3_obj keys and its versions")
                            s3_obj = s3lib.resource_op(
                                {
                                    "obj": rgw_conn,
                                    "resource": "Object",
                                    "args": [bucket.name, s3_object_name],
                                }
                            )
                            log.info(
                                "deleting versions for s3 obj: %s" % s3_object_name
                            )
                            for version in versions:
                                log.info(
                                    "trying to delete obj version: %s"
                                    % version.version_id
                                )
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
                                        reusable.delete_version_object(
                                            bucket,
                                            version.version_id,
                                            s3_object_path,
                                            rgw_conn,
                                            each_user,
                                        )
                                    else:
                                        raise TestExecError("version  deletion failed")
                                else:
                                    raise TestExecError("version deletion failed")
                            log.info("available versions for the object")
                            versions = bucket.object_versions.filter(
                                Prefix=s3_object_name
                            )
                            for version in versions:
                                log.info(
                                    "key_name: %s --> version_id: %s"
                                    % (version.object_key, version.version_id)
                                )
                        if config.test_ops.get("delete_from_extra_user") is True:
                            log.info("trying to delete objects from extra user")
                            s3_obj = s3lib.resource_op(
                                {
                                    "obj": extra_user_conn,
                                    "resource": "Object",
                                    "args": [bucket.name, s3_object_name],
                                }
                            )
                            log.info(
                                "deleting versions for s3 obj: %s" % s3_object_name
                            )
                            for version in versions:
                                log.info(
                                    "trying to delete obj version: %s"
                                    % version.version_id
                                )
                                del_obj_version = s3lib.resource_op(
                                    {
                                        "obj": s3_obj,
                                        "resource": "delete",
                                        "kwargs": dict(VersionId=version.version_id),
                                    }
                                )
                                log.info("response:\n%s" % del_obj_version)
                                if del_obj_version is not False:
                                    response = HttpResponseParser(del_obj_version)
                                    if response.status_code == 204:
                                        log.info("version deleted ")
                                        write_key_io_info.delete_version_info(
                                            each_user["access_key"],
                                            bucket.name,
                                            s3_object_path,
                                            version.version_id,
                                        )
                                        raise TestExecError(
                                            "version and deleted, this should not happen"
                                        )
                                    else:
                                        log.info(
                                            "version did not delete, expected behaviour"
                                        )
                                else:
                                    log.info(
                                        "version did not delete, expected behaviour"
                                    )
                        if config.local_file_delete is True:
                            log.info("deleting local file")
                            utils.exec_shell_cmd("sudo rm -rf %s" % s3_object_path)
                if config.test_ops["suspend_version"] is True:
                    log.info("suspending versioning")
                    # suspend_version_status = s3_ops.resource_op(bucket_versioning, 'suspend')
                    suspend_version_status = s3lib.resource_op(
                        {"obj": bucket_versioning, "resource": "suspend", "args": None}
                    )
                    response = HttpResponseParser(suspend_version_status)
                    if response.status_code == 200:
                        log.info("versioning suspended")
                        write_bucket_io_info.add_versioning_status(
                            each_user["access_key"],
                            bucket.name,
                            VERSIONING_STATUS["SUSPENDED"],
                        )
                        if config.test_versioning_archive:
                            zone_name = "archive"
                            arc_site_ip = utils.get_rgw_ip_zone(zone_name)
                            log.info(f"arc_site_ip s {arc_site_ip}")
                            arc_site_ssh_con = utils.connect_remote(arc_site_ip)
                            bucket_id = json.loads(
                                utils.exec_shell_cmd(
                                    f"radosgw-admin bucket stats --bucket {bucket_name_to_create}"
                                )
                            )["id"]
                            cmd_arc_metadata = f"radosgw-admin metadata get --metadata-key bucket.instance:{bucket_name_to_create}:{bucket_id}"
                            stdin, stdout, stderr = arc_site_ssh_con.exec_command(
                                cmd_arc_metadata
                            )
                            metadata_bucket_get = json.loads(stdout.read().decode())
                            log.info(
                                f"Metadata for the bucket {bucket_name_to_create} is {metadata_bucket_get}"
                            )
                            log.info(
                                "Check the value of flag, it should be 2 for version enabled buckets"
                            )
                            if metadata_bucket_get["data"]["bucket_info"]["flags"] != 2:
                                raise TestExecError(
                                    "versioning suspended at archive, test failed"
                                )

                    else:
                        raise TestExecError("version suspend failed")
                    # getting all objects in the bucket
                    log.info("getting all objects in the bucket")
                    objects = s3lib.resource_op(
                        {"obj": bucket, "resource": "objects", "args": None}
                    )
                    log.info("objects :%s" % objects)
                    all_objects = s3lib.resource_op(
                        {"obj": objects, "resource": "all", "args": None}
                    )
                    log.info("all objects: %s" % all_objects)
                    log.info("all objects2 :%s " % bucket.objects.all())
                    for obj in all_objects:
                        log.info("object_name: %s" % obj.key)
                        versions = bucket.object_versions.filter(Prefix=obj.key)
                        log.info("displaying all versions of the object")
                        for version in versions:
                            log.info(
                                "key_name: %s --> version_id: %s"
                                % (version.object_key, version.version_id)
                            )
                    if config.test_ops.get("delete_after_suspend") is True:
                        log.info("Deleting after suspending versioning on bucket")
                        s3_obj = s3lib.resource_op(
                            {
                                "obj": rgw_conn,
                                "resource": "Object",
                                "args": [bucket.name, s3_object_name],
                            }
                        )
                        for version in versions:
                            log.info("Deleting obj version: %s" % version.version_id)
                            del_obj_version = s3lib.resource_op(
                                {
                                    "obj": s3_obj,
                                    "resource": "delete",
                                    "kwargs": dict(VersionId=version.version_id),
                                }
                            )
                            log.info("response:\n%s" % del_obj_version)
                            if del_obj_version:
                                response = HttpResponseParser(del_obj_version)
                                if response.status_code == 204:
                                    log.info(
                                        "Bucket is suspended and version was deleted which is expected"
                                    )
                                else:
                                    raise TestExecError(
                                        "Bucket is suspended and the version did not delete which is not expected"
                                    )
                            else:
                                raise TestExecError("The version did not delete")
                if config.test_ops.get("suspend_from_extra_user") is True:
                    log.info("suspending versioning from extra user")
                    # suspend_version_status = s3_ops.resource_op(bucket_versioning, 'suspend')

                    bucket_versioning = s3lib.resource_op(
                        {
                            "obj": extra_user_conn,
                            "resource": "BucketVersioning",
                            "args": [bucket.name],
                        }
                    )

                    suspend_version_status = s3lib.resource_op(
                        {"obj": bucket_versioning, "resource": "suspend", "args": None}
                    )
                    if suspend_version_status is not False:
                        response = HttpResponseParser(suspend_version_status)
                        if response.status_code == 200:
                            log.info("versioning suspended")
                            write_bucket_io_info.add_versioning_status(
                                each_user["access_key"],
                                bucket.name,
                                VERSIONING_STATUS["SUSPENDED"],
                            )
                            raise TestExecError(
                                "version suspended, this should not happen"
                            )
                    else:
                        log.info("versioning not suspended, expected behaviour")
            if config.test_ops.get("upload_after_suspend") is True:
                log.info("trying to upload after suspending versioning on bucket")
                for oc, s3_object_size in list(config.mapped_sizes.items()):
                    # non versioning upload
                    s3_object_name = s3_object_names[oc] + ".after_version_suspending"
                    log.info("s3 object name: %s" % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    non_version_data_info = manage_data.io_generator(
                        s3_object_path,
                        s3_object_size,
                        op="append",
                        **{"message": "\nhello for non version\n"},
                    )
                    if non_version_data_info is False:
                        TestExecError("data creation failed")
                    log.info("uploading s3 object: %s" % s3_object_path)
                    upload_info = dict(
                        {
                            "access_key": each_user["access_key"],
                            "versioning_status": "suspended",
                        },
                        **non_version_data_info,
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
                            "args": [non_version_data_info["name"]],
                            "extra_info": upload_info,
                        }
                    )

                    if object_uploaded_status is False:
                        raise TestExecError(
                            "Resource execution failed: object upload failed"
                        )
                    if object_uploaded_status is None:
                        log.info("object uploaded")
                    s3_obj = s3lib.resource_op(
                        {
                            "obj": rgw_conn,
                            "resource": "Object",
                            "args": [bucket.name, s3_object_name],
                        }
                    )
                    log.info("version_id: %s" % s3_obj.version_id)
                    if s3_obj.version_id is None:
                        log.info("Versions are not created after suspending")
                    else:
                        raise TestExecError(
                            "Versions are created even after suspending"
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
                        raise TestExecError(
                            "Resource execution failed: object download failed"
                        )
                    if object_downloaded_status is None:
                        log.info("object downloaded")
                    # checking md5 of the downloaded file
                    s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
                    log.info("s3_object_downloaded_md5: %s" % s3_object_downloaded_md5)
                    log.info(
                        "s3_object_uploaded_md5: %s" % non_version_data_info["md5"]
                    )
                    if config.local_file_delete is True:
                        utils.exec_shell_cmd("sudo rm -rf %s" % s3_object_path)
            if config.test_ops.get("delete_bucket") is True:
                reusable.delete_bucket(bucket)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("test versioning with objects")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)

        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW S3 Automation")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
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
