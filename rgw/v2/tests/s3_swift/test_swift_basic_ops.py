"""
test_swift_basic_ops - Test swift operation on cluster

Usage: test_swift_basic_ops.py -c <input_yaml>

<input_yaml>
    Note: any one of these yamls can be used
    test_swift_basic_ops.yaml
    test_swift_versioning.yaml
    test_swift_version_copy_op.yaml
    test_swift_large_upload.yaml
    test_swift_large_download.yaml
    test_get_objects_from_tenant_swift_user.yaml
    test_delete_container_from_user_of_diff_tenant.yaml
    test_upload_large_obj_with_same_obj_name.yaml
    test_swift_enable_version_with_different_user.yaml
    test_s3_and_swift_versioning.yaml
    test_swift_user_access_read.yaml
    test_swift_user_access_write.yaml
    test_swift_user_access_readwrite.yaml
    test_swift_object_expire_op.yaml
    test_swift_at_root.yaml

Operation:
    Create swift user
    Create number of container specified in yaml file
    Create versioned container
    Upload objects in container
    Download uploaded objects from container
    Modify downloaded objects and re-upload it to the container
    Delete objects from container
    Get object from container
    Delete container
    Copy versioned object
    Multipart upload
    Functionality with swift user with read, write, readwrite access
"""

import glob

# test swift basic ops
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import string
import time
import traceback

import names
import requests
import v2.lib.manage_data as manage_data
import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from swiftclient import ClientException
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth as s3_auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3cmd import auth as s3cmd_auth
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()


TEST_DATA_PATH = None


# create user
# create subuser
# create container
# upload object
def fill_container(
    rgw,
    container_name,
    user_id,
    oc,
    cc,
    size,
    multipart=False,
    split_size=0,
    header=None,
    swift_object_name=None,
):
    if swift_object_name is None:
        swift_object_name = utils.gen_s3_object_name(f"{user_id}.container.{cc}", oc)
    log.info("object name: %s" % swift_object_name)
    object_path = os.path.join(TEST_DATA_PATH, swift_object_name)
    log.info("object path: %s" % object_path)
    data_info = manage_data.io_generator(object_path, size)
    # upload object
    if multipart == True:
        mp_dir = os.path.join(TEST_DATA_PATH, swift_object_name + ".mp.parts")
        log.info(f"mp part dir: {mp_dir}")
        log.info("making multipart object part dir")
        mkdir = utils.exec_shell_cmd("sudo mkdir %s" % mp_dir)
        if mkdir is False:
            raise TestExecError("mkdir failed creating mp_dir_name")
        utils.split_file(object_path, split_size, mp_dir + "/")
        parts_list = sorted(glob.glob(mp_dir + "/" + "*"))
        log.info("parts_list: %s" % parts_list)
        log.info("no of parts: %s" % len(parts_list))
        for each_part in parts_list:
            log.info("trying to upload part: %s" % each_part)
            with open(each_part, "r") as fp:
                etag = rgw.put_object(
                    container_name,
                    swift_object_name + "/" + each_part,
                    contents=fp.read(),
                    content_type="text/plain",
                    headers=header,
                )

        if config.local_file_delete is True:
            log.info("Remove local multipart object part dir")
            rmdir = utils.exec_shell_cmd(f"sudo rm -rf {mp_dir}")
            if rmdir is False:
                raise TestExecError(
                    f"Failed removing local multipart object part dir: {rmdir}"
                )

        return swift_object_name
    else:
        if data_info is False:
            raise TestExecError("data creation failed")
        log.info("uploading object: %s" % object_path)
        with open(object_path, "r") as fp:
            rgw.put_object(
                container_name,
                swift_object_name,
                contents=fp.read(),
                content_type="text/plain",
                headers=header,
            )
        return swift_object_name


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp(ssh_con)
    log.info(type(ceph_conf))
    rgw_service = RGWService()
    # preparing data
    user_name = names.get_first_name() + random.choice(string.ascii_letters)
    if config.user_type == "non-tenanted":
        users_info = []
        user_info = swiftlib.create_users(1)[-1]
        users_info.append(user_info)
        if config.test_ops.get("enable_version_by_s3", False):
            write_bucket_io_info = BucketIoInfo()
            auth_s3 = s3_auth(user_info, ssh_con, ssl=config.ssl)
            s3_rgw_conn = auth_s3.do_auth()
            ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
            s3cmd_auth.do_auth(user_info, ip_and_port)
        subuser_info = swiftlib.create_non_tenant_sub_users(1, user_info)
        auth = Auth(subuser_info[-1], ssh_con, config.ssl)
        rgw = auth.do_auth()
    else:
        tenants_user_info = []
        tenant = "tenant"
        tenant_user_info = umgmt.create_tenant_user(
            tenant_name=tenant, user_id=user_name, displayname=user_name
        )
        tenants_user_info.append(tenant_user_info)
        user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)
        auth = Auth(user_info, ssh_con, config.ssl)
        rgw = auth.do_auth()

    if config.test_ops.get("new_user", False):
        new_user_info = swiftlib.create_users(1)[-1]
        users_info.append(new_user_info)
        new_sub_user_info = swiftlib.create_non_tenant_sub_users(1, new_user_info)
        new_auth = Auth(new_sub_user_info[-1], ssh_con, config.ssl)
        rgw_client = new_auth.do_auth_using_client()

    if config.test_ops.get("new_tenant", False):
        new_tenant = "tenant" + random.choice(string.ascii_letters)
        new_tenant_info = umgmt.create_tenant_user(
            tenant_name=new_tenant, user_id=user_name, displayname=user_name
        )
        tenants_user_info.append(new_tenant_info)
        new_user_info = umgmt.create_subuser(tenant_name=new_tenant, user_id=user_name)
        new_auth = Auth(new_user_info, ssh_con, config.ssl)
        rgw_client = new_auth.do_auth_using_client()

    for cc in range(config.container_count):
        if config.version_enable is True:
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_versioning_enabled, "True", ssh_con
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
            container_name_old = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=str(cc) + "old"
            )
            log.info(container_name_old)
            container = swiftlib.resource_op(
                {
                    "obj": rgw,
                    "resource": "put_container",
                    "kwargs": dict(container=container_name_old),
                }
            )
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=str(cc) + "new"
            )
            log.info(container_name)
            container = swiftlib.resource_op(
                {
                    "obj": rgw,
                    "resource": "put_container",
                    "args": [
                        container_name,
                        {"X-Versions-Location": container_name_old},
                    ],
                }
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation failed"
                )
            ls = []
            swift_object_name = ""
            for version_count in range(config.version_count):
                for oc, size in list(config.mapped_sizes.items()):
                    swift_object_name = fill_container(
                        rgw, container_name, user_name, oc, cc, size
                    )
                ls = rgw.get_container(container_name_old)
                ls = list(ls)
            if config.copy_version_object is True:
                old_obj_name = ls[1][config.version_count - 2]["name"]
                log.info(old_obj_name)
                container = swiftlib.resource_op(
                    {
                        "obj": rgw,
                        "resource": "copy_object",
                        "kwargs": dict(
                            container=container_name_old,
                            obj=old_obj_name,
                            destination=container_name + "/" + swift_object_name,
                        ),
                    }
                )
                if container is False:
                    raise TestExecError("Resource execution failed")
                log.info("Successfully copied item")
            else:
                current_count = "radosgw-admin bucket stats --uid={uid} --tenant={tenant} --bucket='{bucket}' ".format(
                    uid=user_name, tenant=tenant, bucket=container_name
                )
                num_obj_current = utils.exec_shell_cmd(current_count)
                num_obj_current = json.loads(num_obj_current)
                ceph_version_id, _ = utils.get_ceph_version()
                ceph_version_id = ceph_version_id.split("-")
                ceph_version_id = ceph_version_id[0].split(".")
                num_objects_cur = (
                    num_obj_current
                    if float(ceph_version_id[0]) >= 19
                    else num_obj_current[0]
                )
                num_obj_current = (
                    num_objects_cur.get("usage").get("rgw.main").get("num_objects")
                )
                old_count = f"radosgw-admin bucket stats --uid={user_name} --tenant={tenant} --bucket='{container_name_old}'"
                num_obj_old = utils.exec_shell_cmd(old_count)
                num_obj_old = json.loads(num_obj_old)
                num_objects_old = (
                    num_obj_old if float(ceph_version_id[0]) >= 19 else num_obj_old[0]
                )
                num_obj_old = (
                    num_objects_old.get("usage").get("rgw.main").get("num_objects")
                )
                version_count_from_config = (
                    config.objects_count * config.version_count
                ) - config.objects_count
                if (num_obj_current == config.objects_count) and (
                    num_obj_old == version_count_from_config
                ):
                    log.info("objects and versioned obbjects are correct")
                else:
                    test_info.failed_status("test failed")

        elif config.test_ops.get("new_user", False):
            log.info("enabling swift versioning")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_versioning_enabled, "True", ssh_con
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=str(cc) + "_swift"
            )
            reusable.create_container_using_swift(container_name, rgw, user_info)
            new_container_name = utils.gen_bucket_name_from_userid(
                new_user_info["user_id"], rand_no=str(cc) + "_newswift"
            )
            reusable.create_container_using_swift(
                new_container_name, rgw_client, new_user_info
            )

            log.info(
                f"enable versioning on container {container_name} with subuser {new_user_info['user_id']}"
            )
            new_container = swiftlib.resource_op(
                {
                    "obj": rgw_client,
                    "resource": "post_container",
                    "args": [
                        container_name,
                        {"X-Versions-Location": new_container_name},
                    ],
                }
            )

            log.info(f"new_container {new_container}")
            if new_container:
                raise TestExecError(
                    f"enable versioning on container {container_name} with subuser {new_user_info['user_id']} should fail"
                )

        elif config.object_expire is True:
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=cc
            )
            container = swiftlib.resource_op(
                {"obj": rgw, "resource": "put_container", "args": [container_name]}
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation failed"
                )
            for oc, size in list(config.mapped_sizes.items()):
                swift_object_name = fill_container(
                    rgw,
                    container_name,
                    user_name,
                    oc,
                    cc,
                    size,
                    header={"X-Delete-After": 5},
                )
                time.sleep(7)
                container_exists = swiftlib.resource_op(
                    {
                        "obj": rgw,
                        "resource": "get_object",
                        "args": [container_name, swift_object_name],
                    }
                )
                log.info(container_exists)
                if container_exists:
                    msg = "test failed as the objects are still present"
                    test_info.failed_status(msg)
                    raise TestExecError(msg)

        elif config.large_object_upload is True:
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=cc
            )
            container = swiftlib.resource_op(
                {"obj": rgw, "resource": "put_container", "args": [container_name]}
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation failed"
                )
            for oc, size in list(config.mapped_sizes.items()):
                swift_object_name = fill_container(
                    rgw,
                    container_name,
                    user_name,
                    oc,
                    cc,
                    size,
                    multipart=True,
                    split_size=config.split_size,
                )
                container_name_new = utils.gen_bucket_name_from_userid(
                    user_info["user_id"], rand_no=str(cc) + "New"
                )
                container = swiftlib.resource_op(
                    {
                        "obj": rgw,
                        "resource": "put_container",
                        "kwargs": dict(container=container_name_new),
                    }
                )
                if container is False:
                    raise TestExecError(
                        "Resource execution failed: container creation failed"
                    )
                container = swiftlib.resource_op(
                    {
                        "obj": rgw,
                        "resource": "put_object",
                        "kwargs": dict(
                            container=container_name_new,
                            obj=swift_object_name,
                            contents=None,
                            headers={
                                "X-Object-Manifest": container_name
                                + "/"
                                + swift_object_name
                                + "/"
                            },
                        ),
                    }
                )
                if container is False:
                    raise TestExecError(
                        "Resource execution failed: container creation failed"
                    )
                if config.large_object_download is True:
                    swift_old_object_path = os.path.join(
                        TEST_DATA_PATH, swift_object_name
                    )
                    swift_object_download_fname = swift_object_name + ".download"
                    log.info("download object name: %s" % swift_object_download_fname)
                    swift_object_download_path = os.path.join(
                        TEST_DATA_PATH, swift_object_download_fname
                    )
                    log.info("download object path: %s" % swift_object_download_path)
                    swift_object_downloaded = rgw.get_object(
                        container_name_new, swift_object_name
                    )
                    with open(swift_object_download_path, "wb") as fp:
                        fp.write(swift_object_downloaded[1])
                    old_object = utils.get_md5(swift_old_object_path)
                    downloaded_obj = utils.get_md5(swift_object_download_path)
                    log.info("s3_object_downloaded_md5: %s" % old_object)
                    log.info("s3_object_uploaded_md5: %s" % downloaded_obj)
                    if str(old_object) == str(downloaded_obj):
                        log.info("md5 match")
                        utils.exec_shell_cmd("rm -rf %s" % swift_object_download_path)
                    else:
                        raise TestExecError("md5 mismatch")

        elif config.test_ops.get("create_container", False):
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=cc
            )
            container = swiftlib.resource_op(
                {"obj": rgw, "resource": "put_container", "args": [container_name]}
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation failed"
                )
            if config.test_ops.get("fill_container", False):
                for oc, size in list(config.mapped_sizes.items()):
                    if config.test_ops.get("upload_type") == "multipart":
                        swift_object_name = fill_container(
                            rgw,
                            container_name,
                            user_name,
                            oc,
                            cc,
                            size,
                            multipart=True,
                            split_size=config.split_size,
                        )
                    else:
                        swift_object_name = fill_container(
                            rgw,
                            container_name,
                            user_name,
                            oc,
                            cc,
                            size,
                        )

                    if config.test_ops.get(
                        "get_object_with_same_swift_tenant_user_under_diff_tenant",
                        False,
                    ):
                        log.info(
                            f"Get object {swift_object_name} with owner of container"
                        )
                        get_container_obj = swiftlib.resource_op(
                            {
                                "obj": rgw,
                                "resource": "get_object",
                                "args": [container_name, swift_object_name],
                            }
                        )
                        if get_container_obj is False:
                            raise TestExecError(
                                f"Get object failed for container owner: {get_container_obj}"
                            )
                        log.info(
                            f"Get object {swift_object_name} with different tenant of with same user {new_user_info}"
                        )
                        # Verify same user in different tenant not having permission for container can not get objects
                        try:
                            rgw_client.get_object(container_name, swift_object_name)
                            raise Exception(
                                f"{new_user_info['user_id']} user should not get objects in bucket: {container_name}"
                            )
                        except ClientException as e:
                            log.error(
                                f"Get object with different tenant of with same user failed as expected: {e}"
                            )

                    if config.test_ops.get(
                        "upload_another_large_object_with_same_name_with_diff_tenants",
                        False,
                    ):
                        log.info(
                            f"Upload large object {swift_object_name} again with container owner"
                        )
                        large_object_name = fill_container(
                            rgw,
                            container_name,
                            user_name,
                            oc,
                            cc,
                            size,
                            multipart=True,
                            split_size=config.split_size,
                            swift_object_name=swift_object_name,
                        )
                        if swift_object_name != large_object_name:
                            raise TestExecError(
                                f"Try Upload large object:{swift_object_name} twice failed, but uploaded {large_object_name}"
                            )

                        if config.test_ops.get("new_tenant", False):
                            log.info(
                                f"Upload large object:{large_object_name},  with different tenant user"
                            )
                            # Verify same user in different tenant not having permission for container can not upload objects
                            try:
                                upload_large_object = fill_container(
                                    rgw_client,
                                    container_name,
                                    user_name,
                                    oc,
                                    cc,
                                    size,
                                    multipart=True,
                                    split_size=config.split_size,
                                    swift_object_name=swift_object_name,
                                )
                                raise Exception(
                                    f"{new_user_info['user_id']} user should not upload objects to container:{container_name}"
                                )
                            except ClientException as e:
                                log.error(
                                    f"Upload large object with different tenant of with same user failed as expected: {e}"
                                )

            if config.test_ops.get(
                "delete_container_with_same_swift_tenant_user_under_diff_tenant", False
            ):
                if config.test_ops.get("fill_container", False):
                    headers, items = rgw.get_container(container_name)
                    for i in items:
                        rgw.delete_object(container_name, i["name"])

                log.info(
                    f"Delete container {container_name} with different tenant having same user name {new_user_info}"
                )
                # Verify same user in different tenant not having permission for deleting of container
                try:
                    rgw_client.delete_container(container_name)
                    raise Exception(
                        f"{new_user_info['user_id']} user should not be able to delete container: {container_name}"
                    )
                except ClientException as e:
                    log.error(
                        f"Delete container with different tenant tenant having same user name failed as expected: {e}"
                    )

                log.info(f"Delete container {container_name} with container owner")
                rgw.delete_container(container_name)

        elif config.test_ops.get("enable_version_by_s3", False):
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_versioning_enabled, "True", ssh_con
            )
            log.info("trying to restart services")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")

            bucket_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=cc
            )
            log.info(f"creating bucket {bucket_name} with s3 user")
            bucket = reusable.create_bucket(bucket_name, s3_rgw_conn, user_info)
            log.info("enable bucket version using s3 user")
            reusable.enable_versioning(
                bucket, s3_rgw_conn, user_info, write_bucket_io_info
            )
            utils.exec_shell_cmd(f"fallocate -l 4k obj4k")
            s3cmd = "/home/cephuser/venv/bin/s3cmd"
            range_val = f"1..{config.objects_count}"
            cmd = (
                "for i in {"
                + range_val
                + "}; do "
                + f"{s3cmd} put obj4k s3://{bucket_name}/object-$i; done"
            )
            rc = utils.exec_shell_cmd(cmd)
            if rc is False:
                raise AssertionError(
                    f"Failed to upload current object to bucket {bucket_name}"
                )

            response = utils.exec_shell_cmd(cmd)
            if response is False:
                raise AssertionError(
                    f"Failed to upload non-current object to bucket {bucket_name}"
                )

            resp = utils.exec_shell_cmd(f"{s3cmd} ls s3://{bucket_name} | wc -l")
            if int(resp) != config.objects_count:
                raise TestExecError(
                    f"enable versioning on bucket {bucket_name} success but object count miss match"
                )
            resp = json.loads(
                utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {bucket_name}"
                )
            )
            if resp["usage"]["rgw.main"]["num_objects"] != config.objects_count * 2:
                raise TestExecError(
                    f"enable versioning on bucket {bucket_name} success but object count miss match"
                )
            container_name = f"{bucket_name}-swift"
            reusable.create_container_using_swift(container_name, rgw, subuser_info[-1])

            log.info(f"enable versioning on bucket {bucket_name} with swift user")
            container = swiftlib.resource_op(
                {
                    "obj": rgw,
                    "resource": "put_container",
                    "args": [
                        bucket_name,
                        {"X-Versions-Location": container_name},
                    ],
                }
            )
            log.info(f"container {container}")
            if container is False:
                raise TestExecError(
                    f"enable versioning on bucket {bucket_name} with swift user failed"
                )

        elif config.test_ops.get("check_user_permission", False):
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_versioning_enabled, "True", ssh_con
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
            container_name_old = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no="1" + "old"
            )
            log.info(container_name_old)
            container = swiftlib.resource_op(
                {
                    "obj": rgw,
                    "resource": "put_container",
                    "kwargs": dict(container=container_name_old),
                }
            )

            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no="1" + "new"
            )
            log.info(f"container_name is {container_name}")
            container = swiftlib.resource_op(
                {
                    "obj": rgw,
                    "resource": "put_container",
                    "args": [
                        container_name,
                        {"X-Versions-Location": container_name_old},
                    ],
                }
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation failed"
                )
            ls = []
            swift_object_name = ""
            for version_count in range(config.version_count):
                for oc, size in list(config.mapped_sizes.items()):
                    swift_object_name = fill_container(
                        rgw, container_name, user_name, oc, 1, size
                    )
                    log.info(f"swift_object_name: {swift_object_name}")
                log.info(f"performing get container")
                ls = rgw.get_container(container_name)
                ls = list(ls)
                log.info(f"Get container data is {ls}")

            log.info("Validating container behavior with user permission")
            cmd = (
                f"radosgw-admin subuser modify --uid {user_info['user_id']} --subuser={subuser_info[-1]['user_id']}"
                f" --access={config.test_ops.get('access')}"
            )
            utils.exec_shell_cmd(cmd)

            # Sub user with read permission
            if config.test_ops.get("access", "full") == "read":
                log.info("Validating user permission read")
                for oc, size in list(config.mapped_sizes.items()):
                    try:
                        swift_object_name = fill_container(
                            rgw, container_name, user_name, oc, 2, size
                        )
                        raise AssertionError(
                            "Should not allow to write content since permission is read"
                        )
                    except Exception as e:
                        logging.info("PUT Error as expected since permission is read")

                try:
                    ls = rgw.get_container(container_name)
                    log.info(f"Get container succeeded with read permission :{ls}")
                except Exception as e:
                    logging.info("Should not fail since permission is read")
                    raise AssertionError("Should not fail since permission is read")

            # Sub user with write permission
            if config.test_ops.get("access", "full") == "write":
                log.info("Validating user permission write")
                for oc, size in list(config.mapped_sizes.items()):
                    try:
                        swift_object_name = fill_container(
                            rgw, container_name, user_name, oc, 3, size
                        )
                        log.info(f"PUT operation succeeded with write permission ")
                    except Exception as e:
                        raise AssertionError(
                            "Should not fail to write content since permission is write"
                        )
                try:
                    ls = rgw.get_container(container_name)
                    raise AssertionError(
                        "GET operation Should fail since permission is write"
                    )
                except Exception as e:
                    logging.info("GET Error as expected since permission is write")

            # Sub user with readwrite permission
            if config.test_ops.get("access", "full") == "readwrite":
                log.info("Validating user permission readwrite")
                for oc, size in list(config.mapped_sizes.items()):
                    try:
                        swift_object_name = fill_container(
                            rgw, container_name, user_name, oc, 4, size
                        )
                        log.info("PUT operation succeeded with readwrite permission")
                    except Exception as e:
                        raise AssertionError(
                            "Should not fail to write content since permission is readwrite"
                        )
                try:
                    ls = rgw.get_container(container_name)
                    log.info("GET operation succeeded with readwrite permission")
                except Exception as e:
                    raise AssertionError(
                        "Should not fail to write content since permission is readwrite"
                    )

        elif config.test_ops.get("swift_at_root", False):
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_url_prefix, "/", ssh_con
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
            log.info("Check the swift url works at root")
            ip_and_port = rgw.authurl.split("/")[2]
            proto = "https" if config.ssl else "http"
            url = f"{proto}://{ip_and_port}/"

            log.info("Check swift /info")
            response = requests.get(f"{url}/info")
            if response.status_code == 200:
                log.info(f"{response.text}")
            else:
                raise TestExecError(
                    f"Swift at root /info not working: {response.status_code}"
                )

            log.info("Check swift /crossdomain.xml")
            response = requests.get(f"{url}/crossdomain.xml")
            if response.status_code == 200:
                log.info(f"{response.text}")
            else:
                raise TestExecError(
                    f"Swift at root /crossdomain not working: {response.status_code}"
                )

            log.info("Check swift /healthcheck")
            response = requests.get(f"{url}/healthcheck")
            if response.status_code == 200:
                log.info(f"{response.text}")
            else:
                raise TestExecError(
                    f"Swift at root /healthcheck not working: {response.status_code}"
                )
            log.info("With swift at root set, S3 access should fail")
            bucket_name_to_create = "test_bucket"
            auth_s3 = s3_auth(user_info, ssh_con, ssl=config.ssl)
            s3_rgw_conn = auth_s3.do_auth()
            try:
                bucket = reusable.create_bucket(
                    bucket_name_to_create, s3_rgw_conn, user_info
                )
            except Exception as e:
                log.info(f"Bucket creation failed as expected with {e}")
            else:
                raise TestExecError("Bucket creation succeeded")
            log.info("Unsetting the swift at root config option")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_url_prefix, "\ ", ssh_con
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)

        else:
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=cc
            )
            container = swiftlib.resource_op(
                {"obj": rgw, "resource": "put_container", "args": [container_name]}
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation failed"
                )
            for oc, size in list(config.mapped_sizes.items()):
                swift_object_name = fill_container(
                    rgw, container_name, user_name, oc, cc, size
                )
                # download object
                swift_object_download_fname = swift_object_name + ".download"
                log.info("download object name: %s" % swift_object_download_fname)
                swift_object_download_path = os.path.join(
                    TEST_DATA_PATH, swift_object_download_fname
                )
                log.info("download object path: %s" % swift_object_download_path)
                swift_object_downloaded = rgw.get_object(
                    container_name, swift_object_name
                )
                with open(swift_object_download_path, "w") as fp:
                    fp.write(str(swift_object_downloaded[1]))
                # modify and re-upload
                log.info("appending new message to test_data")
                message_to_append = "adding new msg after download"
                fp = open(swift_object_download_path, "a+")
                fp.write(message_to_append)
                fp.close()
                with open(swift_object_download_path, "r") as fp:
                    rgw.put_object(
                        container_name,
                        swift_object_name,
                        contents=fp.read(),
                        content_type="text/plain",
                    )
                # delete object
                log.info("deleting swift object")
                rgw.delete_object(container_name, swift_object_name)
            # delete container
            log.info("deleting swift container")
            rgw.delete_container(container_name)

    if config.user_type == "non-tenanted":
        for user in users_info:
            reusable.remove_user(user)
    else:
        for tuser in tenants_user_info:
            reusable.remove_user(tuser, tenant=tuser["tenant"])

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test swift user key gen")

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
