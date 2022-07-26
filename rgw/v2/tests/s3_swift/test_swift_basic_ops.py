"""
test_swift_basic_ops - Test swift operation on cluster

Usage: test_swift_basic_ops.py -c <input_yaml>

<input_yaml>
    Note: any one of these yamls can be used
    test_swift_basic_ops.yaml
    test_swift_versioning.yaml
    test_swift_version_copy_op.yaml
    test_swift_large_upload.yaml

Operation:
    Create swift user
    Create number of container specified in yaml file
    Create versioned container
    Upload objects in container
    Download uploaded objects from container
    Modify downloaded objects and re-upload it to the container
    Delete objects from container
    Delete container
    Copy versioned object
    Multipart upload
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
import v2.lib.manage_data as manage_data
import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

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
):
    swift_object_name = utils.gen_s3_object_name("%s.container.%s" % (user_id, cc), oc)
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


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    log.info(type(ceph_conf))
    rgw_service = RGWService()
    # preparing data
    user_name = names.get_first_name() + random.choice(string.ascii_letters)
    tenant = "tenant"
    tenant_user_info = umgmt.create_tenant_user(
        tenant_name=tenant, user_id=user_name, displayname=user_name
    )
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)
    auth = Auth(user_info, config.ssl)
    rgw = auth.do_auth()

    for cc in range(config.container_count):
        if config.version_enable is True:
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_swift_versioning_enabled, "True"
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart()
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
                num_obj_current = (
                    num_obj_current[0].get("usage").get("rgw.main").get("num_objects")
                )
                old_count = "radosgw-admin bucket stats --uid={uid} --tenant={tenant} --bucket='{bucket}' ".format(
                    uid=user_name, tenant=tenant, bucket=container_name_old
                )
                num_obj_old = utils.exec_shell_cmd(old_count)
                num_obj_old = json.loads(num_obj_old)
                num_obj_old = (
                    num_obj_old[0].get("usage").get("rgw.main").get("num_objects")
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

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")
    reusable.remove_user(tenant_user_info, tenant=tenant)


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
        args = parser.parse_args()
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read()
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
