# test basic creation of buckets with objects
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import traceback

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as swiftlib
import v2.utils.log as log
import v2.utils.utils as utils
import yaml
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.utils.test_desc import AddTestInfo

TEST_DATA_PATH = None


# create user
# create subuser
# create container
# upload object


def test_exec(config):
    test_info = AddTestInfo("test swift user key gen")
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    try:
        test_info.started_info()
        # preparing data
        user_names = ["tuffy", "scooby", "max"]
        tenant = "tenant"
        tenant_user_info = umgmt.create_tenant_user(
            tenant_name=tenant,
            user_id=user_names[0],
            displayname=user_names[0],
            cluster_name=config.cluster_name,
        )
        user_info = umgmt.create_subuser(
            tenant_name=tenant, user_id=user_names[0], cluster_name=config.cluster_name
        )
        auth = Auth(user_info)
        rgw = auth.do_auth()
        for cc in range(config.container_count):
            container_name = utils.gen_bucket_name_from_userid(
                user_info["user_id"], rand_no=cc
            )
            container = swiftlib.resource_op(
                {"obj": rgw, "resource": "put_container", "args": [container_name]}
            )
            if container is False:
                raise TestExecError(
                    "Resource execution failed: container creation faield"
                )
            for oc in range(config.objects_count):
                swift_object_name = utils.gen_s3_object_name(
                    "%s.container.%s" % (user_names[0], cc), oc
                )
                log.info("object name: %s" % swift_object_name)
                object_path = os.path.join(TEST_DATA_PATH, swift_object_name)
                log.info("object path: %s" % object_path)
                object_size = utils.get_file_size(
                    config.objects_size_range["min"], config.objects_size_range["max"]
                )
                data_info = manage_data.io_generator(object_path, object_size)
                # upload object
                if data_info is False:
                    TestExecError("data creation failed")
                log.info("uploading object: %s" % object_path)
                with open(object_path, "r") as fp:
                    rgw.put_object(
                        container_name,
                        swift_object_name,
                        contents=fp.read(),
                        content_type="text/plain",
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
                    fp.write(swift_object_downloaded[1])
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
        test_info.success_status("test passed")
        sys.exit(0)
    except Exception as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
    except TestExecError as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)


if __name__ == "__main__":
    project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
    test_data_dir = "test_data"
    TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
    log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
    if not os.path.exists(TEST_DATA_PATH):
        log.info("test data dir not exists, creating.. ")
        os.makedirs(TEST_DATA_PATH)
    parser = argparse.ArgumentParser(description="RGW S3 Automation")
    parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
    args = parser.parse_args()
    yaml_file = args.config
    config = Config()
    with open(yaml_file, "r") as f:
        doc = yaml.load(f)
    config.container_count = doc["config"]["container_count"]
    config.objects_count = doc["config"]["objects_count"]
    config.cluster_name = doc["config"]["cluster_name"]
    config.objects_size_range = {
        "min": doc["config"]["objects_size_range"]["min"],
        "max": doc["config"]["objects_size_range"]["max"],
    }
    log.info(
        "bucket_count: %s\n"
        "objects_count: %s\n"
        "objects_size_range: %s\n"
        % (config.container_count, config.objects_count, config.objects_size_range)
    )
    test_exec(config)
