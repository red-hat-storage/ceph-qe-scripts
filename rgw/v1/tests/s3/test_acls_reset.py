import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import sys

import v1.lib.s3.rgw as rgw_lib
import v1.utils.log as log
import yaml
from v1.lib.io_info import AddIOInfo
from v1.lib.s3.rgw import Config, ObjectOps
from v1.utils.test_desc import AddTestInfo


def test_exec_write(config):
    test_info = AddTestInfo("give the permission for all the users and then reset it")
    add_io_info = AddIOInfo()
    add_io_info.initialize()
    try:
        # test case starts
        test_info.started_info()
        all_user_details = rgw_lib.create_users(config.user_count)
        user1 = all_user_details[0]
        u1 = ObjectOps(config, user1)
        u1.create_bucket()
        log.info("user1: %s" % user1)
        all_user_details.pop(0)
        for each_user in all_user_details:
            print("iter ------------------>")
            log.info("user2: %s" % each_user)
            u2 = ObjectOps(config, each_user)
            u2_canonical_id = u2.canonical_id
            log.info("canonical id of u2: %s" % u2_canonical_id)
            log.info("setting only read permission")
            grants = {"permission": "READ", "user_id": None, "recursive": True}
            log.info("write persmission are not set")
            grants["user_id"] = u2_canonical_id
            u1.grants = grants
            u1.set_bucket_properties()
            u2.bucket_names = u1.bucket_names
            u2.buckets_created = u1.buckets_created
            u2.json_file_upload = u1.json_file_upload
            u2.json_file_download = u1.json_file_download
            u2.grants = None
            u2.create_bucket()
            buckets = u2.set_bucket_properties()
            key_created = u2.upload(buckets)
            if not key_created:
                log.info("no write permission set and hence failing to create object")
            elif key_created:
                raise AssertionError("object created even with no permission")
            log.info("setting permission to write also")
            grants = {
                "permission": "WRITE",
                "user_id": u2_canonical_id,
                "recursive": True,
            }
            u1.grants = grants
            u1.set_bucket_properties()
            u2.bucket_names = u1.bucket_names
            u2.buckets_created = u1.buckets_created
            u2.grants = None
            buckets = u2.set_bucket_properties()
            key_created = u2.upload(
                buckets, object_base_name=str(u2.canonical_id) + ".key"
            )
            if key_created:
                log.info("object created after permission set")
        log.info(
            "***************** removing grants and making the bucket private *****************"
        )
        u1.grants = None
        u1.acls = "private"
        u1.set_bucket_properties()
        for each_user in all_user_details:
            u2 = ObjectOps(config, each_user)
            print("iter ------------------>")
            u2.bucket_names = u1.bucket_names
            u2.buckets_created = u1.buckets_created
            u2.json_file_upload = u1.json_file_upload
            u2.json_file_download = u1.json_file_download
            u2.grants = None
            buckets = u2.set_bucket_properties()
            if not buckets:
                log.info("bucket init failed: %s" % buckets)
            elif buckets:
                key_created = u2.upload(buckets)
                if not key_created:
                    log.info(
                        "no write permission set and hence failing to create object"
                    )
                elif key_created:
                    raise AssertionError("object created even with no permission")
        test_info.success_status("test completed")
    except AssertionError as e:
        log.error(e)
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RGW Automation")
    parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
    parser.add_argument(
        "-p", dest="port", default="8080", help="port number where RGW is running"
    )
    args = parser.parse_args()
    yaml_file = args.config
    config = Config()
    config.port = args.port
    if yaml_file is None:
        config.user_count = 2
        config.bucket_count = 2
        config.objects_count = 10
        config.objects_size_range = {"min": 10, "max": 50}
    else:
        with open(yaml_file, "r") as f:
            doc = yaml.safe_load(f)
        config.user_count = doc["config"]["user_count"]
        config.bucket_count = doc["config"]["bucket_count"]
        config.objects_count = doc["config"]["objects_count"]
        config.objects_size_range = {
            "min": doc["config"]["objects_size_range"]["min"],
            "max": doc["config"]["objects_size_range"]["max"],
        }
    log.info(
        "user_count:%s\n"
        "bucket_count: %s\n"
        "objects_count: %s\n"
        "objects_size_range: %s\n"
        % (
            config.user_count,
            config.bucket_count,
            config.objects_count,
            config.objects_size_range,
        )
    )
    test_exec_write(config)
