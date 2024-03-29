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


# only 2 users test case and 1 bucket in each user
def test_exec_read(config):
    test_info = AddTestInfo("Test with read permission on buckets")
    try:
        # test case starts
        add_io_info = AddIOInfo()
        add_io_info.initialize()
        test_info.started_info()
        all_user_details = rgw_lib.create_users(config.user_count)
        user1 = all_user_details[0]
        log.info("user1: %s" % user1)
        user2 = all_user_details[1]
        log.info("user2: %s" % user2)
        u1 = ObjectOps(config, user1)
        u2 = ObjectOps(config, user2)
        u1_grants = {
            "permission": "READ",
            "user_id": u2.canonical_id,
            "recursive": True,
        }
        u2_grants = {
            "permission": "FULL_CONTROL",
            "user_id": u1.canonical_id,
            "recursive": True,
        }
        u1.grants = u1_grants
        u1.create_bucket()
        u1_buckets = u1.set_bucket_properties()
        u1.upload(u1_buckets, object_base_name=u1.canonical_id + ".key")
        all_keys = u1_buckets[0].get_all_keys()
        for key in all_keys:
            log.info("all keys from user 1--------------")
            log.info("name: %s" % key.name)
        u2.grants = u2_grants
        u2.create_bucket()
        u2_buckets = u2.set_bucket_properties()
        bu2 = u1.connection["conn"].get_bucket(u2_buckets[0].name)
        log.info("copying the objects from u1 to u2")
        for each in all_keys:
            bu2.copy_key(each.key, u1_buckets[0].name, each.key)
        all_keys2 = bu2.get_all_keys()
        for key in all_keys2:
            log.info("all keys from user 2--------------")
            log.info("name: %s" % key.name)
        log.info("verifying copied objects--------")
        u2.grants = None
        u2_buckets = u2.set_bucket_properties()
        all_keys3 = u2_buckets[0].get_all_keys()
        for key in all_keys3:
            log.info("all keys from user 2--------------")
            log.info("name: %s" % key.name)
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
        config.bucket_count = 1
        config.user_count = 2
        config.objects_count = 4
        config.objects_size_range = {"min": 10, "max": 50}
    else:
        with open(yaml_file, "r") as f:
            doc = yaml.safe_load(f)
        config.user_count = 2
        config.bucket_count = 1
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
    test_exec_read(config)
