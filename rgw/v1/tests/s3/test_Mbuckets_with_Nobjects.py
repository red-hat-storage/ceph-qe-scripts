import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import sys
import time

import v1.lib.s3.rgw as rgw_lib
import v1.utils.log as log
import yaml
from v1.lib.admin import QuotaMgmt
from v1.lib.io_info import AddIOInfo
from v1.lib.rgw_config_opts import AddToCephConf, ConfigOpts
from v1.lib.s3.rgw import Config, ObjectOps
from v1.utils.test_desc import AddTestInfo
from v1.utils.utils import RGWService


def test_exec(config):
    test_info = AddTestInfo("create m buckets, n objects and delete")
    add_io_info = AddIOInfo()
    add_io_info.initialize()
    try:
        test_info.started_info()
        rgw_service = RGWService()
        quota_mgmt = QuotaMgmt()
        test_config = AddToCephConf()
        if config.shards:
            test_config.set_to_ceph_conf(
                "global", ConfigOpts.rgw_override_bucket_index_max_shards, config.shards
            )
            log.info("test to continue after service restart, sleept time 120 seconds")
            no_of_shards_for_each_bucket = int(config.shards) * int(config.bucket_count)
        if config.dynamic_sharding is True:
            test_config.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_max_objs_per_shard,
                config.max_objects_per_shard,
            )
            test_config.set_to_ceph_conf(
                "global", ConfigOpts.rgw_dynamic_resharding, True
            )
            num_shards_expected = config.objects_count / config.max_objects_per_shard
            log.info("num_shards_expected: %s" % num_shards_expected)
            log.info("test to continue after service restart, sleept time 120 seconds")
        rgw_service.restart()
        time.sleep(120)
        all_user_details = rgw_lib.create_users(config.user_count)
        for each_user in all_user_details:
            if config.max_objects:
                quota_mgmt.set_bucket_quota(each_user["user_id"], config.max_objects)
                quota_mgmt.enable_bucket_quota(each_user["user_id"])
            rgw = ObjectOps(config, each_user)
            buckets = rgw.create_bucket()
            rgw.upload(buckets)
        test_info.success_status("test completed")
        sys.exit(0)
    except AssertionError as e:
        log.error(e)
        test_info.failed_status("test failed: %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RGW Automation")
    parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
    args = parser.parse_args()
    yaml_file = args.config
    config = Config()
    config.shards = None
    config.max_objects = None
    if yaml_file is None:
        config.user_count = 2
        config.bucket_count = 10
        config.objects_count = 2
        config.objects_size_range = {"min": 10, "max": 50}
        config.shards = 32
        config.max_objects = 2
    else:
        with open(yaml_file, "r") as f:
            doc = yaml.load(f)
        config.user_count = doc["config"]["user_count"]
        config.bucket_count = doc["config"]["bucket_count"]
        config.objects_count = doc["config"]["objects_count"]
        config.objects_size_range = {
            "min": doc["config"]["objects_size_range"]["min"],
            "max": doc["config"]["objects_size_range"]["max"],
        }
        for k, v in doc.items():
            if "shards" in v:
                config.shards = doc["config"]["shards"]
                print("shard value: %s" % config.shards)
            if "max_objects" in v:
                config.max_objects = doc["config"]["max_objects"]
        if doc["config"].get("dynamic_sharding", None) is True:
            config.dynamic_sharding = True
            config.max_objects_per_shard = doc["config"]["max_objects_per_shard"]
        else:
            config.dynamic_sharding = False
    log.info(
        "user_count:%s\n"
        "bucket_count: %s\n"
        "objects_count: %s\n"
        "objects_size_range: %s\n"
        "shards: %s\n"
        "max_objects: %s\n"
        % (
            config.user_count,
            config.bucket_count,
            config.objects_count,
            config.objects_size_range,
            config.shards,
            config.max_objects,
        )
    )
    test_exec(config)
