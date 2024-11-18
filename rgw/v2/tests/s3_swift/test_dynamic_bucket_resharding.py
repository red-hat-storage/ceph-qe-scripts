"""
test_dynamic_bucket_resharding - Test resharding operations on bucket

Usage: test_dynamic_bucket_resharding.py -c <input_yaml>

<input_yaml>
    Note: any one of these yamls can be used 
    conf exist in both configs/ and multisite_configs/ :
        test_manual_resharding.yaml
        test_dynamic_resharding.yaml
        test_dynamic_resharding_without_bucket_delete.yaml
        test_manual_resharding_without_bucket_delete.yaml
        test_dynamic_resharding_with_version_without_bucket_delete.yaml

    multisite_configs/test_bucket_generation.yaml
    multisite_configs/test_resharding_disable_in_zonegroup.yaml
    multisite_configs/test_dynamic_resharding_quota_exceed.yaml
    multisite_configs/test_bucket_chown_reshard.yaml

    configs/test_bucket_index_shards.yaml
    configs/test_dbr_with_custom_objs_per_shard_and_max_dynamic_shard.yaml
    configs/test_dbr_with_custom_objs_per_shard_max_dynamic_shard_and_reshard_thread_interval.yaml
    configs/test_manual_resharding_with_version.yaml
    configs/test_dynamic_resharding_with_version.yaml
    configs/test_disable_and_enable_dynamic_resharding.yaml
    configs/test_disable_and_enable_dynamic_resharding_with_1k_bucket.yaml

Operation:
    Create user
    Perform IOs in specific bucket
    Initiate dynamic or manual sharding on bucket
    Restart RGW service
    Verify created shard numbers of bucket
"""

# test RGW dynamic bucket resharding
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import quota_management as quota_mgmt
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()

TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    log.info("starting IO")
    config.user_count = 1
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = Auth(user_info, ssh_con, ssl=config.ssl)
    rgw_conn = auth.do_auth()
    verification = True
    if config.test_with_bucket_index_shards:
        utils.exec_shell_cmd(
            "radosgw-admin zonegroup modify --bucket_index_max_shards 0"
        )
    log.info("sharding configuration will be added now.")
    if config.sharding_type == "dynamic":
        log.info("sharding type is dynamic")
        # for dynamic,
        # the number of shards  should be greater than   [ (no of objects)/(max objects per shard) ]
        # example: objects = 500 ; max object per shard = 10
        # then no of shards should be at least 50 or more
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

        num_shards_expected = config.objects_count / config.max_objects_per_shard
        log.info("num_shards_expected: %s" % num_shards_expected)
    log.info("trying to restart services ")
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    config.bucket_count = 1
    objects_created_list = []
    log.info("no of buckets to create: %s" % config.bucket_count)
    bucket_name = utils.gen_bucket_name_from_userid(user_info["user_id"], rand_no=1)
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info)
    if config.test_ops.get("enable_version", False):
        log.info("enable bucket version")
        reusable.enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info)

    if config.test_ops.get("exceed_quota_access_bucket_sec", False):
        quota_mgmt.set_quota(
            quota_scope="bucket",
            user_info=user_info,
            max_objects=config.objects_count * 2,
        )
        quota_mgmt.toggle_quota("enable", "bucket", user_info)

    log.info("s3 objects to create: %s" % config.objects_count)
    for oc, size in list(config.mapped_sizes.items()):
        config.obj_size = size
        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
        if config.test_ops.get("enable_version", False):
            reusable.upload_version_object(
                config,
                user_info,
                rgw_conn,
                s3_object_name,
                config.obj_size,
                bucket,
                TEST_DATA_PATH,
            )
        else:
            reusable.upload_object(
                s3_object_name, bucket, TEST_DATA_PATH, config, user_info
            )
        objects_created_list.append((s3_object_name, s3_object_path))

    if config.test_ops.get("bucket_chown", False) is True:
        log.info("Create new user and change bucket ownership")
        new_user = s3lib.create_users(1)
        new_user = new_user[0]
        new_auth = Auth(new_user, ssh_con, ssl=config.ssl)
        new_conn = new_auth.do_auth()
        new_name = new_user["user_id"]
        out = reusable.unlink_bucket(user_info["user_id"], bucket_name)
        log.info("Bucket unlink successful")
        out1 = reusable.link_chown_nontenant_to_nontenant(
            new_user["user_id"], bucket_name
        )
        log.info(f"Bucket ownership changed to {new_name}")

    if config.test_ops.get("verify_bucket_gen", False) is True:
        bucket_gen_before = reusable.fetch_bucket_gen(bucket.name)
        log.info(f"Current Bucket generation value is {bucket_gen_before}")
        bkt_sync_status = reusable.check_bucket_sync_status(bucket.name)
        log.info(f"Bucket sync status is {bkt_sync_status}")
        if "failed" in bkt_sync_status or "ERROR" in bkt_sync_status:
            log.info("checking for any sync error")
            utils.exec_shell_cmd("sudo radosgw-admin sync error list")
            raise AssertionError("sync status is in failed or errored state!")
        bkt_stat_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
        old_shard_value = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))["num_shards"]
        manual_shard_no = old_shard_value + 5
        cmd_exec = utils.exec_shell_cmd(
            f"radosgw-admin bucket reshard --bucket={bucket.name} "
            f"--num-shards={manual_shard_no}"
        )
        if not cmd_exec:
            raise TestExecError("manual resharding command execution failed")
        new_shard_value = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))["num_shards"]
        if new_shard_value == manual_shard_no:
            log.info("manual reshard succeeded!")
        bucket_gen_after = reusable.fetch_bucket_gen(bucket.name)
        log.info(f"Latest generation of a bucket {bucket.name} is :{bucket_gen_after}")
        if bucket_gen_after > bucket_gen_before:
            log.info("Bucket generation change success!")
        else:
            raise AssertionError("Bucket generation is not changed!")
        verification = False
        reusable.check_sync_status()

    if config.sharding_type == "manual":
        log.info("sharding type is manual")
        # for manual.
        # the number of shards will be the value set in the command.
        time.sleep(15)
        log.info("in manual sharding")
        cmd_exec = utils.exec_shell_cmd(
            "radosgw-admin bucket reshard --bucket=%s --num-shards=%s "
            "--yes-i-really-mean-it" % (bucket.name, config.shards)
        )
        if cmd_exec is False:
            raise TestExecError("manual resharding command execution failed")

    if verification:
        log.info(
            "the sleep time chosen is 180 sec owing to the value of reshard_thread_interval"
        )
        sleep_time = 180
        log.info(f"verification starts after waiting for {sleep_time} seconds")
        time.sleep(sleep_time)
        json_doc = json.loads(
            utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket.name}")
        )
        bucket_id = json_doc["id"]
        num_shards_created = json_doc["num_shards"]
        log.info(f"no_of_shards_created: {num_shards_created}")
    if config.sharding_type == "manual":
        if config.shards != num_shards_created:
            raise TestExecError("expected number of shards not created")
        log.info("Expected number of shards created")
    if config.sharding_type == "dynamic":
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

    if config.disable_dynamic_shard:
        log.info("Testing disable of DBR")
        bucket_stat_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
        json_doc = json.loads(utils.exec_shell_cmd(bucket_stat_cmd))
        num_objects = json_doc["usage"]["rgw.main"]["num_objects"]
        num_shards_created = json_doc["num_shards"]
        if num_shards_created > 11:
            log.info("Dynamic Re-sharding is successfull!")
        else:
            raise AssertionError("Dynamic Re-sharding FAILED!")

        log.info("Disabling resharding in Zonegroup")
        reusable.resharding_enable_disable_in_zonegroup(enable=False)

        config.objects_count = (
            (num_shards_created * config.max_objects_per_shard) + 2 - num_objects
        )
        config.mapped_sizes = utils.make_mapped_sizes(config)
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            name = bucket.name + "new"
            s3_object_name = utils.gen_s3_object_name(name, oc)
            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
            if config.test_ops.get("enable_version", False):
                reusable.upload_version_object(
                    config,
                    user_info,
                    rgw_conn,
                    s3_object_name,
                    config.obj_size,
                    bucket,
                    TEST_DATA_PATH,
                )
            else:
                reusable.upload_object(
                    s3_object_name, bucket, TEST_DATA_PATH, config, user_info
                )
            objects_created_list.append((s3_object_name, s3_object_path))

        time.sleep(300)
        json_doc = json.loads(utils.exec_shell_cmd(bucket_stat_cmd))
        new_num_shards_created = json_doc["num_shards"]
        log.info(f"new no_of_shards_created {new_num_shards_created}")
        if new_num_shards_created == num_shards_created:
            log.info(
                "Dynamic bucket re-sharding not taken place since feature is disabled!"
            )
        else:
            raise AssertionError("dynamically re-sharded even though DBR is disabled")

        reusable.check_sync_status()

    # test bug 2174235
    if config.test_with_bucket_index_shards:
        log.info("Bucket stats should have same num_objects post a resharding event.")
        if config.objects_count != json_doc["usage"]["rgw.main"]["num_objects"]:
            raise TestExecError("Bucket metadata lost post resharding")

    if verification:
        log.info("Test acls are preserved after a resharding operation.")
        reusable.verify_acl_preserved(bucket.name, bucket_id)

    # test bug 2024408
    if config.test_ops.get("exceed_quota_access_bucket_sec", False):
        log.info(
            f"uploading {config.objects_count} objects again to test multiple reshards"
        )
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(
                bucket.name, oc + config.objects_count
            )
            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
            reusable.upload_object(
                s3_object_name, bucket, TEST_DATA_PATH, config, user_info
            )
            objects_created_list.append((s3_object_name, s3_object_path))

        s3_object_name = utils.gen_s3_object_name(bucket.name, config.objects_count * 2)
        try:
            reusable.upload_object(
                s3_object_name, bucket, TEST_DATA_PATH, config, user_info
            )
            AssertionError(
                "bucket quota with max objects failed as upload object is successful after reaching limit"
            )
        except TestExecError as e:
            log.info(
                "Upload object failed as expected because it exceeded bucket quota max objects limit"
            )
        log.info(
            f"Sleeping for {config.rgw_reshard_thread_interval} seconds,"
            + " to test multiple reshards should not cause bucket stats failure"
        )
        time.sleep(config.rgw_reshard_thread_interval)

        bucket_stats_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
        bucket_list_cmd = f"radosgw-admin bucket list --bucket {bucket.name}"
        utils.exec_shell_cmd(bucket_list_cmd)

        # execute radsogw-admin bucket stats, list and metadata get on sec site
        sec_site_rgw_ip = utils.get_rgw_ip(master_zone=False)
        sec_site_ssh_con = utils.connect_remote(sec_site_rgw_ip)
        stdin, stdout, stderr = sec_site_ssh_con.exec_command(bucket_stats_cmd)
        bucket_stats_sec = json.loads(stdout.read().decode())
        log.info(f"Bucket stats output from secondary: {bucket_stats_sec}")
        bucket_id_sec = bucket_stats_sec["id"]
        stdin, stdout, stderr = sec_site_ssh_con.exec_command(
            f"radosgw-admin metadata get bucket.instance:{bucket.name}:{bucket_id_sec}"
        )
        metadata_get_sec = json.loads(stdout.read().decode())
        log.info(f"metadata get output from secondary: {metadata_get_sec}")
        stdin, stdout, stderr = sec_site_ssh_con.exec_command(bucket_list_cmd)
        bucket_list_sec = json.loads(stdout.read().decode())
        log.info(f"Bucket list output from secondary: {bucket_list_sec}")

        # List objects from sec site using boto3 rgw client
        other_site_auth = Auth(user_info, sec_site_ssh_con, ssl=config.ssl)
        sec_site_rgw_conn = other_site_auth.do_auth_using_client()
        resp = sec_site_rgw_conn.list_objects(Bucket=bucket.name)
        log.info(f"List objects output using rgw client from sec site: {resp}")

    if config.test_ops.get("delete_bucket_object", False):
        if config.test_ops.get("enable_version", False):
            for name, path in objects_created_list:
                reusable.delete_version_object(bucket, name, path, rgw_conn, user_info)
        else:
            reusable.delete_objects(bucket)
        reusable.delete_bucket(bucket)
    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW Dynamic Resharding test")
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
