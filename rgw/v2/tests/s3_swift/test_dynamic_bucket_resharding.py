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
        test_downshard.yaml

    multisite_configs/test_bucket_generation.yaml
    multisite_configs/test_resharding_disable_in_zonegroup.yaml
    multisite_configs/test_dynamic_resharding_quota_exceed.yaml
    multisite_configs/test_bucket_chown_reshard.yaml
    multisite_configs/test_versioning_objects_suspend_enable.yaml
    multisite_configs/test_max_generations.yaml

    configs/test_bucket_index_shards.yaml
    configs/test_dbr_with_custom_objs_per_shard_and_max_dynamic_shard.yaml
    configs/test_dbr_with_custom_objs_per_shard_max_dynamic_shard_and_reshard_thread_interval.yaml
    configs/test_manual_resharding_with_version.yaml
    configs/test_dynamic_resharding_with_version.yaml
    configs/test_disable_and_enable_dynamic_resharding.yaml
    configs/test_disable_and_enable_dynamic_resharding_with_1k_bucket.yaml
    configs/test_dbr_high_default_limit.yaml

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

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import quota_management as quota_mgmt
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

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
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    log.info("starting IO")
    config.user_count = 1
    user_info = s3lib.create_users(config.user_count)
    user_info = user_info[0]
    auth = reusable.get_auth(user_info, ssh_con, config.ssl, config.haproxy)
    rgw_conn = auth.do_auth()
    s3_client = auth.do_auth_using_client()
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

        object_count = (
            (config.version_count + 1) * config.objects_count
            if config.test_ops.get("upload_after_suspend", False)
            else config.objects_count
        )
        num_shards_expected = object_count / config.max_objects_per_shard
        log.info(f"num_shards_expected: {num_shards_expected}")
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
    bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info, ip_and_port)
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

    if config.test_ops.get("upload_after_suspend", False):
        log.info("suspending versioning")
        bucket_versioning = s3lib.resource_op(
            {
                "obj": rgw_conn,
                "resource": "BucketVersioning",
                "args": [bucket_name],
            }
        )
        # suspend_version_status = s3_ops.resource_op(bucket_versioning, 'suspend')
        suspend_version_status = s3lib.resource_op(
            {"obj": bucket_versioning, "resource": "suspend", "args": None}
        )
        response = HttpResponseParser(suspend_version_status)
        if response.status_code == 200:
            log.info("versioning suspended")
            write_bucket_io_info.add_versioning_status(
                user_info["access_key"],
                bucket.name,
                VERSIONING_STATUS["SUSPENDED"],
            )
        else:
            raise TestExecError("version suspend failed")
        # getting all objects in the bucket
        log.info("getting all objects in the bucket")
        objects = s3lib.resource_op(
            {"obj": bucket, "resource": "objects", "args": None}
        )
        log.info(f"objects : {objects}")
        all_objects = s3lib.resource_op(
            {"obj": objects, "resource": "all", "args": None}
        )
        log.info(f"all objects: {all_objects}")
        log.info(f"all objects2 {bucket.objects.all()}")
        for obj in all_objects:
            log.info(f"object_name: {obj.key}")
            versions = bucket.object_versions.filter(Prefix=obj.key)
            log.info("displaying all versions of the object")
            for version in versions:
                log.info(
                    f"key_name: {version.object_key} --> version_id: {version.version_id}"
                )
        log.info("trying to upload after suspending versioning on bucket")
        for oc, s3_object_size in list(config.mapped_sizes.items()):
            # non versioning upload
            s3_object_name = (
                utils.gen_s3_object_name(bucket.name, str(oc))
                + "_after_version_suspending"
            )
            log.info(f"s3 object name: {s3_object_name}")
            s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
            non_version_data_info = manage_data.io_generator(
                s3_object_path,
                s3_object_size,
                op="append",
                **{"message": "\nhello for non version\n"},
            )
            if non_version_data_info is False:
                TestExecError("data creation failed")
            log.info(f"uploading s3 object: {s3_object_path}")
            upload_info = dict(
                {
                    "access_key": user_info["access_key"],
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
                    f"Resource execution failed: object upload failed {s3_object_name}"
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
            log.info(f"version_id: {s3_obj.version_id}")
            if s3_obj.version_id is None:
                log.info("Versions are not created after suspending")
            else:
                raise TestExecError("Versions are created even after suspending")
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
            log.info(f"s3_object_downloaded_md5: {s3_object_downloaded_md5}")
            log.info(f"s3_object_uploaded_md5: {non_version_data_info['md5']}")

        bktstat_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
        sus_shard_value = json.loads(utils.exec_shell_cmd(bktstat_cmd))["num_shards"]
        log.info(f"with version suspending number of shards : {sus_shard_value}")

        log.info("enable bucket version and then upload objects")
        reusable.enable_versioning(bucket, rgw_conn, user_info, write_bucket_io_info)

    log.info(f"s3 objects to create: {config.objects_count}")
    for oc, size in list(config.mapped_sizes.items()):
        config.obj_size = size
        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
        if config.test_ops.get("upload_after_suspend", False):
            s3_object_name += "_after_enable_version"
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

    if config.test_ops.get("downshard", False) is True:
        log.info("Verify downsharding happens as expected on the above created bucket")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_dynamic_resharding_reduction_wait,
            str(config.rgw_dynamic_resharding_reduction_wait),
            ssh_con,
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_reshard_debug_interval,
            str(config.rgw_reshard_debug_interval),
            ssh_con,
        )
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")
        log.info("Reshard the bucket to 50 shards")
        cmd_exec = utils.exec_shell_cmd(
            f"radosgw-admin bucket reshard --bucket={bucket.name} --num-shards=50"
        )
        time.sleep(5)
        log.info("Delete some objects on the bucket, and it should trigger downshard")
        for i in range(10):
            s3_obj_name, _ = objects_created_list.pop()
            log.info(f"Object delete {s3_obj_name}")
            s3_client.delete_object(
                Bucket=bucket.name,
                Key=s3_obj_name,
            )
        log.info(f"wait for 5 minutes for downshard to trigger")
        time.sleep(310)
        json_doc = json.loads(
            utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket.name}")
        )
        bucket_id = json_doc["id"]
        num_shards_present = json_doc["num_shards"]
        log.info(f"number of shards at present: {num_shards_present}")
        verification = False
        if num_shards_present < 50:
            log.info("Downshard has happened to less than 50")
        else:
            raise TestExecError("Downshard unsuccessful, num shards is till at 50")

    if config.test_ops.get("bucket_chown", False) is True:
        log.info("Create new user and change bucket ownership")
        new_user = s3lib.create_users(1)
        new_user = new_user[0]
        new_auth = reusable.get_auth(new_user, ssh_con, config.ssl, config.haproxy)
        new_conn = new_auth.do_auth()
        new_name = new_user["user_id"]
        out = reusable.unlink_bucket(user_info["user_id"], bucket_name)
        log.info("Bucket unlink successful")
        out1 = reusable.link_chown_nontenant_to_nontenant(
            new_user["user_id"], bucket_name
        )
        log.info(f"Bucket ownership changed to {new_name}")

    if config.test_ops.get("verify_bucket_gen", False) is True:
        gen_count = 1
        while gen_count < 4:
            bucket_gen_before = reusable.fetch_bucket_gen(bucket.name)
            log.info(f"Current Bucket generation value is {bucket_gen_before}")
            bkt_sync_status = reusable.check_bucket_sync_status(bucket.name)
            log.info(f"Bucket sync status is {bkt_sync_status}")
            if "failed" in bkt_sync_status or "ERROR" in bkt_sync_status:
                log.info("checking for any sync error")
                utils.exec_shell_cmd("sudo radosgw-admin sync error list")
                raise AssertionError("sync status is in failed or errored state!")
            bkt_stat_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
            old_shard_value = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))[
                "num_shards"
            ]
            manual_shard_no = old_shard_value + 5
            cmd_exec = utils.exec_shell_cmd(
                f"radosgw-admin bucket reshard --bucket={bucket.name} "
                f"--num-shards={manual_shard_no}"
            )
            if not cmd_exec:
                raise TestExecError("manual resharding command execution failed")
            new_shard_value = json.loads(utils.exec_shell_cmd(bkt_stat_cmd))[
                "num_shards"
            ]
            if new_shard_value == manual_shard_no:
                log.info("manual reshard succeeded!")
            bucket_gen_after = reusable.fetch_bucket_gen(bucket.name)
            log.info(
                f"Latest generation of a bucket {bucket.name} is :{bucket_gen_after}"
            )
            if bucket_gen_after > bucket_gen_before:
                log.info("Bucket generation change success!")
            else:
                raise AssertionError("Bucket generation is not changed!")
            verification = False
            reusable.check_sync_status()
            if config.test_ops.get("verify_maxgen", False):
                log.info("Incrementing Generation count by 1, sleep for 30 sec")
                time.sleep(30)
                gen_count += 1
            else:
                break

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
        if not config.test_ops.get("downshard", False):
            log.info("Verify if resharding list is empty")
            reshard_list_op = json.loads(
                utils.exec_shell_cmd("radosgw-admin reshard list")
            )
            if reshard_list_op:
                for reshard in reshard_list_op:
                    if reshard["bucket_name"] == bucket.name:
                        raise TestExecError("bucket still exist in reshard list")
            log.info(
                "for dynamic number of shards created should be greater than or equal to number of expected shards"
            )
            log.info(f"no_of_shards_expected: {num_shards_expected}")
            if int(num_shards_created) < int(num_shards_expected):
                raise TestExecError("Expected number of shards not created")

            if config.test_ops.get("upload_after_suspend", False):
                ena_shard_value = json.loads(utils.exec_shell_cmd(bktstat_cmd))[
                    "num_shards"
                ]
                log.info(
                    f"without version suspending number of shards : {ena_shard_value}"
                )
                if int(ena_shard_value) > int(sus_shard_value):
                    log.info(
                        "dynamic resharding works as expected with and without suspending versioning"
                    )
                else:
                    raise TestExecError(
                        "dynamic resharding failed with and without suspending versioning"
                    )

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

        if config.test_ops.get("disable_dynamic_reshard_zone", False):
            log.info("Disabling resharding in Zone")
            rgw_service = utils.exec_shell_cmd("ceph orch ps | grep rgw").split(" ")[0]
            log.info(f"rgw name : {rgw_service}")
            reusable.resharding_disable_in_zone(zone_name=rgw_service)

        else:
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
        other_site_auth = reusable.get_auth(
            user_info, sec_site_ssh_con, config.ssl, config.haproxy
        )
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
    if config.test_ops.get("disable_dynamic_reshard_zone", False):
        reusable.resharding_disable_in_zone(zone_name=rgw_service, disable=False)
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
        ceph_conf = CephConfOp(ssh_con)
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
