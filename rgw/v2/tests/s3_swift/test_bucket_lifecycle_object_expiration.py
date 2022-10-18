"""
Test bucket lifecycle for object expiration:
Script tests the s3 object(both versioned and non-versioned) expiration rules based on:
a) Prefix filters 
b) ANDing of Prefix and TAG filters

Usage: test_bucket_lifecycle_object_expiration.py -c configs/<input-yaml>
where : <input-yaml> are test_lc_date.yaml, test_rgw_enable_lc_threads.yaml, test_lc_multiple_rule_prefix_current_days.yaml, test_lc_rule_delete_marker.yaml, test_lc_rule_prefix_and_tag.yaml and test_lc_rule_prefix_non_current_days.yaml

Operation:

-Create a user and a bucket
-Enable versioning on the bucket as per config in the input-yaml file.
-Put objects (object count and size taken from input-yaml)
-Enable Lifecycle(lc) rule on the bucket based on the rule created as per the input-yaml
-Validate the lc rule via lifecycle_validation()
-Remove the user at successful completion.

"""

# test s3 bucket_lifecycle: object expiration operations
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
from v2.lib.s3 import lifecycle_validation as lc_ops
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
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
    buckets = []
    log.info("making changes to ceph.conf")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_lc_debug_interval,
        str(config.rgw_lc_debug_interval),
        ssh_con,
    )
    if not config.rgw_enable_lc_threads:
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_enable_lc_threads,
            str(config.rgw_enable_lc_threads),
            ssh_con,
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_lifecycle_work_time,
            str(config.rgw_lifecycle_work_time),
            ssh_con,
        )
    _, version_name = utils.get_ceph_version()
    if "nautilus" in version_name:
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_lc_max_worker,
            str(config.rgw_lc_max_worker),
            ssh_con,
        )
    else:
        ceph_conf.set_to_ceph_conf(
            section=None,
            option=ConfigOpts.rgw_lc_max_worker,
            value=str(config.rgw_lc_max_worker),
            ssh_con=ssh_con,
        )
    log.info("trying to restart services")
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    config.user_count = config.user_count if config.user_count else 1
    config.bucket_count = config.bucket_count if config.bucket_count else 1

    log.info(f"user count is {config.user_count}")
    log.info(f"bucket count is {config.bucket_count}")
    # create user
    user_info = s3lib.create_users(config.user_count)
    for each_user in user_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        log.info("no of buckets to create: %s" % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            obj_list = []
            obj_tag = "suffix1=WMV1"
            bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
            prefix = list(
                map(
                    lambda x: x,
                    [
                        rule["Filter"].get("Prefix")
                        or rule["Filter"]["And"].get("Prefix")
                        for rule in config.lifecycle_conf
                    ],
                )
            )
            prefix = prefix if prefix else ["dummy1"]
            if config.test_ops["enable_versioning"] is True:
                reusable.enable_versioning(
                    bucket, rgw_conn, each_user, write_bucket_io_info
                )
                upload_start_time = time.time()
                if config.test_ops["create_object"] is True:
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        key = prefix.pop()
                        prefix.insert(0, key)
                        s3_object_name = key + "." + bucket.name + "." + str(oc)
                        obj_list.append(s3_object_name)
                        if config.test_ops["version_count"] > 0:
                            for vc in range(config.test_ops["version_count"]):
                                log.info(
                                    "version count for %s is %s"
                                    % (s3_object_name, str(vc))
                                )
                                log.info("modifying data: %s" % s3_object_name)
                                reusable.upload_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                    append_data=True,
                                    append_msg="hello object for version: %s\n"
                                    % str(vc),
                                )
                        else:
                            log.info("s3 objects to create: %s" % config.objects_count)
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                            )

                if not config.parallel_lc:
                    life_cycle_rule = {"Rules": config.lifecycle_conf}
                    reusable.put_get_bucket_lifecycle_test(
                        bucket,
                        rgw_conn,
                        rgw_conn2,
                        life_cycle_rule,
                        config,
                        upload_start_time,
                    )
                    time.sleep(30)
                    lc_ops.validate_prefix_rule(bucket, config)
                    if config.test_ops["delete_marker"] is True:
                        life_cycle_rule_new = {"Rules": config.delete_marker_ops}
                        reusable.put_get_bucket_lifecycle_test(
                            bucket,
                            rgw_conn,
                            rgw_conn2,
                            life_cycle_rule_new,
                            config,
                        )
                    if config.multiple_delete_marker_check:
                        log.info(
                            f"verification of TC: Not more than 1 delete marker is created for objects deleted many times using LC"
                        )
                        time.sleep(60)
                        cmd = f"radosgw-admin bucket list --bucket {bucket.name}| grep delete-marker | wc -l"
                        out = utils.exec_shell_cmd(cmd)
                        del_marker_count = out.split("\n")[0]
                        if int(del_marker_count) != int(config.objects_count):
                            raise AssertionError(
                                f"more than one delete marker created for the objects in the bucket {bucket.name}"
                            )
                else:
                    buckets.append(bucket)

            if config.test_ops["enable_versioning"] is False:
                upload_start_time = time.time()
                if config.test_ops["create_object"] is True:
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        key = prefix.pop()
                        prefix.insert(0, key)
                        s3_object_name = key + "." + bucket.name + "." + str(oc)
                        obj_list.append(s3_object_name)
                        reusable.upload_object_with_tagging(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            each_user,
                            obj_tag,
                        )
                if not config.parallel_lc:
                    life_cycle_rule = {"Rules": config.lifecycle_conf}
                    if not config.invalid_date and config.rgw_enable_lc_threads:
                        reusable.put_get_bucket_lifecycle_test(
                            bucket,
                            rgw_conn,
                            rgw_conn2,
                            life_cycle_rule,
                            config,
                            upload_start_time,
                        )
                        time.sleep(30)
                        lc_ops.validate_and_rule(bucket, config)
                    elif not config.invalid_date and not config.rgw_enable_lc_threads:
                        bucket_before_lc = json.loads(
                            utils.exec_shell_cmd(
                                f"radosgw-admin bucket stats --bucket={bucket.name}"
                            )
                        )
                        reusable.put_bucket_lifecycle(
                            bucket, rgw_conn, rgw_conn2, life_cycle_rule
                        )
                        time.sleep(60)
                        lc_list_before = json.loads(
                            utils.exec_shell_cmd("radosgw-admin lc list")
                        )
                        log.info(f"lc lists is {lc_list_before}")
                        for data in lc_list_before:
                            if data["bucket"] == bucket.name:
                                if data["status"] != "UNINITIAL":
                                    raise TestExecError(
                                        f"Since rgw_enable_lc_threads set to false for bucket {bucket.name}, lc status should be 'UNINITIAL'"
                                    )
                        bucket_after_lc = json.loads(
                            utils.exec_shell_cmd(
                                f"radosgw-admin bucket stats --bucket={bucket.name}"
                            )
                        )
                        if (
                            bucket_before_lc["usage"]["rgw.main"]["num_objects"]
                            != bucket_after_lc["usage"]["rgw.main"]["num_objects"]
                        ):
                            raise TestExecError(
                                f"Since rgw_enable_lc_threads set to false for bucket {bucket.name}, object count should not decrease"
                            )
                        utils.exec_shell_cmd(
                            f"radosgw-admin lc process --bucket {bucket.name}"
                        )
                        list_lc_after = json.loads(
                            utils.exec_shell_cmd("radosgw-admin lc list")
                        )
                        log.info(f"lc lists is {list_lc_after}")
                        for data in list_lc_after:
                            if data["bucket"] == bucket.name:
                                if data["status"] == "UNINITIAL":
                                    raise TestExecError(
                                        f"Even if rgw_enable_lc_threads set to false manual lc process for bucket {bucket.name} should work"
                                    )
                        time.sleep(30)
                        lc_ops.validate_and_rule(bucket, config)
                    else:
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
                        if put_bucket_life_cycle:
                            lc_list = utils.exec_shell_cmd("radosgw-admin lc list")
                            log.info(f"lc list Details: {lc_list}")
                            raise TestExecError(
                                "Put bucket lifecycle Succeeded, expected failure due to invalid date in LC rule"
                            )
                else:
                    log.info("Inside parallel lc")
                    buckets.append(bucket)
        if config.parallel_lc:
            log.info("Inside parallel lc processing")
            life_cycle_rule = {"Rules": config.lifecycle_conf}
            for bucket in buckets:
                reusable.put_bucket_lifecycle(
                    bucket, rgw_conn, rgw_conn2, life_cycle_rule
                )
            time.sleep(60)
            for bucket in buckets:
                if config.test_ops["enable_versioning"] is False:
                    lc_ops.validate_prefix_rule_non_versioned(bucket)
                else:
                    lc_ops.validate_prefix_rule(bucket, config)

        if not config.rgw_enable_lc_threads:
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_enable_lc_threads, "true", ssh_con
            )
            rgw_service.restart()
            time.sleep(30)
        reusable.remove_user(each_user)
        # check for any crashes during the execution
        crash_info = reusable.check_for_crash()
        if crash_info:
            raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("bucket life cycle: test object expiration")
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
