"""
Usage: test_multisite_bucket_granular_sync_policy.py

<input_yaml>
	Note: Any one of these yamls can be used
    multisite_configs/test_multisite_granular_bucket_sync_policy.yaml
    multisite_configs/test_multisite_granular_bucketsync_allowed_forbidden.yaml
    multisite_configs/test_multisite_granular_bucketsync_enable_enable.yaml
    multisite_configs/test_multisite_granular_bucketsync_enabled_forbidden.yaml
    multisite_configs/test_multisite_granular_bucketsync_forbidden_enabled.yaml
    multisite_configs/test_multisite_granular_bucketsync_forbidden_forbidden.yaml
    multisite_configs/test_multisite_granular_bucketsync_forbidden_allowed.yaml
    multisite_configs/test_multisite_granular_bucketsync_sync_to_diff_bucket.yaml
    multisite_configs/test_multisite_granular_bucketsync_sync_from_diff_bucket.yaml

Operation:
	Creates delete sync policy group bucket , zonegroupl level
    perform IO and verify sync
"""
# test basic creation of buckets with objects
import os
import sys
from random import randint

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
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()

        period_details = json.loads(utils.exec_shell_cmd("radosgw-admin period get"))
        zone_list = json.loads(utils.exec_shell_cmd("radosgw-admin zone list"))
        for zone in period_details["period_map"]["zonegroups"][0]["zones"]:
            if zone["name"] not in zone_list["zones"]:
                rgw_nodes = zone["endpoints"][0].split(":")
                node_rgw = rgw_nodes[1].split("//")[-1]
                log.info(f"Another site is: {zone['name']} and ip {node_rgw}")
                break
        rgw_ssh_con = utils.connect_remote(node_rgw)
        if config.test_ops.get("write_io_verify_another_site", False):
            other_site_auth = Auth(each_user, rgw_ssh_con, ssl=config.ssl)
            other_site_rgw_conn = other_site_auth.do_auth()

        # create buckets
        if config.test_ops.get("create_bucket", False):
            log.info(f"no of buckets to create: {config.bucket_count}")
            buckets = []
            new_buckets = []
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info(f"creating bucket with name: {bucket_name_to_create}")
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )

                if config.test_ops.get("create_new_bucket", False):
                    bucket_count = config.test_ops.get("new_bucket_count", 1)
                    for i in range(bucket_count):
                        new_bucket_name = f"{bucket_name_to_create}-new-{i}"
                        log.info(f"creating new bucket with name: {new_bucket_name}")
                        new_bucket = reusable.create_bucket(
                            new_bucket_name, rgw_conn, each_user
                        )
                        new_buckets.append(new_bucket)

                reusable.verify_bucket_sync_on_other_site(rgw_ssh_con, bucket)
                buckets.append(bucket)

    if utils.is_cluster_multisite():
        if config.test_ops.get("zonegroup_group", False):
            group_status = config.test_ops["zonegroup_status"]
            group_id = "zonegroup_sync_group"
            reusable.group_operation(group_id, "create", group_status)
            if config.test_ops.get("zonegroup_flow", False):
                flow_type = config.test_ops["zonegroup_flow_type"]
                zonegroup_source_flow = config.test_ops.get(
                    "zonegroup_source_zone", None
                )
                zonegroup_dest_flow = config.test_ops.get("zonegroup_dest_zone", None)
                reusable.flow_operation(
                    group_id,
                    "create",
                    flow_type,
                    source_zone=zonegroup_source_flow,
                    dest_zone=zonegroup_dest_flow,
                )
            if config.test_ops.get("zonegroup_pipe", False):
                zonegroup_details = config.test_ops.get(
                    "zonegroup_policy_details", None
                )
                zonegroup_source_pipe = config.test_ops.get(
                    "zonegroup_source_zones", None
                )
                zonegroup_dest_pipe = config.test_ops.get("zonegroup_dest_zones", None)
                pipe_id = reusable.pipe_operation(
                    group_id,
                    "create",
                    policy_detail=zonegroup_details,
                    source_zones=zonegroup_source_pipe,
                    dest_zones=zonegroup_dest_pipe,
                )

    if config.test_ops.get("create_bucket", False):
        for each_user in all_users_info:
            # authenticate
            auth = Auth(each_user, ssh_con, ssl=config.ssl)
            rgw_conn = auth.do_auth()
            if utils.is_cluster_multisite():
                if config.test_ops.get("modify_zonegroup_policy", False):
                    modify_zgroup_status = config.test_ops["modify_zgroup_status"]
                    reusable.group_operation(
                        group_id,
                        "modify",
                        modify_zgroup_status,
                    )
                for bkt in buckets:
                    if config.test_ops.get("bucket_group", False):
                        bucket_group_status = config.test_ops["bucket_status"]
                        bucket_count = config.test_ops.get("bucket_count", 1)
                        if config.test_ops.get("sync_from_diff_bucket", False):
                            bucket_count = config.test_ops.get("new_bucket_count", 1)
                            old_bucket = bkt.name
                        for i in range(bucket_count):
                            if config.test_ops.get("sync_from_diff_bucket", False):
                                new_bucket = f"{bucket_name_to_create}-new-{i}"
                                for new_bkt in new_buckets:
                                    if new_bkt.name == new_bucket:
                                        bkt = new_bkt

                            bucket_group = "bgroup-" + bkt.name
                            reusable.group_operation(
                                bucket_group,
                                "create",
                                bucket_group_status,
                                bkt.name,
                            )
                            if config.test_ops.get("bucket_flow", False):
                                bucket_flow_type = config.test_ops["bucket_flow_type"]
                                bucket_source_flow = config.test_ops.get(
                                    "bucket_source_zone", None
                                )
                                bucket_dest_flow = config.test_ops.get(
                                    "bucket_dest_zone", None
                                )
                                reusable.flow_operation(
                                    bucket_group,
                                    "create",
                                    bucket_flow_type,
                                    bkt.name,
                                    bucket_source_flow,
                                    bucket_dest_flow,
                                )
                            if config.test_ops.get("bucket_pipe", False):
                                bucket_pipe_count = config.test_ops.get(
                                    "bucket_pipe_count", 1
                                )
                                for pipec in range(bucket_pipe_count):
                                    bucket_details = config.test_ops.get(
                                        "bucket_policy_details", None
                                    )
                                    pipe_id = None
                                    if config.test_ops.get(
                                        "sync_to_diff_bucket", False
                                    ):
                                        bucket_details = " " + bucket_details.replace(
                                            "<dest_bucket_name>",
                                            f"{bkt.name}-new-{pipec}",
                                        )
                                        pipe_id = f"{bucket_group}pipe{pipec}"

                                    if config.test_ops.get(
                                        "sync_from_diff_bucket", False
                                    ):
                                        bucket_details = " " + bucket_details.replace(
                                            "<source_bucket_name>", old_bucket
                                        )

                                    bucket_source_pipe = config.test_ops.get(
                                        "bucket_source_zones", None
                                    )
                                    bucket_dest_pipe = config.test_ops.get(
                                        "bucket_dest_zones", None
                                    )
                                    pipe_id = reusable.pipe_operation(
                                        bucket_group,
                                        "create",
                                        bucket_name=bkt.name,
                                        policy_detail=bucket_details,
                                        source_zones=bucket_source_pipe,
                                        dest_zones=bucket_dest_pipe,
                                        pipe_id=pipe_id,
                                    )

                for bkt in buckets:
                    if config.test_ops.get("bucket_group", False):
                        if config.test_ops.get("bucket_pipe", False):
                            if config.test_ops.get("sync_from_diff_bucket", False):
                                bucket_count = config.test_ops.get(
                                    "new_bucket_count", 1
                                )
                                for i in range(bucket_count):
                                    new_bucket = f"{bucket_name_to_create}-new-{i}"
                                    for new_bkt in new_buckets:
                                        if new_bkt.name == new_bucket:
                                            reusable.verify_bucket_sync_policy_on_other_site(
                                                rgw_ssh_con, new_bkt
                                            )
                            else:
                                reusable.verify_bucket_sync_policy_on_other_site(
                                    rgw_ssh_con, bkt
                                )

                    if config.test_ops.get("create_object", False):
                        # uploading data
                        log.info(f"s3 objects to create: {config.objects_count}")
                        for oc, size in list(config.mapped_sizes.items()):
                            config.obj_size = size
                            s3_object_name = utils.gen_s3_object_name(bkt.name, oc)
                            log.info(f"s3 object name: {s3_object_name}")
                            s3_object_path = os.path.join(
                                TEST_DATA_PATH, s3_object_name
                            )
                            log.info(f"s3 object path: {s3_object_path}")
                            if config.test_ops.get("enable_version", False):
                                reusable.upload_version_object(
                                    config,
                                    each_user,
                                    rgw_conn,
                                    s3_object_name,
                                    config.obj_size,
                                    bkt,
                                    TEST_DATA_PATH,
                                )
                            else:
                                log.info("upload type: normal")
                                reusable.upload_object(
                                    s3_object_name,
                                    bkt,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )

                        if config.test_ops.get("should_sync", False):
                            reusable.verify_object_sync_on_other_site(
                                rgw_ssh_con, bkt, config
                            )
                        else:
                            time.sleep(1200)
                            _, stdout, _ = rgw_ssh_con.exec_command(
                                f"radosgw-admin bucket stats --bucket {bkt.name}"
                            )
                            cmd_output = json.loads(stdout.read().decode())

                            if (
                                "rgw.main" in cmd_output["usage"].keys()
                                and cmd_output["usage"]["rgw.main"]["num_objects"]
                                == config.objects_count
                            ):
                                raise TestExecError(
                                    f"object should not sync to another site for bucket {bkt.name}, but synced"
                                )
                            log.info(
                                f"object did not sync to another site for bucket {bkt.name} as expected"
                            )

                            if config.test_ops.get(
                                "sync_to_diff_bucket", False
                            ) or config.test_ops.get("sync_from_diff_bucket", False):
                                log.info(
                                    f"Verify object sync on same site for bucket {bkt.name}"
                                )
                                bucket_stats = json.loads(
                                    utils.exec_shell_cmd(
                                        f"radosgw-admin bucket stats --bucket {bkt.name}"
                                    )
                                )
                                bkt_objects = bucket_stats["usage"]["rgw.main"][
                                    "num_objects"
                                ]
                                if bkt_objects != config.objects_count:
                                    raise TestExecError(
                                        f"Did not find {config.objects_count} in bucket {bkt.name}, but found {bkt_objects}"
                                    )

                                log.info(
                                    f"object did sync on same site for bucket {bkt.name} as expected"
                                )
                                bucket_count = config.test_ops.get(
                                    "new_bucket_count", 1
                                )
                                for i in range(bucket_count):
                                    new_bucket = f"{bucket_name_to_create}-new-{i}"
                                    for new_bkt in new_buckets:
                                        if new_bkt.name == new_bucket:
                                            reusable.verify_object_sync_on_other_site(
                                                rgw_ssh_con,
                                                new_bkt,
                                                config,
                                                bucket_object=bkt_objects,
                                            )

                            if config.test_ops.get("bucket_sync", False):
                                bucket_group = "bgroup-" + bkt.name
                                reusable.group_operation(
                                    bucket_group,
                                    "modify",
                                    "enabled",
                                    bkt.name,
                                )
                                # uploading data
                                log.info(
                                    f"new s3 objects to create: {config.objects_count}"
                                )
                                for oc, size in list(config.mapped_sizes.items()):
                                    config.obj_size = size
                                    s3_object_name = "new-" + utils.gen_s3_object_name(
                                        bkt.name, oc
                                    )
                                    log.info(f"s3 object name: {s3_object_name}")
                                    s3_object_path = os.path.join(
                                        TEST_DATA_PATH, s3_object_name
                                    )
                                    log.info(f"s3 object path: {s3_object_path}")
                                    log.info("upload type: normal")
                                    reusable.upload_object(
                                        s3_object_name,
                                        bkt,
                                        TEST_DATA_PATH,
                                        config,
                                        each_user,
                                    )
                                new_obj_count = config.objects_count * 2
                                time.sleep(1200)
                                _, re_stdout, _ = rgw_ssh_con.exec_command(
                                    f"radosgw-admin bucket stats --bucket {bkt.name}"
                                )
                                re_cmd_output = json.loads(re_stdout.read().decode())
                                if (
                                    "rgw.main" not in re_cmd_output["usage"].keys()
                                    or re_cmd_output["usage"]["rgw.main"]["num_objects"]
                                    != new_obj_count
                                ):
                                    log.error(
                                        f"object should be sync to another site for bucket {bkt.name}, but not synced"
                                    )

                        if config.test_ops.get("write_io_verify_another_site", False):
                            if config.test_ops.get(
                                "sync_to_diff_bucket", False
                            ) or config.test_ops.get("sync_from_diff_bucket", False):
                                cmd_output = json.loads(
                                    utils.exec_shell_cmd(
                                        f"radosgw-admin bucket stats --bucket {bkt.name}"
                                    )
                                )
                                sync_num_obj = (
                                    cmd_output["usage"]["rgw.main"]["num_objects"]
                                    if "rgw.main" in cmd_output["usage"].keys()
                                    else 0
                                )

                            _, stdout, _ = rgw_ssh_con.exec_command(
                                f"radosgw-admin bucket stats --bucket {bkt.name}"
                            )
                            cmd_output = json.loads(stdout.read().decode())
                            num_objects = (
                                cmd_output["usage"]["rgw.main"]["num_objects"]
                                if "rgw.main" in cmd_output["usage"].keys()
                                else 0
                            )

                            other_site_bucket = s3lib.resource_op(
                                {
                                    "obj": other_site_rgw_conn,
                                    "resource": "Bucket",
                                    "args": [bkt.name],
                                }
                            )
                            for oc, size in list(config.mapped_sizes.items()):
                                config.obj_size = size
                                s3_object_name = "new-" + utils.gen_s3_object_name(
                                    bkt.name, oc
                                )
                                log.info(f"s3 object name: {s3_object_name}")
                                s3_object_path = os.path.join(
                                    TEST_DATA_PATH, s3_object_name
                                )
                                log.info(f"s3 object path: {s3_object_path}")
                                log.info("upload type: normal")
                                reusable.upload_object(
                                    s3_object_name,
                                    other_site_bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )

                            _, stats_stdout, _ = rgw_ssh_con.exec_command(
                                f"radosgw-admin bucket stats --bucket {bkt.name}"
                            )
                            re_cmd_output = json.loads(stats_stdout.read().decode())
                            log.info(f"re_cmd_output : {re_cmd_output}")
                            new_object_count = num_objects + config.objects_count
                            if (
                                re_cmd_output["usage"]["rgw.main"]["num_objects"]
                                != new_object_count
                            ):
                                raise TestExecError(
                                    f"Failed to upload new objects to bucket {bkt.name}"
                                )

                            log.info(
                                f"Verify object sync on other site for bucket {bkt.name}"
                            )
                            time.sleep(1200)
                            bucket_stats = json.loads(
                                utils.exec_shell_cmd(
                                    f"radosgw-admin bucket stats --bucket {bkt.name}"
                                )
                            )
                            bkt_objects = bucket_stats["usage"]["rgw.main"][
                                "num_objects"
                            ]

                            if config.test_ops.get(
                                "write_io_verify_should_sync", False
                            ):
                                if bkt_objects != config.objects_count * 2:
                                    raise TestExecError(
                                        f"Object did not sync in bucket {bkt.name}, but found {bkt_objects}"
                                    )
                                log.info(
                                    f"Object synced for bucket {bkt.name}, on another site as expected"
                                )

                            elif config.test_ops.get(
                                "sync_to_diff_bucket", False
                            ) or config.test_ops.get("sync_from_diff_bucket", False):
                                if bkt_objects != sync_num_obj:
                                    raise TestExecError(
                                        f"Object should not sync in bucket {bkt.name}, but found {bkt_objects}"
                                    )

                                bucket_count = config.test_ops.get(
                                    "new_bucket_count", 1
                                )
                                for i in range(bucket_count):
                                    new_bkt = f"{bucket_name_to_create}-new-{i}"
                                    _, stats_stdout, _ = rgw_ssh_con.exec_command(
                                        f"radosgw-admin bucket stats --bucket {new_bkt}"
                                    )
                                    re_cmd_output = json.loads(
                                        stats_stdout.read().decode()
                                    )
                                    log.info(
                                        f"re_cmd_output for {new_bkt} : {re_cmd_output}"
                                    )
                                    if (
                                        re_cmd_output["usage"]["rgw.main"][
                                            "num_objects"
                                        ]
                                        != config.objects_count
                                    ):
                                        raise TestExecError(
                                            f"IO performed for {bkt.name} should not sync to {new_bkt} in same site as of IO"
                                        )
                                    log.info(
                                        f"IO did not sync to {new_bkt} as expected in same site as of IO"
                                    )
                                    log.info(
                                        f"verify IO sync on {new_bkt} in another site"
                                    )
                                    new_bucket_stats = json.loads(
                                        utils.exec_shell_cmd(
                                            f"radosgw-admin bucket stats --bucket {new_bkt}"
                                        )
                                    )
                                    new_bkt_objects = new_bucket_stats["usage"][
                                        "rgw.main"
                                    ]["num_objects"]
                                    if new_bkt_objects != config.objects_count:
                                        raise TestExecError(
                                            f"Object did not sync in bucket {new_bkt}, but found {new_bkt_objects}"
                                        )
                                    log.info(
                                        f"Object synced for bucket {new_bkt}, on another site as expected"
                                    )

                            else:
                                if bkt_objects != config.objects_count:
                                    raise TestExecError(
                                        f"Object should not sync in bucket {bkt.name}, but found {bkt_objects}"
                                    )
                                log.info(
                                    f"Object did not sync for bucket {bkt.name}, on another site as expected"
                                )

    if config.test_ops.get("zonegroup_group_remove", False):
        group_id = reusable.group_operation(group_id, "remove", group_status)
        utils.exec_shell_cmd(f"radosgw-admin period update --commit")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    for i in all_users_info:
        reusable.remove_user(i)

    # check for any health errors or large omaps
    out = utils.get_ceph_status()
    if not out:
        raise TestExecError(
            "ceph status is either in HEALTH_ERR or we have large omap objects."
        )


if __name__ == "__main__":
    test_info = AddTestInfo("Test multisite sync policy")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
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

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
