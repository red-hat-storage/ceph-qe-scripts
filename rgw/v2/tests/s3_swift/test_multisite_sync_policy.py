"""test_Mbuckets_with_Nobjects.py - Test with M buckets and N objects

Usage: test_multisite_sync_policy.py -c <input_yaml>

<input_yaml>
        Note: Any one of these yamls can be used
        test_multisite_sync_policy.yaml
    test_sync_policy_state_change.yaml
    test_multisite_mirror_sync_policy.yaml
    test_multisite_bucket_mirror_sync_policy.yaml
    test_multisite_sync_policy_extended.yaml

Operation:
        Creates and delete sync policy group
        Creates and delete sync policy flow
    Creates and delete sync policy pipe
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
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{"signature_version": "s3v4"})
        else:
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

        # create buckets
        if config.test_ops.get("create_bucket", False):
            log.info(f"no of buckets to create: {config.bucket_count}")
            buckets = []
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info(f"creating bucket with name: {bucket_name_to_create}")
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user, ip_and_port
                )
                reusable.verify_bucket_sync_on_other_site(rgw_ssh_con, bucket)
                buckets.append(bucket)

            if config.test_ops.get("new_bucket_and_group_state_change", False):
                new_bucket_name = (
                    f"new-{utils.gen_bucket_name_from_userid(each_user['user_id'])}"
                )
                log.info(f"creating new bucket with name: {new_bucket_name}")
                new_bucket = reusable.create_bucket(
                    new_bucket_name, rgw_conn, each_user, ip_and_port
                )
                reusable.verify_bucket_sync_on_other_site(rgw_ssh_con, new_bucket)

    if config.multisite_global_sync_policy:
        ceph_version_id, _ = utils.get_ceph_version()
        ceph_version_id = ceph_version_id.split("-")
        ceph_version_id = ceph_version_id[0].split(".")
        if float(ceph_version_id[0]) >= 16:
            if utils.is_cluster_multisite():
                if config.test_ops["group_create"]:
                    group_status = config.test_ops["group_status"]
                    group_id = "global_group"
                    reusable.group_operation(group_id, "create", group_status)
                    if config.test_ops["flow_create"]:
                        flow_type = config.test_ops["flow_type"]
                        zone_names = reusable.flow_operation(
                            group_id, "create", flow_type
                        )
                    if config.test_ops["pipe_create"]:
                        pipe_id = reusable.pipe_operation(
                            group_id, "create", zone_names
                        )
                    if config.test_ops.get("group_transition", False):
                        transition_status = config.test_ops["group_transition_status"]
                        reusable.group_operation(group_id, "modify", transition_status)
                        log.info("Creating new group after transition of old group")
                        group_id2 = "new_group"
                        reusable.group_operation(group_id2, "create", group_status)
                        pipe2 = reusable.pipe_operation(group_id2, "create", zone_names)

    if config.test_ops.get("create_bucket", False):
        for each_user in all_users_info:
            # authenticate
            auth = Auth(each_user, ssh_con, ssl=config.ssl)
            if config.use_aws4 is True:
                rgw_conn = auth.do_auth(**{"signature_version": "s3v4"})
            else:
                rgw_conn = auth.do_auth()
            for bkt in buckets:
                if config.multisite_sync_policy:
                    ceph_version_id, _ = utils.get_ceph_version()
                    ceph_version_id = ceph_version_id.split("-")
                    ceph_version_id = ceph_version_id[0].split(".")
                    if float(ceph_version_id[0]) >= 16:
                        if utils.is_cluster_multisite():
                            if config.test_ops["group_create"]:
                                # modifying global group status to allowed if its not allowed
                                bucket_group_status = config.test_ops[
                                    "bucket_group_status"
                                ]
                                group_info = reusable.get_sync_policy()
                                if group_info["groups"][0]["status"] != "allowed":
                                    reusable.group_operation(
                                        group_id,
                                        "modify",
                                        "allowed",
                                    )
                                group_id1 = "group-" + bkt.name
                                reusable.group_operation(
                                    group_id1,
                                    "create",
                                    bucket_group_status,
                                    bkt.name,
                                )
                                zone_names = None
                                if config.test_ops["pipe_create"]:
                                    pipe_id = reusable.pipe_operation(
                                        group_id1,
                                        "create",
                                        zone_names,
                                        bucket_name=bkt.name,
                                    )

            for bkt in buckets:
                ceph_version_id, _ = utils.get_ceph_version()
                ceph_version_id = ceph_version_id.split("-")
                ceph_version_id = ceph_version_id[0].split(".")
                if float(ceph_version_id[0]) >= 16:
                    if utils.is_cluster_multisite():
                        if config.multisite_sync_policy:
                            if config.test_ops["group_create"]:
                                if config.test_ops["pipe_create"]:
                                    reusable.verify_bucket_sync_policy_on_other_site(
                                        rgw_ssh_con, bkt
                                    )

                                if config.test_ops.get("create_object", False):
                                    # uploading data
                                    log.info(
                                        f"s3 objects to create: {config.objects_count}"
                                    )
                                    for oc, size in list(config.mapped_sizes.items()):
                                        config.obj_size = size
                                        s3_object_name = utils.gen_s3_object_name(
                                            bkt.name, oc
                                        )
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

                                    reusable.verify_object_sync_on_other_site(
                                        rgw_ssh_con, bkt, config
                                    )

                                if config.test_ops["pipe_remove"]:
                                    pipe_id = reusable.pipe_operation(
                                        group_id1,
                                        "remove",
                                        zone_names,
                                        bucket_name=bkt.name,
                                    )

                                if config.test_ops["group_remove"]:
                                    pipe_id = reusable.group_operation(
                                        group_id1,
                                        "remove",
                                        group_status,
                                        bucket_name=bkt.name,
                                    )

                        else:
                            if config.test_ops.get("create_object", False):
                                # uploading data
                                log.info(
                                    f"s3 objects to create: {config.objects_count}"
                                )
                                for oc, size in list(config.mapped_sizes.items()):
                                    config.obj_size = size
                                    s3_object_name = utils.gen_s3_object_name(
                                        bkt.name, oc
                                    )
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

                                reusable.verify_object_sync_on_other_site(
                                    rgw_ssh_con, bkt, config
                                )

            if config.test_ops.get("new_bucket_and_group_state_change", False):
                reusable.group_operation(group_id, "modify", "enabled")
                newgroup_id = f"new-group-{new_bucket_name}"
                reusable.group_operation(
                    newgroup_id,
                    "create",
                    "allowed",
                    new_bucket_name,
                )
                zone_names = None
                pipe_id = reusable.pipe_operation(
                    newgroup_id,
                    "create",
                    zone_names,
                    bucket_name=new_bucket_name,
                )
                reusable.verify_bucket_sync_policy_on_other_site(
                    rgw_ssh_con, new_bucket
                )
                log.info(f"s3 objects to create: {config.objects_count}")
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(new_bucket_name, oc)
                    log.info(f"s3 object name: {s3_object_name}")
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info(f"s3 object path: {s3_object_path}")
                    reusable.upload_object(
                        s3_object_name,
                        new_bucket,
                        TEST_DATA_PATH,
                        config,
                        each_user,
                    )

                reusable.verify_object_sync_on_other_site(
                    rgw_ssh_con, new_bucket, config
                )

    if config.test_ops["pipe_remove"]:
        pipe_id = reusable.pipe_operation(group_id, "remove", zone_names)

    if config.test_ops["flow_remove"]:
        flow_type = config.test_ops["flow_type"]
        zone_names = reusable.flow_operation(group_id, "remove", flow_type)

    if config.test_ops["group_remove"]:
        group_id = reusable.group_operation(group_id, "remove", group_status)
        if config.test_ops.get("group_transition", False):
            reusable.group_operation(group_id2, "remove", group_status)
        utils.exec_shell_cmd(f"radosgw-admin period update --commit")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

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
