"""
Usage: test_aws_s3_replication.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    multisite_configs/test_aws_s3_bucket_replication.yaml
"""


import argparse
import json
import logging
import os
import random
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from types import SimpleNamespace

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    # create user
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
    endpoint = aws_reusable.get_endpoint(
        ssh_con, ssl=config.ssl, haproxy=config.haproxy
    )
    for each_user in user_info:
        # authenticate
        user_name = each_user["user_id"]
        log.info(f"user currently being executed {user_name}")
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(each_user)

        period_details = json.loads(utils.exec_shell_cmd("radosgw-admin period get"))
        zone_list = json.loads(utils.exec_shell_cmd("radosgw-admin zone list"))
        for zone in period_details["period_map"]["zonegroups"][0]["zones"]:
            if zone["name"] not in zone_list["zones"]:
                rgw_nodes = zone["endpoints"][0].split(":")
                node_rgw = rgw_nodes[1].split("//")[-1]
                if config.test_ops.get("archive_zone", False):
                    if zone["name"] == "archive":
                        break
                else:
                    break

        log.info(f"Another site is: {zone['name']} and ip {node_rgw}")
        if config.test_ops.get("archive_zone", False):
            if zone["name"] != "archive":
                raise TestExecError(
                    f"archive zone not found {period_details['period_map']['zonegroups'][0]['zones']}"
                )

        rgw_ssh_con = utils.connect_remote(node_rgw)
        if config.test_ops.get("write_io_verify_another_site", False):
            other_site_auth = Auth(each_user, rgw_ssh_con, ssl=config.ssl)
            other_site_rgw_conn = other_site_auth.do_auth()

        # create buckets
        if config.test_ops.get("create_bucket", False):
            buckets = []
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                log.info(f"Bucket {bucket_name} created")

                if config.test_ops.get("enable_version", False):
                    log.info(f"bucket versioning test on bucket: {bucket_name}")
                    aws_reusable.put_get_bucket_versioning(
                        cli_aws, bucket_name, endpoint
                    )

                buckets.append({"name": bucket_name})
                log.info(buckets)
                buckets = [SimpleNamespace(**b) for b in buckets]
                reusable.verify_bucket_sync_on_other_site(rgw_ssh_con, buckets[bc - 1])

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
        for each_user in user_info:
            user_name = each_user["user_id"]
            log.info(f"user currently being executed {user_name}")
            cli_aws = AWS(ssl=config.ssl)
            aws_auth.do_auth_aws(each_user)
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
                    log.info(f"perform put s3 replication on bucket {bkt.name}")
                    aws_reusable.create_s3_replication_json(config, bkt.name)
                    aws_reusable.put_bucket_s3_replication(cli_aws, bkt.name, endpoint)
                    log.info(f"perform get s3 replication on bucket {bkt.name}")
                    aws_reusable.get_bucket_s3_replication(cli_aws, bkt.name, endpoint)

                    reusable.verify_bucket_sync_policy_on_other_site(rgw_ssh_con, bkt)
                    if config.test_ops.get("create_object", False):
                        # uploading data
                        log.info(f"s3 objects to create: {config.objects_count}")
                        for oc, size in list(config.mapped_sizes.items()):
                            config.obj_size = size
                            s3_object_name = f"object-oc-{config.obj_size}"
                            utils.exec_shell_cmd(
                                f"fallocate -l {size} {s3_object_name}"
                            )
                            log.info(f"upload s3 object: {s3_object_name}")
                            aws_reusable.put_object(
                                cli_aws, bkt.name, s3_object_name, endpoint
                            )
                            if config.test_ops.get("enable_version", False):
                                aws_reusable.put_object(
                                    cli_aws, bkt.name, s3_object_name, endpoint
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

                        if config.test_ops.get("write_io_verify_another_site", False):
                            aws_auth.do_auth_aws(each_user, ssh_remote_host=rgw_ssh_con)
                            other_endpoint = aws_reusable.get_endpoint(
                                rgw_ssh_con, ssl=config.ssl, haproxy=config.haproxy
                            )
                            cmd_output = json.loads(
                                aws_auth.run_remote_cmd(
                                    rgw_ssh_con,
                                    f"radosgw-admin bucket stats --bucket {bkt.name}",
                                )
                            )
                            num_objects = (
                                cmd_output["usage"]["rgw.main"]["num_objects"]
                                if "rgw.main" in cmd_output["usage"].keys()
                                else 0
                            )

                            aws_path = aws_auth.run_remote_cmd(
                                rgw_ssh_con, "command -v aws"
                            )
                            aws_cli = f"{aws_path} s3api"
                            for oc, size in list(config.mapped_sizes.items()):
                                config.obj_size = size
                                s3_object_name = f"new-object-oc-{config.obj_size}"
                                rgw_ssh_con.exec_command(
                                    f"fallocate -l {size} {s3_object_name}"
                                )
                                log.info(f"upload s3 object: {s3_object_name}")
                                cmd = f"{aws_cli} put-object --bucket {bkt.name} --key {s3_object_name} --body {s3_object_name} --endpoint {other_endpoint}"
                                log.info(f"executing command: {cmd}")
                                out_resp = aws_auth.run_remote_cmd(rgw_ssh_con, cmd)
                                if config.test_ops.get("enable_version", False):
                                    out_resp = aws_auth.run_remote_cmd(rgw_ssh_con, cmd)

                            re_cmd_output = json.loads(
                                aws_auth.run_remote_cmd(
                                    rgw_ssh_con,
                                    f"radosgw-admin bucket stats --bucket {bkt.name}",
                                )
                            )
                            log.info(f"bucket stats : {re_cmd_output}")
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

                                if config.test_ops.get(
                                    "dest_param_storage_class", False
                                ):
                                    log.info(
                                        f"Start the validation of object sync in destination with staorage class {config.storage_class}"
                                    )
                                    bkt_list = json.loads(
                                        utils.exec_shell_cmd(
                                            f"radosgw-admin bucket list --bucket {bkt.name}"
                                        )
                                    )
                                    for obj in bkt_list:
                                        if obj["name"].startswith(
                                            f"new-key_{bkt.name}_"
                                        ):
                                            if (
                                                obj["meta"]["storage_class"]
                                                != config.storage_class
                                            ):
                                                raise TestExecError(
                                                    f"object synced to master for bucket {bkt.name}, does not belong to storage class {config.storage_class}"
                                                )

                            else:
                                if bkt_objects != config.objects_count:
                                    raise TestExecError(
                                        f"Object should not sync in bucket {bkt.name}, but found {bkt_objects}"
                                    )
                                log.info(
                                    f"Object did not sync for bucket {bkt.name}, on another site as expected"
                                )

                for bkt in buckets:
                    log.info(f"perform delete s3 replication on bucket {bkt.name}")
                    aws_reusable.delete_bucket_s3_replication(
                        cli_aws, bkt.name, endpoint
                    )

    if config.test_ops.get("zonegroup_group_remove", False):
        group_id = reusable.group_operation(group_id, "remove", group_status)
        utils.exec_shell_cmd(f"radosgw-admin period update --commit")

    for i in user_info:
        reusable.remove_user(i)

    # check for any health errors or large omaps
    out = utils.get_ceph_status()
    if not out:
        raise TestExecError(
            "ceph status is either in HEALTH_ERR or we have large omap objects."
        )

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test s3 bucket replication through awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW s3 bucket replication through AWS"
        )
        parser.add_argument(
            "-c", dest="config", help="GW s3 bucket replication through AWS"
        )
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
        config = resource_op.Config(yaml_file)
        config.read()
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
