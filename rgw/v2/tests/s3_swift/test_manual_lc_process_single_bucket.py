"""
Test LC process for a single bucket: CEPH-83574809
Usage: test_manual_lc_process_single_bucket.py -c configs/<input-yaml>
where : <input-yaml> are test_lc_process_single_bucket_expired.yaml or
                        test_lc_process_single_bucket_nonexpired.yaml
Operation:
-Create a user and two bucket
-Upload objects
-setlifecycle to both the bucket
-Perform radosgw-admin lc process on one bucket
-check once the lc reaches complete state, lc process is happened for only one bucket which was given
-check all the expired objects are deleted
-Non expired objects are not deleted
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # create user
    user_info = s3lib.create_users(config.user_count)
    for each_user in user_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        buckets = []
        buckets_meta = []
        if config.test_ops["create_bucket"]:
            log.info("no of buckets to create: %s" % config.bucket_count)
            # create bucket
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                bucket = reusable.create_bucket(
                    bucket_name, rgw_conn, each_user, ip_and_port
                )
                buckets.append(bucket_name)
                buckets_meta.append(bucket)
                if config.test_ops["create_object"]:
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        log.info(f"s3 objects to create of size {config.obj_size}")
                        s3_object_name = config.lifecycle_conf[0]["Filter"][
                            "Prefix"
                        ] + str(oc)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info(
                            f"s3 object path: {s3_object_path}, name: {s3_object_name}"
                        )
                        reusable.upload_object(
                            s3_object_name, bucket, TEST_DATA_PATH, config, each_user
                        )
                life_cycle_rule = {"Rules": config.lifecycle_conf}
                reusable.put_bucket_lifecycle(
                    bucket, rgw_conn, rgw_conn2, life_cycle_rule
                )

        log.info(f"buckets are {buckets}")

        for bkt in buckets:
            bucket_details = json.loads(
                utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket={bkt}")
            )
            num_objects = bucket_details["usage"]["rgw.main"]["num_objects"]
            log.info(f"objects count in bucket {bkt} is {num_objects}")

        lc_list_op_before = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
        log.info(f"lc lists before lc process is {lc_list_op_before}")

        utils.exec_shell_cmd(f"radosgw-admin lc process --bucket {buckets[0]}")
        time.sleep(60)
        lc_list_op_after = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
        log.info(f"lc lists after lc process is {lc_list_op_after}")
        completed_bucket = 0
        completed_bkt_name = ""
        for data in lc_list_op_after:
            if data["status"] == "COMPLETE" and buckets[0] in data["bucket"]:
                completed_bucket += 1
                completed_bkt_name = data["bucket"]
        log.info(f"Manual LC process completed bucket is {completed_bkt_name}")
        bucket_details = json.loads(
            utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket={buckets[0]}")
        )
        num_objects_after = bucket_details["usage"]["rgw.main"]["num_objects"]

        if config.object_expire:
            if (
                completed_bucket == 1
                and (buckets[0] in completed_bkt_name)
                and num_objects_after == 0
            ):
                log.info(f"processing of single bucket:{buckets[0]} succeeded")
            else:
                raise TestExecError("LC Processing of a single bucket failed")
        else:
            if (
                completed_bucket == 1
                and (buckets[0] in completed_bkt_name)
                and num_objects_after == config.objects_count
            ):
                log.info(f"Successfully completed, non-expired objects did not deleted")
            else:
                raise TestExecError(
                    "Failed! removed non-expired objects from the bucket"
                )

        delete_conf = config.lifecycle_conf[0]
        delete_conf["Status"] = "Disabled"
        for bkt in buckets_meta:
            life_cycle_rule_delete = {"Rules": [delete_conf]}
            reusable.put_bucket_lifecycle(
                bkt, rgw_conn, rgw_conn2, life_cycle_rule_delete
            )


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
        parser = argparse.ArgumentParser(
            description="RGW lc process for a single bucket"
        )
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
        log.exception(e)
        test_info.failed_status("test failed")
        sys.exit(1)
