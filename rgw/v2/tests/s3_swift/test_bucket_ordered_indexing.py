"""
test_bucket_ordered_indexing.py - Bucket ordered index (BOI) sanity

Usage: test_bucket_ordered_indexing.py -c <input_yaml>

<input_yaml>
    configs/test_obi_hashed_to_ordered.yaml
    configs/test_obi_ordered_to_hashed.yaml
    configs/test_obi_hashed_to_hashed.yaml
    configs/test_obi_ordered_to_ordered_negative.yaml

Operation:
    hashed_to_ordered:
      Set rgw_max_objs_per_shard, create buckets (hashed), upload, reshard to
      ordered, upload more, verify list count/order/completeness.

    ordered_to_hashed (includes hashed_to_ordered first):
      Reshard back to hashed, verify no data loss, upload more, verify listing.

    hashed_to_hashed (traditional reshard path):
      Set rgw_max_objs_per_shard, create hashed buckets, upload, reshard to
      hashed with a different shard count (bucket_reshard_manual), verify
      count and listing with no data loss.

    ordered_to_ordered_negative:
      Upload, reshard to ordered, attempt ordered again (expect clear error),
      verify bucket still usable (upload/list/GET), then ordered->hashed and
      hashed->ordered succeed.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import argparse
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
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

    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    max_per_shard = config.max_objects_per_shard or 5
    pre_count = config.objects_count or 100
    post_count = config.test_ops.get("objects_count_post_reshard", 500)
    post_hashed_count = config.test_ops.get("objects_count_post_hashed", 100)
    post_rejected = config.test_ops.get("objects_count_post_rejected", 20)
    shards_retry = config.test_ops.get("shards_retry", 48)
    expected_after_ordered = pre_count + post_count
    do_hashed_to_ordered = config.test_ops.get("hashed_to_ordered", False)
    do_ordered_to_hashed = config.test_ops.get("ordered_to_hashed", False)
    do_hashed_to_hashed = config.test_ops.get("hashed_to_hashed", False)
    do_ordered_to_ordered_neg = config.test_ops.get(
        "ordered_to_ordered_negative", False
    )
    ordered_type = config.test_ops.get("bucket_index_type", "ordered")
    hashed_type = config.test_ops.get("bucket_index_type_hashed", "hashed")

    if do_ordered_to_hashed:
        do_hashed_to_ordered = True
    if not (do_hashed_to_ordered or do_hashed_to_hashed or do_ordered_to_ordered_neg):
        raise TestExecError(
            "enable hashed_to_ordered, ordered_to_hashed, hashed_to_hashed, "
            "and/or ordered_to_ordered_negative"
        )

    log.info(f"setting rgw_max_objs_per_shard={max_per_shard}")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_max_objs_per_shard,
        str(max_per_shard),
        ssh_con,
    )
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    log.info("RGW service restarted")

    user_info = s3lib.create_users(config.user_count or 1)[0]
    auth = reusable.get_auth(user_info, ssh_con, config.ssl, config.haproxy)
    rgw_conn = auth.do_auth()
    s3_client = auth.do_auth_using_client()

    buckets = []
    expected_by_bucket = {}

    log.info(f"creating {config.bucket_count} buckets with default hashed index")
    for bc in range(config.bucket_count):
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info["user_id"], rand_no=bc
        )
        if config.haproxy:
            bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info)
        else:
            bucket = reusable.create_bucket(
                bucket_name, rgw_conn, user_info, ip_and_port
            )
        idx = reusable.get_bucket_index_type(bucket.name)
        log.info(f"bucket {bucket.name} initial index_type={idx}")
        if idx and str(idx).lower() not in ("hashed", "normal"):
            log.warning(f"expected hashed/default index before reshard, got {idx}")
        buckets.append(bucket)
        expected_by_bucket[bucket.name] = set()

    if do_hashed_to_hashed:
        reusable.upload_zero_padded_object_wave(
            buckets,
            expected_by_bucket,
            0,
            pre_count,
            config,
            user_info,
            TEST_DATA_PATH,
            wave_label="pre-reshard (hashed)",
        )
        log.info(
            f"traditional reshard of {len(buckets)} buckets to "
            f"num_shards={config.shards} (hashed)"
        )
        for bucket in buckets:
            reusable.bucket_reshard_manual(bucket, config)
            reusable.assert_bucket_index_type(bucket.name, hashed_type)
        log.info("hashed_to_hashed: verify list after traditional reshard")
        reusable.verify_buckets_list_and_index(
            s3_client,
            buckets,
            expected_by_bucket,
            pre_count,
            hashed_type,
        )

    elif do_ordered_to_ordered_neg:
        reusable.upload_zero_padded_object_wave(
            buckets,
            expected_by_bucket,
            0,
            pre_count,
            config,
            user_info,
            TEST_DATA_PATH,
            wave_label="pre-reshard (hashed)",
        )
        log.info(f"resharding to {ordered_type} with shards={config.shards}")
        for bucket in buckets:
            reusable.bucket_reshard_with_index_type(
                bucket, config, index_type=ordered_type
            )

        log.info(
            f"negative: attempt {ordered_type}->{ordered_type} with "
            f"shards={shards_retry} (expect clear error)"
        )
        for bucket in buckets:
            reusable.expect_bucket_reshard_with_index_type_failure(
                bucket, shards_retry, index_type=ordered_type
            )
            reusable.assert_bucket_index_type(bucket.name, ordered_type)

        log.info("after rejected reshard: verify list intact")
        reusable.verify_buckets_list_and_index(
            s3_client,
            buckets,
            expected_by_bucket,
            pre_count,
            ordered_type,
        )

        reusable.upload_zero_padded_object_wave(
            buckets,
            expected_by_bucket,
            pre_count,
            post_rejected,
            config,
            user_info,
            TEST_DATA_PATH,
            wave_label="post-rejected-reshard",
        )
        expected_after_reject = pre_count + post_rejected
        log.info("after rejected reshard: verify list + GET still work")
        reusable.verify_buckets_list_and_index(
            s3_client,
            buckets,
            expected_by_bucket,
            expected_after_reject,
            ordered_type,
        )
        for bucket in buckets:
            reusable.verify_object_gets(
                s3_client, bucket.name, expected_by_bucket[bucket.name]
            )

        log.info(f"valid path: reshard to {hashed_type} (must succeed)")
        for bucket in buckets:
            reusable.bucket_reshard_with_index_type(
                bucket, config, index_type=hashed_type
            )
            reusable.assert_bucket_index_type(bucket.name, hashed_type)
        reusable.verify_buckets_list_and_index(
            s3_client,
            buckets,
            expected_by_bucket,
            expected_after_reject,
            hashed_type,
        )

        log.info(f"valid path: reshard back to {ordered_type} (must succeed)")
        for bucket in buckets:
            reusable.bucket_reshard_with_index_type(
                bucket, config, index_type=ordered_type
            )
            reusable.assert_bucket_index_type(bucket.name, ordered_type)
        reusable.verify_buckets_list_and_index(
            s3_client,
            buckets,
            expected_by_bucket,
            expected_after_reject,
            ordered_type,
        )

    elif do_hashed_to_ordered:
        reusable.upload_zero_padded_object_wave(
            buckets,
            expected_by_bucket,
            0,
            pre_count,
            config,
            user_info,
            TEST_DATA_PATH,
            wave_label="pre-reshard (hashed)",
        )
        log.info(f"resharding {len(buckets)} buckets to index_type={ordered_type}")
        for bucket in buckets:
            reusable.bucket_reshard_with_index_type(
                bucket, config, index_type=ordered_type
            )
        reusable.upload_zero_padded_object_wave(
            buckets,
            expected_by_bucket,
            pre_count,
            post_count,
            config,
            user_info,
            TEST_DATA_PATH,
            wave_label="post-reshard (ordered)",
        )
        log.info("hashed_to_ordered: verify list after hashed->ordered")
        reusable.verify_buckets_list_and_index(
            s3_client,
            buckets,
            expected_by_bucket,
            expected_after_ordered,
            ordered_type,
        )

        if do_ordered_to_hashed:
            log.info(f"resharding {len(buckets)} buckets back to {hashed_type}")
            for bucket in buckets:
                reusable.bucket_reshard_with_index_type(
                    bucket, config, index_type=hashed_type
                )
                reusable.assert_bucket_index_type(bucket.name, hashed_type)

            log.info("ordered_to_hashed: verify list (no data loss)")
            reusable.verify_buckets_list_and_index(
                s3_client,
                buckets,
                expected_by_bucket,
                expected_after_ordered,
                hashed_type,
            )

            reusable.upload_zero_padded_object_wave(
                buckets,
                expected_by_bucket,
                expected_after_ordered,
                post_hashed_count,
                config,
                user_info,
                TEST_DATA_PATH,
                wave_label="post-reshard (hashed)",
            )
            expected_final = expected_after_ordered + post_hashed_count
            log.info("ordered_to_hashed: verify listing after additional uploads")
            reusable.verify_buckets_list_and_index(
                s3_client,
                buckets,
                expected_by_bucket,
                expected_final,
                hashed_type,
            )

    if config.test_ops.get("delete_bucket_object", False):
        for bucket in buckets:
            reusable.delete_objects(bucket)
            reusable.delete_bucket(bucket)

    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW bucket ordered indexing sanity")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW bucket ordered indexing")
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
