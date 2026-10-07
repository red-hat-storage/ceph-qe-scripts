"""
test_s3vectors_basic.py - Test S3 Vectors basic CRUD operations

Usage: test_s3vectors_basic.py -c <input_yaml>

<input_yaml>
    test_s3vectors_basic.yaml

Operation:
    - Create, get, list, and delete vector buckets
    - Create, get, list, and delete indexes
    - Verify vector bucket and index metadata
    - Verify delete-bucket-with-indexes is rejected
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import s3vectors as s3v
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    s3v_cfg = config.test_ops.get("s3vectors", {})
    dimension = s3v_cfg.get("dimension", 4)
    distance_metric = s3v_cfg.get("distance_metric", "euclidean")
    vector_bucket_count = s3v_cfg.get("vector_bucket_count", 2)
    index_count = s3v_cfg.get("index_count", 3)

    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        s3_client = auth.do_auth_using_client()
        s3v_client = s3v.create_s3vectors_client(auth)

        created_buckets = []

        try:
            # ---------------------------------------------------------------
            # TEST 1: Create vector buckets
            # ---------------------------------------------------------------
            log.info("TEST 1: Create vector buckets")
            for i in range(vector_bucket_count):
                bname = s3v.gen_vector_bucket_name(each_user["user_id"], i)
                resp = s3v.create_vector_bucket(s3v_client, bname, s3_client)
                assert "vectorBucketArn" in resp, "Missing vectorBucketArn in response"
                created_buckets.append(bname)
            log.info(f"TEST 1 PASSED: created {vector_bucket_count} vector bucket(s)")

            # ---------------------------------------------------------------
            # TEST 2: Get vector bucket
            # ---------------------------------------------------------------
            log.info("TEST 2: Get vector bucket")
            resp = s3v.get_vector_bucket(s3v_client, created_buckets[0])
            assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
            log.info("TEST 2 PASSED: get_vector_bucket succeeded")

            # ---------------------------------------------------------------
            # TEST 3: List vector buckets
            # ---------------------------------------------------------------
            log.info("TEST 3: List vector buckets")
            resp = s3v.list_vector_buckets(s3v_client)
            listed_names = [b["vectorBucketName"] for b in resp.get("vectorBuckets", [])]
            for bname in created_buckets:
                assert bname in listed_names, f"Bucket '{bname}' not in listing"
            log.info("TEST 3 PASSED: all created buckets appear in listing")

            # ---------------------------------------------------------------
            # TEST 4: List vector buckets with prefix
            # ---------------------------------------------------------------
            log.info("TEST 4: List vector buckets with prefix")
            prefix = f"vb-{each_user['user_id']}"[:20]
            resp = s3v.list_vector_buckets(s3v_client, prefix=prefix)
            listed = resp.get("vectorBuckets", [])
            assert len(listed) >= vector_bucket_count, (
                f"Expected >= {vector_bucket_count} buckets with prefix '{prefix}', "
                f"got {len(listed)}"
            )
            log.info("TEST 4 PASSED: prefix listing works")

            # ---------------------------------------------------------------
            # TEST 5: Create indexes
            # ---------------------------------------------------------------
            log.info("TEST 5: Create indexes")
            target_bucket = created_buckets[0]
            created_indexes = []
            for i in range(index_count):
                idx_name = f"idx-{i}"
                resp = s3v.create_index(
                    s3v_client, target_bucket, idx_name, dimension, distance_metric
                )
                assert "indexArn" in resp, "Missing indexArn in response"
                created_indexes.append(idx_name)
            log.info(f"TEST 5 PASSED: created {index_count} index(es)")

            # ---------------------------------------------------------------
            # TEST 6: Get index and verify details
            # ---------------------------------------------------------------
            log.info("TEST 6: Get index and verify details")
            resp = s3v.get_index(s3v_client, target_bucket, created_indexes[0])
            idx_info = resp.get("index", resp)
            assert idx_info.get("dimension") == dimension, (
                f"Expected dimension={dimension}, got {idx_info.get('dimension')}"
            )
            assert idx_info.get("distanceMetric") == distance_metric, (
                f"Expected metric={distance_metric}, got {idx_info.get('distanceMetric')}"
            )
            assert idx_info.get("dataType") == "float32"
            log.info("TEST 6 PASSED: index metadata verified")

            # ---------------------------------------------------------------
            # TEST 7: List indexes
            # ---------------------------------------------------------------
            log.info("TEST 7: List indexes")
            resp = s3v.list_indexes(s3v_client, target_bucket)
            listed_idx = [ix["indexName"] for ix in resp.get("indexes", [])]
            for idx_name in created_indexes:
                assert idx_name in listed_idx, f"Index '{idx_name}' not listed"
            log.info("TEST 7 PASSED: all indexes appear in listing")

            # ---------------------------------------------------------------
            # TEST 8: List indexes with prefix
            # ---------------------------------------------------------------
            log.info("TEST 8: List indexes with prefix")
            resp = s3v.list_indexes(s3v_client, target_bucket, prefix="idx-")
            listed_idx = resp.get("indexes", [])
            assert len(listed_idx) == index_count
            log.info("TEST 8 PASSED: prefix index listing works")

            # ---------------------------------------------------------------
            # TEST 9: Delete vector bucket with indexes should fail
            # ---------------------------------------------------------------
            log.info("TEST 9: Delete vector bucket that still has indexes")
            try:
                s3v.delete_vector_bucket(s3v_client, target_bucket)
                raise TestExecError(
                    "delete_vector_bucket should have failed (bucket has indexes)"
                )
            except s3v_client.exceptions.ClientError as e:
                err_code = e.response["ResponseMetadata"]["HTTPStatusCode"]
                log.info(f"Correctly rejected with HTTP {err_code}")
            log.info("TEST 9 PASSED: delete rejected for non-empty bucket")

            # ---------------------------------------------------------------
            # TEST 10: Delete an index then verify listing
            # ---------------------------------------------------------------
            log.info("TEST 10: Delete index and verify")
            s3v.delete_index(s3v_client, target_bucket, created_indexes[0])
            resp = s3v.list_indexes(s3v_client, target_bucket)
            remaining = [ix["indexName"] for ix in resp.get("indexes", [])]
            assert created_indexes[0] not in remaining, "Deleted index still listed"
            assert len(remaining) == index_count - 1
            log.info("TEST 10 PASSED: index deleted and removed from listing")

            # ---------------------------------------------------------------
            # TEST 11: Delete remaining indexes and vector buckets
            # ---------------------------------------------------------------
            log.info("TEST 11: Full cleanup and verify")
            for bname in created_buckets:
                s3v.delete_all_indexes(s3v_client, bname)
                s3v.delete_vector_bucket(s3v_client, bname)
            resp = s3v.list_vector_buckets(s3v_client, prefix=prefix)
            remaining_buckets = resp.get("vectorBuckets", [])
            assert len(remaining_buckets) == 0, "Vector buckets still exist after deletion"
            log.info("TEST 11 PASSED: all vector buckets cleaned up")

            created_buckets = []

        finally:
            for bname in created_buckets:
                s3v.cleanup_vector_bucket(s3v_client, bname, s3_client)

    reusable.check_sync_status()
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test S3 Vectors Basic CRUD")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating..")
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
