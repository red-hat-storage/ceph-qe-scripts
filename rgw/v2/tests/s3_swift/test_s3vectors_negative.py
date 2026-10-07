"""
test_s3vectors_negative.py - Test S3 Vectors negative and edge cases

Usage: test_s3vectors_negative.py -c <input_yaml>

<input_yaml>
    test_s3vectors_negative.yaml

Operation:
    - Dimension mismatch on put_vectors
    - Get/delete non-existent vector bucket and index
    - Put vectors to non-existent index
    - Delete vector bucket that still has indexes
    - Duplicate vector bucket creation (idempotent)
    - Duplicate index creation
    - Query with topK exceeding max (10000)
    - Put vectors with malformed metadata
    - Multiple indexes in a single vector bucket
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
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


def _expect_client_error(s3v_client, func, expected_http_codes, description):
    """Call *func* and assert it raises ClientError with one of the expected codes."""
    try:
        func()
        raise TestExecError(f"{description}: expected failure but succeeded")
    except s3v_client.exceptions.ClientError as e:
        code = e.response["ResponseMetadata"]["HTTPStatusCode"]
        if code not in expected_http_codes:
            raise TestExecError(
                f"{description}: expected HTTP {expected_http_codes}, got {code}"
            )
        log.info(f"{description}: correctly rejected with HTTP {code}")


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    s3v_cfg = config.test_ops.get("s3vectors", {})
    dimension = s3v_cfg.get("dimension", 4)
    distance_metric = s3v_cfg.get("distance_metric", "euclidean")

    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        s3_client = auth.do_auth_using_client()
        s3v_client = s3v.create_s3vectors_client(auth)

        bucket_name = s3v.gen_vector_bucket_name(each_user["user_id"], 0)
        index_name = "neg-index"

        try:
            # -- setup --
            s3v.create_vector_bucket(s3v_client, bucket_name, s3_client)
            s3v.create_index(
                s3v_client, bucket_name, index_name, dimension, distance_metric
            )

            # ---------------------------------------------------------------
            # TEST 1: Put vectors with wrong dimension
            # ---------------------------------------------------------------
            log.info("TEST 1: Put vectors with dimension mismatch")
            wrong_dim_vectors = [
                {
                    "key": "bad-dim",
                    "data": {"float32": [0.1, 0.2]},  # dim=2 vs index dim=4
                }
            ]
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.put_vectors(
                    vectorBucketName=bucket_name,
                    indexName=index_name,
                    vectors=wrong_dim_vectors,
                ),
                [400],
                "Dimension mismatch",
            )
            log.info("TEST 1 PASSED")

            # ---------------------------------------------------------------
            # TEST 2: Get non-existent vector bucket
            # ---------------------------------------------------------------
            log.info("TEST 2: Get non-existent vector bucket")
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.get_vector_bucket(
                    vectorBucketName="no-such-vb-bucket-xyz"
                ),
                [404],
                "Non-existent vector bucket",
            )
            log.info("TEST 2 PASSED")

            # ---------------------------------------------------------------
            # TEST 3: Get non-existent index
            # ---------------------------------------------------------------
            log.info("TEST 3: Get non-existent index")
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.get_index(
                    vectorBucketName=bucket_name,
                    indexName="no-such-index-xyz",
                ),
                [404],
                "Non-existent index",
            )
            log.info("TEST 3 PASSED")

            # ---------------------------------------------------------------
            # TEST 4: Put vectors to non-existent index
            # ---------------------------------------------------------------
            log.info("TEST 4: Put vectors to non-existent index")
            vectors = s3v.generate_vectors(1, dimension)
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.put_vectors(
                    vectorBucketName=bucket_name,
                    indexName="no-such-index-xyz",
                    vectors=vectors,
                ),
                [404],
                "Put to non-existent index",
            )
            log.info("TEST 4 PASSED")

            # ---------------------------------------------------------------
            # TEST 5: Delete vector bucket that has indexes
            # ---------------------------------------------------------------
            log.info("TEST 5: Delete vector bucket with existing indexes")
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.delete_vector_bucket(
                    vectorBucketName=bucket_name
                ),
                [409, 400],
                "Delete non-empty bucket",
            )
            log.info("TEST 5 PASSED")

            # ---------------------------------------------------------------
            # TEST 6: Duplicate vector bucket creation (should be idempotent)
            # ---------------------------------------------------------------
            log.info("TEST 6: Duplicate vector bucket creation")
            resp = s3v_client.create_vector_bucket(vectorBucketName=bucket_name)
            assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
                "Duplicate vector bucket creation should succeed (idempotent)"
            )
            log.info("TEST 6 PASSED: duplicate creation is idempotent")

            # ---------------------------------------------------------------
            # TEST 7: Put vectors with malformed metadata
            # ---------------------------------------------------------------
            log.info("TEST 7: Put vectors with malformed metadata")
            bad_md_vectors = [
                {
                    "key": "bad-md",
                    "data": {"float32": s3v.generate_vector_data(dimension, 0)},
                    "metadata": '{"broken": "missing end brace',
                }
            ]
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.put_vectors(
                    vectorBucketName=bucket_name,
                    indexName=index_name,
                    vectors=bad_md_vectors,
                ),
                [400],
                "Malformed metadata",
            )
            log.info("TEST 7 PASSED")

            # ---------------------------------------------------------------
            # TEST 8: Multiple indexes in a single vector bucket
            # ---------------------------------------------------------------
            log.info("TEST 8: Multiple indexes in one bucket")
            idx_names = ["multi-a", "multi-b", "multi-c"]
            for iname in idx_names:
                s3v.create_index(
                    s3v_client, bucket_name, iname, dimension, distance_metric
                )

            for iname in idx_names:
                vectors = s3v.generate_vectors(5, dimension, key_prefix=iname)
                s3v.put_vectors(s3v_client, bucket_name, iname, vectors)

            for iname in idx_names:
                resp = s3v.list_vectors(
                    s3v_client, bucket_name, iname, max_results=100
                )
                assert len(resp.get("vectors", [])) == 5, (
                    f"Index '{iname}' should have 5 vectors"
                )

            for iname in idx_names:
                s3v.delete_index(s3v_client, bucket_name, iname)
            log.info("TEST 8 PASSED: multiple indexes work independently")

            # ---------------------------------------------------------------
            # TEST 9: Delete non-existent index
            # ---------------------------------------------------------------
            log.info("TEST 9: Delete non-existent index")
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.delete_index(
                    vectorBucketName=bucket_name,
                    indexName="ghost-index",
                ),
                [404],
                "Delete non-existent index",
            )
            log.info("TEST 9 PASSED")

            # ---------------------------------------------------------------
            # TEST 10: Query with topK > 10000
            # ---------------------------------------------------------------
            log.info("TEST 10: Query with topK > 10000")
            s3v.put_vectors(
                s3v_client, bucket_name, index_name,
                s3v.generate_vectors(2, dimension)
            )
            query_vec = {"float32": s3v.generate_vector_data(dimension, seed=0)}
            _expect_client_error(
                s3v_client,
                lambda: s3v_client.query_vectors(
                    vectorBucketName=bucket_name,
                    indexName=index_name,
                    queryVector=query_vec,
                    topK=10001,
                ),
                [400],
                "topK > 10000",
            )
            log.info("TEST 10 PASSED")

            # ---------------------------------------------------------------
            # TEST 11: Get vectors with non-existent keys
            # ---------------------------------------------------------------
            log.info("TEST 11: Get vectors with non-existent keys")
            resp = s3v_client.get_vectors(
                vectorBucketName=bucket_name,
                indexName=index_name,
                keys=["no-such-key-1", "no-such-key-2"],
                returnData=True,
            )
            returned = resp.get("vectors", [])
            assert len(returned) == 0, (
                f"Expected 0 vectors for non-existent keys, got {len(returned)}"
            )
            log.info("TEST 11 PASSED: non-existent keys return empty list")

            # ---------------------------------------------------------------
            # TEST 12: Cosine distance metric index
            # ---------------------------------------------------------------
            log.info("TEST 12: Create index with cosine metric")
            cosine_idx = "cosine-idx"
            s3v.create_index(
                s3v_client, bucket_name, cosine_idx, dimension, "cosine"
            )
            resp = s3v.get_index(s3v_client, bucket_name, cosine_idx)
            idx_info = resp.get("index", resp)
            assert idx_info.get("distanceMetric") == "cosine"
            s3v.put_vectors(
                s3v_client, bucket_name, cosine_idx,
                s3v.generate_vectors(5, dimension)
            )
            resp = s3v.query_vectors(
                s3v_client, bucket_name, cosine_idx,
                {"float32": s3v.generate_vector_data(dimension, seed=0)},
                top_k=3, return_distance=True
            )
            assert resp.get("distanceMetric") == "cosine"
            assert len(resp.get("vectors", [])) == 3
            s3v.delete_index(s3v_client, bucket_name, cosine_idx)
            log.info("TEST 12 PASSED: cosine index works correctly")

        finally:
            s3v.cleanup_vector_bucket(s3v_client, bucket_name, s3_client)

    reusable.check_sync_status()
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test S3 Vectors Negative and Edge Cases")
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
