"""
test_s3vectors_operations.py - Test S3 Vectors data operations

Usage: test_s3vectors_operations.py -c <input_yaml>

<input_yaml>
    test_s3vectors_operations.yaml

Operation:
    - Put, get, list, and delete vectors
    - Upsert (update existing key)
    - Pagination of list_vectors
    - Query nearest neighbours with distance and metadata
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


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    s3v_cfg = config.test_ops.get("s3vectors", {})
    dimension = s3v_cfg.get("dimension", 4)
    distance_metric = s3v_cfg.get("distance_metric", "euclidean")
    vector_count = s3v_cfg.get("vector_count", 20)
    top_k = s3v_cfg.get("top_k", 5)

    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        s3_client = auth.do_auth_using_client()
        s3v_client = s3v.create_s3vectors_client(auth)

        bucket_name = s3v.gen_vector_bucket_name(each_user["user_id"], 0)
        index_name = "ops-index"

        try:
            # -- setup --
            s3v.create_vector_bucket(s3v_client, bucket_name, s3_client)
            s3v.create_index(
                s3v_client, bucket_name, index_name, dimension, distance_metric
            )

            # ---------------------------------------------------------------
            # TEST 1: Put vectors
            # ---------------------------------------------------------------
            log.info("TEST 1: Put vectors")
            vectors = s3v.generate_vectors(vector_count, dimension)
            s3v.put_vectors(s3v_client, bucket_name, index_name, vectors)
            log.info(f"TEST 1 PASSED: {vector_count} vectors inserted")

            # ---------------------------------------------------------------
            # TEST 2: Get vectors with data
            # ---------------------------------------------------------------
            log.info("TEST 2: Get vectors with data")
            keys = [v["key"] for v in vectors[:5]]
            resp = s3v.get_vectors(s3v_client, bucket_name, index_name, keys)
            returned = resp.get("vectors", [])
            assert len(returned) == 5, f"Expected 5 vectors, got {len(returned)}"
            for v in returned:
                assert "data" in v, f"Vector '{v['key']}' missing 'data'"
                assert len(v["data"]["float32"]) == dimension, (
                    f"Vector '{v['key']}' has wrong dimension"
                )
            log.info("TEST 2 PASSED: get_vectors returned correct data")

            # ---------------------------------------------------------------
            # TEST 3: Put vectors with metadata and get with returnMetadata
            # ---------------------------------------------------------------
            log.info("TEST 3: Put vectors with metadata")
            md_vectors = s3v.generate_vectors(
                5, dimension, with_metadata=True, key_prefix="md"
            )
            s3v.put_vectors(s3v_client, bucket_name, index_name, md_vectors)
            md_keys = [v["key"] for v in md_vectors]
            resp = s3v.get_vectors(
                s3v_client, bucket_name, index_name, md_keys,
                return_data=True, return_metadata=True
            )
            for v in resp.get("vectors", []):
                assert "metadata" in v, f"Vector '{v['key']}' missing metadata"
                md = json.loads(v["metadata"])
                assert "category" in md, "Metadata missing 'category'"
                assert "year" in md, "Metadata missing 'year'"
            log.info("TEST 3 PASSED: metadata stored and retrieved correctly")

            # ---------------------------------------------------------------
            # TEST 4: Get vectors without returnData
            # ---------------------------------------------------------------
            log.info("TEST 4: Get vectors without data")
            resp = s3v.get_vectors(
                s3v_client, bucket_name, index_name, keys,
                return_data=False, return_metadata=False
            )
            for v in resp.get("vectors", []):
                assert "data" not in v, f"Vector '{v['key']}' should not have data"
                assert "metadata" not in v, f"Vector '{v['key']}' should not have metadata"
            log.info("TEST 4 PASSED: returnData=False hides vector data")

            # ---------------------------------------------------------------
            # TEST 5: List vectors
            # ---------------------------------------------------------------
            log.info("TEST 5: List vectors")
            resp = s3v.list_vectors(s3v_client, bucket_name, index_name, max_results=500)
            listed = resp.get("vectors", [])
            total_expected = vector_count + 5  # original + metadata vectors
            assert len(listed) == total_expected, (
                f"Expected {total_expected} vectors, got {len(listed)}"
            )
            log.info("TEST 5 PASSED: list_vectors returned all vectors")

            # ---------------------------------------------------------------
            # TEST 6: List vectors with pagination
            # ---------------------------------------------------------------
            log.info("TEST 6: List vectors with pagination")
            page_size = 5
            all_keys = set()
            next_token = None
            pages = 0
            while True:
                resp = s3v.list_vectors(
                    s3v_client, bucket_name, index_name,
                    max_results=page_size, next_token=next_token
                )
                page_vectors = resp.get("vectors", [])
                for v in page_vectors:
                    all_keys.add(v["key"])
                pages += 1
                next_token = resp.get("nextToken")
                if not next_token or not page_vectors:
                    break
            assert len(all_keys) == total_expected, (
                f"Pagination collected {len(all_keys)} keys, expected {total_expected}"
            )
            log.info(f"TEST 6 PASSED: pagination over {pages} pages collected all keys")

            # ---------------------------------------------------------------
            # TEST 7: List vectors with returnData and returnMetadata
            # ---------------------------------------------------------------
            log.info("TEST 7: List vectors with data and metadata")
            resp = s3v.list_vectors(
                s3v_client, bucket_name, index_name,
                max_results=500, return_data=True, return_metadata=True
            )
            for v in resp.get("vectors", []):
                assert "data" in v, f"Vector '{v['key']}' missing data"
            log.info("TEST 7 PASSED: list_vectors returns data when requested")

            # ---------------------------------------------------------------
            # TEST 8: Delete vectors
            # ---------------------------------------------------------------
            log.info("TEST 8: Delete vectors")
            delete_keys = [f"vec-{i}" for i in range(3)]
            s3v.delete_vectors(s3v_client, bucket_name, index_name, delete_keys)
            resp = s3v.list_vectors(s3v_client, bucket_name, index_name, max_results=500)
            remaining_keys = {v["key"] for v in resp.get("vectors", [])}
            for dk in delete_keys:
                assert dk not in remaining_keys, f"Deleted key '{dk}' still present"
            assert len(remaining_keys) == total_expected - 3
            log.info("TEST 8 PASSED: vectors deleted successfully")

            # ---------------------------------------------------------------
            # TEST 9: Upsert (put with existing key)
            # ---------------------------------------------------------------
            log.info("TEST 9: Upsert vectors")
            upsert_key = "vec-5"
            new_data = s3v.generate_vector_data(dimension, seed=999)
            upsert_vec = [
                {
                    "key": upsert_key,
                    "data": {"float32": new_data},
                    "metadata": json.dumps({"category": "updated", "year": 9999}),
                }
            ]
            s3v.put_vectors(s3v_client, bucket_name, index_name, upsert_vec)
            resp = s3v.get_vectors(
                s3v_client, bucket_name, index_name, [upsert_key],
                return_data=True, return_metadata=True
            )
            returned = resp.get("vectors", [])
            assert len(returned) == 1
            assert returned[0]["data"]["float32"] == new_data, "Vector data not updated"
            md = json.loads(returned[0]["metadata"])
            assert md["year"] == 9999, "Metadata not updated after upsert"
            log.info("TEST 9 PASSED: upsert replaced vector data and metadata")

            # ---------------------------------------------------------------
            # TEST 10: Basic query
            # ---------------------------------------------------------------
            log.info("TEST 10: Basic query (nearest neighbours)")
            query_vec = {"float32": s3v.generate_vector_data(dimension, seed=5)}
            resp = s3v.query_vectors(
                s3v_client, bucket_name, index_name, query_vec, top_k
            )
            result_vectors = resp.get("vectors", [])
            assert len(result_vectors) == top_k, (
                f"Expected {top_k} results, got {len(result_vectors)}"
            )
            result_keys = [v["key"] for v in result_vectors]
            assert "vec-5" in result_keys or upsert_key in result_keys, (
                "Exact-match vector not in top results"
            )
            log.info("TEST 10 PASSED: query returned top-K results")

            # ---------------------------------------------------------------
            # TEST 11: Query with returnDistance
            # ---------------------------------------------------------------
            log.info("TEST 11: Query with returnDistance")
            resp = s3v.query_vectors(
                s3v_client, bucket_name, index_name, query_vec, top_k,
                return_distance=True
            )
            for v in resp.get("vectors", []):
                assert "distance" in v, f"Vector '{v['key']}' missing distance"
            assert resp.get("distanceMetric") == distance_metric
            log.info("TEST 11 PASSED: distances returned correctly")

            # ---------------------------------------------------------------
            # TEST 12: Query with returnMetadata
            # ---------------------------------------------------------------
            log.info("TEST 12: Query with returnMetadata")
            resp = s3v.query_vectors(
                s3v_client, bucket_name, index_name, query_vec, top_k,
                return_metadata=True
            )
            log.info("TEST 12 PASSED: query with metadata succeeded")

            # ---------------------------------------------------------------
            # TEST 13: Query with topK=1
            # ---------------------------------------------------------------
            log.info("TEST 13: Query with topK=1")
            resp = s3v.query_vectors(
                s3v_client, bucket_name, index_name, query_vec, 1,
                return_distance=True
            )
            assert len(resp.get("vectors", [])) == 1
            log.info("TEST 13 PASSED: topK=1 returns exactly 1 result")

        finally:
            s3v.cleanup_vector_bucket(s3v_client, bucket_name, s3_client)

    reusable.check_sync_status()
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test S3 Vectors Data Operations")
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
