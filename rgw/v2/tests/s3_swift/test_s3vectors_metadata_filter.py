"""
test_s3vectors_metadata_filter.py - Test S3 Vectors metadata and filtered queries

Usage: test_s3vectors_metadata_filter.py -c <input_yaml>

<input_yaml>
    test_s3vectors_metadata_filter.yaml

Operation:
    - Create index with filterable metadata keys
    - Put vectors with typed metadata
    - Query with equality, comparison, set, boolean, and logical filters
    - Query with mixed column + JSON metadata filters
    - Verify non-filterable metadata is stored and returned
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

SAMPLE_VECTORS = [
    {
        "key": "v0",
        "metadata": json.dumps(
            {"genre": "rock", "year": 2020, "popular": True, "color": "red"}
        ),
    },
    {
        "key": "v1",
        "metadata": json.dumps(
            {"genre": "jazz", "year": 2019, "popular": False, "color": "blue"}
        ),
    },
    {
        "key": "v2",
        "metadata": json.dumps(
            {"genre": "rock", "year": 2018, "popular": True, "color": "red"}
        ),
    },
    {
        "key": "v3",
        "metadata": json.dumps(
            {"genre": "pop", "year": 2021, "popular": False, "color": "green"}
        ),
    },
    {
        "key": "v4",
        "metadata": json.dumps(
            {"genre": "jazz", "year": 2020, "popular": True, "color": "red"}
        ),
    },
]


def _attach_vector_data(vectors, dimension):
    """Add deterministic float32 data to each vector dict."""
    for i, v in enumerate(vectors):
        v["data"] = {"float32": s3v.generate_vector_data(dimension, seed=i)}


def _query_keys(s3v_client, bucket_name, index_name, dimension, filter_expr):
    """Run a filtered query and return sorted list of matched keys."""
    query_vec = {"float32": s3v.generate_vector_data(dimension, seed=0)}
    resp = s3v.query_vectors(
        s3v_client, bucket_name, index_name, query_vec, top_k=10,
        filter_expr=filter_expr
    )
    return sorted([v["key"] for v in resp.get("vectors", [])])


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    s3v_cfg = config.test_ops.get("s3vectors", {})
    dimension = s3v_cfg.get("dimension", 4)

    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        s3_client = auth.do_auth_using_client()
        s3v_client = s3v.create_s3vectors_client(auth)

        bucket_name = s3v.gen_vector_bucket_name(each_user["user_id"], 0)
        index_name = "filter-index"

        try:
            # -- setup --
            s3v.create_vector_bucket(s3v_client, bucket_name, s3_client)

            # ---------------------------------------------------------------
            # TEST 1: Create index with filterable metadata keys
            # ---------------------------------------------------------------
            log.info("TEST 1: Create index with filterable metadata")
            metadata_config = {
                "nonFilterableMetadataKeys": ["color"],
                "filterableMetadataKeys": [
                    {"name": "genre", "type": "String"},
                    {"name": "year", "type": "Number"},
                    {"name": "popular", "type": "Boolean"},
                ],
            }
            s3v.create_index(
                s3v_client, bucket_name, index_name, dimension,
                distance_metric="euclidean", metadata_config=metadata_config
            )
            log.info("TEST 1 PASSED: index with filterable metadata created")

            # ---------------------------------------------------------------
            # TEST 2: Verify filterable metadata in get_index
            # ---------------------------------------------------------------
            log.info("TEST 2: Verify index metadata configuration")
            resp = s3v.get_index(s3v_client, bucket_name, index_name)
            idx_info = resp.get("index", resp)
            md_cfg = idx_info.get("metadataConfiguration", {})
            non_filt = md_cfg.get("nonFilterableMetadataKeys", [])
            assert "color" in non_filt, "nonFilterableMetadataKeys missing 'color'"
            log.info("TEST 2 PASSED: metadata configuration verified")

            # ---------------------------------------------------------------
            # TEST 3: Put vectors with typed metadata
            # ---------------------------------------------------------------
            log.info("TEST 3: Put vectors with metadata")
            vectors = [dict(v) for v in SAMPLE_VECTORS]
            _attach_vector_data(vectors, dimension)
            s3v.put_vectors(s3v_client, bucket_name, index_name, vectors)
            log.info("TEST 3 PASSED: vectors with metadata inserted")

            # ---------------------------------------------------------------
            # TEST 4: Implicit equality filter
            # ---------------------------------------------------------------
            log.info("TEST 4: Implicit equality filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": "rock"}
            )
            assert result == ["v0", "v2"], f"Expected ['v0','v2'], got {result}"
            log.info("TEST 4 PASSED")

            # ---------------------------------------------------------------
            # TEST 5: Explicit $eq
            # ---------------------------------------------------------------
            log.info("TEST 5: Explicit $eq filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": {"$eq": "rock"}}
            )
            assert result == ["v0", "v2"], f"Expected ['v0','v2'], got {result}"
            log.info("TEST 5 PASSED")

            # ---------------------------------------------------------------
            # TEST 6: $ne filter
            # ---------------------------------------------------------------
            log.info("TEST 6: $ne filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": {"$ne": "rock"}}
            )
            assert result == ["v1", "v3", "v4"], f"Unexpected result: {result}"
            log.info("TEST 6 PASSED")

            # ---------------------------------------------------------------
            # TEST 7: $gt filter
            # ---------------------------------------------------------------
            log.info("TEST 7: $gt filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"year": {"$gt": 2019}}
            )
            assert result == ["v0", "v3", "v4"], f"Unexpected result: {result}"
            log.info("TEST 7 PASSED")

            # ---------------------------------------------------------------
            # TEST 8: Range filter ($gte + $lte)
            # ---------------------------------------------------------------
            log.info("TEST 8: Range filter ($gte + $lte)")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"year": {"$gte": 2019, "$lte": 2020}}
            )
            assert result == ["v0", "v1", "v4"], f"Unexpected result: {result}"
            log.info("TEST 8 PASSED")

            # ---------------------------------------------------------------
            # TEST 9: $in filter
            # ---------------------------------------------------------------
            log.info("TEST 9: $in filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": {"$in": ["rock", "jazz"]}}
            )
            assert result == ["v0", "v1", "v2", "v4"], f"Unexpected result: {result}"
            log.info("TEST 9 PASSED")

            # ---------------------------------------------------------------
            # TEST 10: $nin filter
            # ---------------------------------------------------------------
            log.info("TEST 10: $nin filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": {"$nin": ["rock"]}}
            )
            assert result == ["v1", "v3", "v4"], f"Unexpected result: {result}"
            log.info("TEST 10 PASSED")

            # ---------------------------------------------------------------
            # TEST 11: Boolean filter
            # ---------------------------------------------------------------
            log.info("TEST 11: Boolean filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"popular": True}
            )
            assert result == ["v0", "v2", "v4"], f"Unexpected result: {result}"
            log.info("TEST 11 PASSED")

            # ---------------------------------------------------------------
            # TEST 12: $and filter
            # ---------------------------------------------------------------
            log.info("TEST 12: $and filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"$and": [{"genre": "rock"}, {"year": {"$gt": 2019}}]}
            )
            assert result == ["v0"], f"Unexpected result: {result}"
            log.info("TEST 12 PASSED")

            # ---------------------------------------------------------------
            # TEST 13: $or filter
            # ---------------------------------------------------------------
            log.info("TEST 13: $or filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"$or": [{"genre": "rock"}, {"genre": "jazz"}]}
            )
            assert result == ["v0", "v1", "v2", "v4"], f"Unexpected result: {result}"
            log.info("TEST 13 PASSED")

            # ---------------------------------------------------------------
            # TEST 14: Implicit AND (multiple top-level fields)
            # ---------------------------------------------------------------
            log.info("TEST 14: Implicit AND")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": "jazz", "popular": True}
            )
            assert result == ["v4"], f"Unexpected result: {result}"
            log.info("TEST 14 PASSED")

            # ---------------------------------------------------------------
            # TEST 15: $exists filter
            # ---------------------------------------------------------------
            log.info("TEST 15: $exists filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"genre": {"$exists": True}}
            )
            assert len(result) == 5, f"Expected 5, got {len(result)}"
            log.info("TEST 15 PASSED")

            # ---------------------------------------------------------------
            # TEST 16: Mixed column + JSON metadata filter via $and
            # ---------------------------------------------------------------
            log.info("TEST 16: Mixed column + JSON metadata filter")
            result = _query_keys(
                s3v_client, bucket_name, index_name, dimension,
                {"$and": [{"genre": "rock"}, {"color": "red"}]}
            )
            assert result == ["v0", "v2"], f"Unexpected result: {result}"
            log.info("TEST 16 PASSED")

            # ---------------------------------------------------------------
            # TEST 17: Query with metadata returns metadata
            # ---------------------------------------------------------------
            log.info("TEST 17: Query returnMetadata=True")
            query_vec = {"float32": s3v.generate_vector_data(dimension, seed=0)}
            resp = s3v.query_vectors(
                s3v_client, bucket_name, index_name, query_vec, top_k=5,
                return_metadata=True
            )
            for v in resp.get("vectors", []):
                assert "metadata" in v, f"Vector '{v['key']}' missing metadata"
            log.info("TEST 17 PASSED")

            # ---------------------------------------------------------------
            # TEST 18: Non-filterable metadata is stored and returned
            # ---------------------------------------------------------------
            log.info("TEST 18: Non-filterable metadata is returned")
            resp = s3v.get_vectors(
                s3v_client, bucket_name, index_name,
                ["v0", "v1"], return_metadata=True
            )
            for v in resp.get("vectors", []):
                md = json.loads(v["metadata"])
                assert "color" in md, f"Non-filterable key 'color' missing in {v['key']}"
            log.info("TEST 18 PASSED")

        finally:
            s3v.cleanup_vector_bucket(s3v_client, bucket_name, s3_client)

    reusable.check_sync_status()
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Test S3 Vectors Metadata and Filtered Queries")
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
