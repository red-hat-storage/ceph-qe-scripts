"""
S3 Vectors reusable library for RGW testing.

Provides helper functions for:
- Creating s3vectors boto3 client
- Vector bucket management (CRUD)
- Index management (CRUD with filterable metadata)
- Vector data operations (put/get/list/delete/query)
- Test data generation
- Cleanup utilities
"""

import json
import logging
import random

import boto3

from v2.lib.exceptions import TestExecError

log = logging.getLogger()


def create_s3vectors_client(auth):
    """
    Create a boto3 s3vectors client reusing credentials and endpoint from an Auth object.

    Args:
        auth: Auth object (from v2.lib.s3.auth) with access_key, secret_key, endpoint_url

    Returns:
        boto3 s3vectors client
    """
    try:
        client = boto3.client(
            "s3vectors",
            aws_access_key_id=auth.access_key,
            aws_secret_access_key=auth.secret_key,
            endpoint_url=auth.endpoint_url,
            verify=False,
            region_name="default",
        )
        log.info("s3vectors client created successfully")
        return client
    except Exception as e:
        raise TestExecError(f"Failed to create s3vectors client: {e}")


# ---------------------------------------------------------------------------
# Vector bucket helpers
# ---------------------------------------------------------------------------


def gen_vector_bucket_name(user_id, suffix=0):
    """Generate a unique vector bucket name from a user ID."""
    return f"vb-{user_id}-{suffix}".lower()[:63]


def create_backing_bucket(s3_client, bucket_name):
    """Create the backing S3 bucket required by the rgw backend."""
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        log.info(f"Backing S3 bucket '{bucket_name}' already exists")
    except s3_client.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("404", "NoSuchBucket"):
            log.info(f"Creating backing S3 bucket '{bucket_name}'")
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            raise


def delete_backing_bucket(s3_client, bucket_name):
    """Delete the backing S3 bucket and all its objects (best-effort)."""
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            if "Contents" in page:
                objects = [{"Key": obj["Key"]} for obj in page["Contents"]]
                if objects:
                    s3_client.delete_objects(
                        Bucket=bucket_name, Delete={"Objects": objects}
                    )
        s3_client.delete_bucket(Bucket=bucket_name)
        log.info(f"Deleted backing S3 bucket '{bucket_name}'")
    except Exception as e:
        log.warning(f"Failed to delete backing S3 bucket '{bucket_name}': {e}")


def create_vector_bucket(s3v_client, bucket_name, s3_client=None):
    """
    Create a vector bucket.  When *s3_client* is supplied the backing
    S3 bucket is created first (required for the rgw backend).

    Returns:
        dict: create_vector_bucket API response
    """
    if s3_client:
        create_backing_bucket(s3_client, bucket_name)

    log.info(f"Creating vector bucket: {bucket_name}")
    response = s3v_client.create_vector_bucket(vectorBucketName=bucket_name)
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    if status != 200:
        raise TestExecError(f"create_vector_bucket failed with status {status}")
    log.info(
        f"Vector bucket created: {bucket_name}, "
        f"ARN: {response.get('vectorBucketArn')}"
    )
    return response


def get_vector_bucket(s3v_client, bucket_name):
    """Get vector bucket info."""
    log.info(f"Getting vector bucket: {bucket_name}")
    return s3v_client.get_vector_bucket(vectorBucketName=bucket_name)


def list_vector_buckets(s3v_client, prefix=None, max_results=None):
    """List vector buckets with optional prefix filter."""
    kwargs = {}
    if prefix:
        kwargs["prefix"] = prefix
    if max_results:
        kwargs["maxResults"] = max_results
    log.info(f"Listing vector buckets (prefix={prefix})")
    response = s3v_client.list_vector_buckets(**kwargs)
    buckets = response.get("vectorBuckets", [])
    log.info(f"Found {len(buckets)} vector bucket(s)")
    return response


def delete_vector_bucket(s3v_client, bucket_name):
    """Delete a vector bucket (all indexes must already be deleted)."""
    log.info(f"Deleting vector bucket: {bucket_name}")
    response = s3v_client.delete_vector_bucket(vectorBucketName=bucket_name)
    log.info(f"Deleted vector bucket: {bucket_name}")
    return response


# ---------------------------------------------------------------------------
# Index helpers
# ---------------------------------------------------------------------------


def create_index(
    s3v_client,
    bucket_name,
    index_name,
    dimension,
    distance_metric="euclidean",
    data_type="float32",
    metadata_config=None,
):
    """
    Create an index inside a vector bucket.

    Args:
        s3v_client:       boto3 s3vectors client
        bucket_name:      vector bucket name
        index_name:       index name
        dimension:        vector dimension (1-4096)
        distance_metric:  'cosine' or 'euclidean'
        data_type:        'float32'
        metadata_config:  optional dict, e.g.
                          {"nonFilterableMetadataKeys": [...],
                           "filterableMetadataKeys": [...]}

    Returns:
        dict: create_index API response
    """
    kwargs = {
        "vectorBucketName": bucket_name,
        "indexName": index_name,
        "dataType": data_type,
        "dimension": dimension,
        "distanceMetric": distance_metric,
    }
    if metadata_config:
        kwargs["metadataConfiguration"] = metadata_config

    log.info(
        f"Creating index '{index_name}' in '{bucket_name}' "
        f"(dim={dimension}, metric={distance_metric})"
    )
    response = s3v_client.create_index(**kwargs)
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    if status != 200:
        raise TestExecError(f"create_index failed with status {status}")
    log.info(f"Index created: {index_name}, ARN: {response.get('indexArn')}")
    return response


def get_index(s3v_client, bucket_name, index_name):
    """Get index details."""
    log.info(f"Getting index '{index_name}' in '{bucket_name}'")
    return s3v_client.get_index(vectorBucketName=bucket_name, indexName=index_name)


def list_indexes(s3v_client, bucket_name, prefix=None, max_results=None):
    """List indexes in a vector bucket."""
    kwargs = {"vectorBucketName": bucket_name}
    if prefix:
        kwargs["prefix"] = prefix
    if max_results:
        kwargs["maxResults"] = max_results
    log.info(f"Listing indexes in '{bucket_name}'")
    response = s3v_client.list_indexes(**kwargs)
    indexes = response.get("indexes", [])
    log.info(f"Found {len(indexes)} index(es) in '{bucket_name}'")
    return response


def delete_index(s3v_client, bucket_name, index_name):
    """Delete a single index."""
    log.info(f"Deleting index '{index_name}' from '{bucket_name}'")
    response = s3v_client.delete_index(
        vectorBucketName=bucket_name, indexName=index_name
    )
    log.info(f"Deleted index '{index_name}'")
    return response


def delete_all_indexes(s3v_client, bucket_name):
    """Delete every index in a vector bucket."""
    response = list_indexes(s3v_client, bucket_name)
    for idx in response.get("indexes", []):
        delete_index(s3v_client, bucket_name, idx["indexName"])


# ---------------------------------------------------------------------------
# Vector data helpers
# ---------------------------------------------------------------------------


def generate_vector_data(dimension, seed=None):
    """Return a list of *dimension* floats.  Deterministic when *seed* is set."""
    rng = random.Random(seed) if seed is not None else random
    return [round(rng.random(), 6) for _ in range(dimension)]


def generate_vectors(count, dimension, with_metadata=False, key_prefix="vec"):
    """
    Build a list of test vectors ready for put_vectors.

    Args:
        count:         how many vectors to generate
        dimension:     length of each float32 vector
        with_metadata: attach sample JSON metadata when True
        key_prefix:    prefix for the vector key names

    Returns:
        list[dict]: each dict has 'key', 'data', and optionally 'metadata'
    """
    categories = ["science", "history", "math", "art", "tech"]
    vectors = []
    for i in range(count):
        vec = {
            "key": f"{key_prefix}-{i}",
            "data": {"float32": generate_vector_data(dimension, seed=i)},
        }
        if with_metadata:
            vec["metadata"] = json.dumps(
                {
                    "category": categories[i % len(categories)],
                    "year": 2020 + (i % 6),
                    "score": round(random.Random(i).uniform(1.0, 10.0), 2),
                }
            )
        vectors.append(vec)
    return vectors


def put_vectors(s3v_client, bucket_name, index_name, vectors):
    """Insert or upsert *vectors* into an index."""
    log.info(f"Putting {len(vectors)} vector(s) into '{bucket_name}/{index_name}'")
    response = s3v_client.put_vectors(
        vectorBucketName=bucket_name, indexName=index_name, vectors=vectors
    )
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    if status != 200:
        raise TestExecError(f"put_vectors failed with status {status}")
    log.info(f"Successfully put {len(vectors)} vector(s)")
    return response


def get_vectors(
    s3v_client,
    bucket_name,
    index_name,
    keys,
    return_data=True,
    return_metadata=False,
):
    """Retrieve vectors by their keys."""
    log.info(f"Getting {len(keys)} vector(s) from '{bucket_name}/{index_name}'")
    return s3v_client.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=keys,
        returnData=return_data,
        returnMetadata=return_metadata,
    )


def list_vectors(
    s3v_client,
    bucket_name,
    index_name,
    max_results=500,
    return_data=False,
    return_metadata=False,
    next_token=None,
):
    """List vectors with pagination support."""
    kwargs = {
        "vectorBucketName": bucket_name,
        "indexName": index_name,
        "maxResults": max_results,
        "returnData": return_data,
        "returnMetadata": return_metadata,
    }
    if next_token:
        kwargs["nextToken"] = next_token
    log.info(f"Listing vectors in '{bucket_name}/{index_name}' (max={max_results})")
    response = s3v_client.list_vectors(**kwargs)
    log.info(f"Listed {len(response.get('vectors', []))} vector(s)")
    return response


def delete_vectors(s3v_client, bucket_name, index_name, keys):
    """Delete vectors by key."""
    log.info(f"Deleting {len(keys)} vector(s) from '{bucket_name}/{index_name}'")
    response = s3v_client.delete_vectors(
        vectorBucketName=bucket_name, indexName=index_name, keys=keys
    )
    log.info(f"Deleted {len(keys)} vector(s)")
    return response


def query_vectors(
    s3v_client,
    bucket_name,
    index_name,
    query_vector,
    top_k,
    return_distance=False,
    return_metadata=False,
    filter_expr=None,
):
    """
    Run a nearest-neighbour search.

    Args:
        query_vector:    {"float32": [0.1, ...]}
        top_k:           number of neighbours (1-10000)
        filter_expr:     optional MongoDB-style filter dict
    """
    kwargs = {
        "vectorBucketName": bucket_name,
        "indexName": index_name,
        "queryVector": query_vector,
        "topK": top_k,
        "returnDistance": return_distance,
        "returnMetadata": return_metadata,
    }
    if filter_expr is not None:
        kwargs["filter"] = filter_expr
    log.info(f"Querying '{bucket_name}/{index_name}' (topK={top_k})")
    response = s3v_client.query_vectors(**kwargs)
    log.info(f"Query returned {len(response.get('vectors', []))} vector(s)")
    return response


# ---------------------------------------------------------------------------
# Cleanup helpers
# ---------------------------------------------------------------------------


def cleanup_vector_bucket(s3v_client, bucket_name, s3_client=None):
    """Best-effort full cleanup: indexes -> vector bucket -> backing bucket."""
    log.info(f"Cleaning up vector bucket: {bucket_name}")
    try:
        delete_all_indexes(s3v_client, bucket_name)
    except Exception as e:
        log.warning(f"Failed to delete indexes in '{bucket_name}': {e}")
    try:
        delete_vector_bucket(s3v_client, bucket_name)
    except Exception as e:
        log.warning(f"Failed to delete vector bucket '{bucket_name}': {e}")
    if s3_client:
        delete_backing_bucket(s3_client, bucket_name)


def cleanup_all_vector_buckets(s3v_client, s3_client=None):
    """Delete every vector bucket owned by the authenticated user."""
    try:
        response = list_vector_buckets(s3v_client)
        for bucket in response.get("vectorBuckets", []):
            cleanup_vector_bucket(
                s3v_client, bucket["vectorBucketName"], s3_client
            )
    except Exception as e:
        log.warning(f"Failed to cleanup all vector buckets: {e}")
