"""Exercise API contracts with botocore validation and fault injection."""

import io
import json
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from botocore.stub import Stubber
from rgw_tests.config import Config
from rgw_tests.operations.buckets import Buckets
from rgw_tests.operations.crud import CRUD
from rgw_tests.operations.gc import GarbageCollection
from rgw_tests.operations.notifications import Notifications
from rgw_tests.operations.users import Users
from rgw_tests.resources import Resources


@pytest.fixture
def s3():
    return boto3.client(
        "s3",
        endpoint_url="http://127.0.0.1:1",
        region_name="us-east-1",
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
    )


def test_paginated_listing_and_stream_closed(s3):
    with Stubber(s3) as stub:
        stub.add_response(
            "list_objects_v2",
            {
                "IsTruncated": True,
                "NextContinuationToken": "next",
                "Contents": [{"Key": "a"}],
            },
            {"Bucket": "owned-bucket", "Prefix": ""},
        )
        stub.add_response(
            "list_objects_v2",
            {
                "IsTruncated": False,
                "Contents": [{"Key": "b"}],
            },
            {"Bucket": "owned-bucket", "Prefix": "", "ContinuationToken": "next"},
        )
        stream = io.BytesIO(b"content")
        stub.add_response(
            "get_object",
            {"Body": StreamingBody(stream, 7)},
            {
                "Bucket": "owned-bucket",
                "Key": "a",
                "VersionId": "v1",
            },
        )
        ops = CRUD(s3, "owned-bucket")
        assert ops.list() == ["a", "b"]
        assert ops.get("a", "v1") == b"content"
        assert stream.closed
        stub.assert_no_pending_responses()


def test_head_access_denied_is_not_absence(s3):
    with Stubber(s3) as stub:
        stub.add_client_error(
            "head_object", service_error_code="403", http_status_code=403
        )
        with pytest.raises(ClientError):
            CRUD(s3, "owned-bucket").exists("a")
        stub.add_client_error(
            "head_object", service_error_code="404", http_status_code=404
        )
        assert not CRUD(s3, "owned-bucket").exists("a")


def test_multipart_failure_aborts_but_keeps_original_error(s3):
    with Stubber(s3) as stub:
        args = {"Bucket": "owned-bucket", "Key": "a"}
        stub.add_response("create_multipart_upload", {"UploadId": "upload"}, args)
        stub.add_response(
            "upload_part",
            {"ETag": "first"},
            {
                **args,
                "UploadId": "upload",
                "PartNumber": 1,
                "Body": b"abc",
            },
        )
        stub.add_client_error(
            "upload_part",
            service_error_code="InjectedFailure",
            expected_params={
                **args,
                "UploadId": "upload",
                "PartNumber": 2,
                "Body": b"def",
            },
        )
        stub.add_client_error(
            "abort_multipart_upload",
            service_error_code="AbortFailure",
            expected_params={
                **args,
                "UploadId": "upload",
            },
        )
        with pytest.raises(ClientError, match="InjectedFailure"):
            CRUD(s3, "owned-bucket").multipart("a", b"abcdef", 3)
        stub.assert_no_pending_responses()


def test_multipart_copy_ranges_and_completion(s3):
    with Stubber(s3) as stub:
        args = {"Bucket": "owned-bucket", "Key": "copy"}
        stub.add_response("create_multipart_upload", {"UploadId": "upload"}, args)
        for number, span in [(1, "bytes=0-2"), (2, "bytes=3-5")]:
            stub.add_response(
                "upload_part_copy",
                {"CopyPartResult": {"ETag": str(number)}},
                {
                    **args,
                    "UploadId": "upload",
                    "PartNumber": number,
                    "CopySource": {"Bucket": "owned-bucket", "Key": "source"},
                    "CopySourceRange": span,
                },
            )
        stub.add_response(
            "complete_multipart_upload",
            {"ETag": "complete"},
            {
                **args,
                "UploadId": "upload",
                "MultipartUpload": {
                    "Parts": [
                        {"PartNumber": 1, "ETag": "1"},
                        {"PartNumber": 2, "ETag": "2"},
                    ]
                },
            },
        )
        assert (
            CRUD(s3, "owned-bucket").multipart("copy", b"abcdef", 3, source="source")[
                "ETag"
            ]
            == "complete"
        )
        stub.assert_no_pending_responses()


def test_bucket_cleanup_versions_markers_and_uploads(s3):
    with Stubber(s3) as stub:
        bucket = {"Bucket": "owned-bucket"}
        stub.add_response(
            "put_bucket_notification_configuration",
            {},
            {
                **bucket,
                "NotificationConfiguration": {},
            },
        )
        stub.add_response("delete_bucket_lifecycle", {}, bucket)
        stub.add_response(
            "list_multipart_uploads",
            {"Uploads": [{"Key": "incomplete", "UploadId": "u"}]},
            bucket,
        )
        stub.add_response(
            "abort_multipart_upload",
            {},
            {**bucket, "Key": "incomplete", "UploadId": "u"},
        )
        stub.add_response(
            "list_object_versions",
            {
                "Versions": [{"Key": "key", "VersionId": "old"}],
                "DeleteMarkers": [{"Key": "key", "VersionId": "marker"}],
            },
            bucket,
        )
        stub.add_response(
            "delete_objects",
            {},
            {
                **bucket,
                "Delete": {
                    "Objects": [
                        {"Key": "key", "VersionId": "old"},
                        {"Key": "key", "VersionId": "marker"},
                    ],
                    "Quiet": True,
                },
            },
        )
        stub.add_response(
            "list_objects_v2", {"Contents": [{"Key": "unversioned"}]}, bucket
        )
        stub.add_response(
            "delete_objects",
            {},
            {
                **bucket,
                "Delete": {
                    "Objects": [{"Key": "unversioned"}],
                    "Quiet": True,
                },
            },
        )
        stub.add_response("delete_bucket", {}, bucket)
        Buckets(s3, Resources()).remove("owned-bucket")
        stub.assert_no_pending_responses()


def test_bucket_cleanup_surfaces_partial_delete_errors(s3):
    with Stubber(s3) as stub:
        stub.add_response(
            "delete_objects", {"Errors": [{"Key": "a", "Code": "AccessDenied"}]}
        )
        with pytest.raises(RuntimeError, match="failed to delete 1"):
            Buckets(s3, Resources())._delete("owned-bucket", [{"Key": "a"}])


def test_partial_provisioning_removes_account():
    admin = Mock()
    admin.run.side_effect = [
        {"id": "RGW123"},
        RuntimeError("user creation failed"),
        None,
    ]
    resources = Resources()
    with pytest.raises(RuntimeError, match="user creation failed"):
        Users(Config(), admin, resources).create("account-root")
    resources.close()
    assert admin.run.call_args.args == ("account", "rm")
    assert admin.run.call_args.kwargs == {"account_id": "RGW123", "json_output": False}


def test_partial_bucket_setup_registers_cleanup_before_versioning():
    client = Mock()
    client.put_bucket_versioning.side_effect = RuntimeError("versioning failed")
    resources = Resources()
    with pytest.raises(RuntimeError):
        Buckets(client, resources).create("versioned")
    assert len(resources.callbacks) == 1


def test_gc_does_not_match_other_bucket_entries():
    admin = Mock()
    admin.run.side_effect = [
        {"marker": "bucket-marker"},
        [
            {
                "tag": "ours",
                "objs": [{"oid": "bucket-marker_object", "key": "locator"}],
            },
            {"tag": "other", "objs": [{"oid": "different_object", "key": "locator"}]},
        ],
    ]
    assert [e["tag"] for e in GarbageCollection(admin, "owned-bucket").entries()] == [
        "ours"
    ]


def test_notification_envelope_filter_and_duplicate_tolerance():
    import threading

    notify = Notifications.__new__(Notifications)
    notify.records = []
    notify.lock = threading.Lock()
    records = [
        {"s3": {"bucket": {"name": "owned-bucket"}}, "eventName": "ObjectCreated:Put"}
    ]
    notify.accept(json.dumps({"Message": json.dumps({"Records": records})}))
    notify.accept(json.dumps({"Records": [{"s3": {"bucket": {"name": "other"}}}]}))
    assert notify.events("owned-bucket") == records
    notify.accept(json.dumps({"Records": records}))
    assert len(notify.events("owned-bucket")) == 2
    with pytest.raises(ValueError):
        notify.accept('{"Records": "invalid"}')


def test_iam_user_failure_cleans_dependencies_in_order(monkeypatch):
    admin = Mock()
    admin.run.side_effect = [
        {"id": "RGW123"},
        {"keys": [{"access_key": "access", "secret_key": "secret"}]},
        None,
        None,
    ]
    iam = Mock()
    iam.create_access_key.side_effect = RuntimeError("failed after policy creation")
    monkeypatch.setattr("rgw_tests.operations.users.make_client", lambda *_: iam)
    resources = Resources()
    with pytest.raises(RuntimeError, match="after policy"):
        Users(Config(), admin, resources).create("account-user")
    resources.close()
    assert [call[0] for call in iam.method_calls] == [
        "create_user",
        "put_user_policy",
        "create_access_key",
        "delete_user_policy",
        "delete_user",
        "close",
    ]
    assert admin.run.call_args_list[-2].args == ("user", "rm")
    assert admin.run.call_args_list[-1].args == ("account", "rm")


def test_preprovisioned_identity_is_never_registered_for_deletion(monkeypatch):
    monkeypatch.setenv("EXISTING_ACCESS_KEY_ID", "access")
    monkeypatch.setenv("EXISTING_SECRET_ACCESS_KEY", "secret")
    admin, resources = Mock(), Resources()
    credential = Users(
        Config(identities={"normal": "EXISTING"}), admin, resources
    ).create("normal")
    assert credential.access_key == "access"
    resources.close()
    admin.run.assert_not_called()
