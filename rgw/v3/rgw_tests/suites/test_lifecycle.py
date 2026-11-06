"""Lifecycle requires a timeout that matches the cluster's expiration schedule."""

import pytest
from rgw_tests.operations.lifecycle import Lifecycle
from rgw_tests.polling import wait_for


@pytest.mark.lifecycle
class TestLifecycle:
    def test_policy_roundtrip(self, feature_context, cfg):
        lc = Lifecycle(feature_context.client, feature_context.bucket)
        rule = lc.configure(days=cfg.lifecycle_days)
        assert lc.rules() == [rule]
        feature_context.client.delete_bucket_lifecycle(Bucket=feature_context.bucket)
        from botocore.exceptions import ClientError

        with pytest.raises(ClientError) as error:
            lc.rules()
        assert error.value.response["Error"]["Code"] == "NoSuchLifecycleConfiguration"

    @pytest.mark.slow
    def test_current_expiration(self, feature_context, cfg):
        ops = feature_context.crud
        ops.put("expire/object", b"expire me")
        ops.put("keep/object", b"keep me")
        Lifecycle(feature_context.client, feature_context.bucket).configure(
            days=cfg.lifecycle_days
        )
        wait_for(
            lambda: not ops.exists("expire/object"),
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description="current object expiration",
        )
        assert ops.get("keep/object") == b"keep me"

    @pytest.mark.slow
    def test_noncurrent_expiration(self, versioned_context, cfg):
        ops = versioned_context.crud
        old = ops.put("expire/object", b"old")["VersionId"]
        latest = ops.put("expire/object", b"latest")["VersionId"]
        Lifecycle(versioned_context.client, versioned_context.bucket).configure(
            days=cfg.lifecycle_days, noncurrent=True
        )
        wait_for(
            lambda: old
            not in [v["VersionId"] for v in ops.versions("expire/")["Versions"]],
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description="noncurrent version expiration",
        )
        assert ops.get("expire/object", latest) == b"latest"

    @pytest.mark.slow
    def test_incomplete_upload_expiration(self, feature_context, cfg):
        ops = feature_context.crud
        upload_id = ops.start_multipart("expire/incomplete")
        feature_context.client.upload_part(
            Bucket=feature_context.bucket,
            Key="expire/incomplete",
            UploadId=upload_id,
            PartNumber=1,
            Body=b"incomplete",
        )
        Lifecycle(feature_context.client, feature_context.bucket).configure(
            days=cfg.lifecycle_days, abort=True
        )
        wait_for(
            lambda: not any(u["UploadId"] == upload_id for u in ops.uploads()),
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description="incomplete multipart expiration",
        )
