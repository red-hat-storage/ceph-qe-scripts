"""Optional clients exercise owned buckets and reuse the standard finalizer."""

import shutil

import pytest
from rgw_tests.operations.crud import payload
from rgw_tests.operations.tools import AWSCLI, Elbencho


@pytest.mark.awscli
class TestAWSCLI:
    def test_crud(self, feature_context, cfg):
        if not shutil.which("aws"):
            pytest.skip("AWS CLI executable is not installed")
        AWSCLI(cfg, feature_context.credentials).exercise(
            feature_context.bucket, payload(cfg.object_size)
        )
        assert feature_context.crud.list() == []


@pytest.mark.elbencho
class TestElbencho:
    def test_crud(self, feature_context, cfg):
        if not shutil.which("elbencho"):
            pytest.skip("Elbencho with S3 support is not installed")
        tool = Elbencho(cfg, feature_context.credentials)
        tool.phase("write", feature_context.bucket)
        assert len(feature_context.crud.list()) == cfg.objects
        tool.phase("read", feature_context.bucket)
        tool.phase("delete", feature_context.bucket)
        assert feature_context.crud.list() == []
