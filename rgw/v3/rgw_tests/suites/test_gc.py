"""Require observation before disappearance to avoid an empty-queue false pass."""

import pytest
from rgw_tests.operations.crud import payload
from rgw_tests.operations.gc import GarbageCollection
from rgw_tests.polling import wait_for


@pytest.mark.gc
@pytest.mark.slow
class TestGC:
    def test_deleted_multipart_queue_drains(self, feature_context, admin, cfg):
        ops = feature_context.crud
        gc = GarbageCollection(
            admin, feature_context.bucket, feature_context.credentials.tenant
        )
        data = payload(cfg.multipart_part_size * 2)
        ops.multipart("gc-object", data, cfg.multipart_part_size)
        ops.delete("gc-object")
        assert not ops.exists("gc-object")
        observed = wait_for(
            gc.entries,
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description=f"GC entries for bucket {feature_context.bucket}",
        )
        tags = {entry["tag"] for entry in observed}
        wait_for(
            lambda: tags.isdisjoint(entry["tag"] for entry in gc.entries()),
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description=f"observed GC tags to drain: {sorted(tags)}",
        )
