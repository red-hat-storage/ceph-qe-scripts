"""Verify bucket data and ACLs survive an explicit reshard."""

import pytest
from rgw_tests.operations.crud import payload
from rgw_tests.operations.resharding import Resharding
from rgw_tests.polling import wait_for


@pytest.mark.resharding
class TestResharding:
    def test_data_and_acl_preserved(self, feature_context, admin, cfg):
        context = feature_context
        ops = context.crud
        expected = {
            f"data/{i}": payload(cfg.object_size, str(i)) for i in range(cfg.objects)
        }
        ops.parallel(lambda key: ops.put(key, expected[key]), expected, cfg.workers)
        acl = context.client.get_bucket_acl(Bucket=context.bucket)
        reshard = Resharding(admin, context.bucket, context.credentials.tenant)
        target = cfg.shards if reshard.shards() != cfg.shards else cfg.shards + 2
        reshard.reshard(target)
        wait_for(
            lambda: reshard.shards() == target,
            timeout=cfg.timeout,
            interval=cfg.poll_interval,
            description=f"bucket shard count {target}",
        )
        assert set(ops.list()) == set(expected)
        for key, data in expected.items():
            assert ops.get(key) == data
        after = context.client.get_bucket_acl(Bucket=context.bucket)
        assert after["Owner"] == acl["Owner"]
        assert after["Grants"] == acl["Grants"]
        ops.put("after-reshard", b"new data")
        assert ops.get("after-reshard") == b"new data"
        ops.delete("after-reshard")
        assert not ops.exists("after-reshard")
