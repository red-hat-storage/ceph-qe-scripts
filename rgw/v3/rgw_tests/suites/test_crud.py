"""P0 matrix: identity x bucket state x independently reported CRUD scenarios."""

import pytest
from rgw_tests.operations.crud import digest, payload


@pytest.mark.sanity
class TestCRUD:
    def test_put_get_list(self, context, cfg):
        ops = context.crud
        expected = {
            f"data/{i:05d}": payload(cfg.object_size, str(i))
            for i in range(cfg.objects)
        }
        ops.parallel(lambda key: ops.put(key, expected[key]), expected, cfg.workers)
        assert set(ops.list("data/")) == set(expected)

        def verify(key):
            assert digest(ops.get(key)) == digest(
                expected[key]
            ), f"Content mismatch: {key}"

        ops.parallel(verify, expected, cfg.workers)

    def test_copy(self, context, cfg):
        ops = context.crud
        data = payload(cfg.object_size)
        ops.put("source", data)
        keys = [f"copy/{i:05d}" for i in range(cfg.objects)]
        ops.parallel(lambda key: ops.copy("source", key), keys, cfg.workers)
        assert set(ops.list("copy/")) == set(keys)
        for key in keys:
            assert digest(ops.get(key)) == digest(data)

    def test_delete(self, context, cfg):
        ops = context.crud
        keys = [f"delete/{i:05d}" for i in range(cfg.objects)]
        ops.parallel(
            lambda key: ops.put(key, payload(cfg.object_size)), keys, cfg.workers
        )
        ops.parallel(ops.delete, keys, cfg.workers)
        assert ops.list("delete/") == []
        assert all(not ops.exists(key) for key in keys)
        if context.state == "versioned":
            history = ops.versions("delete/")
            assert len(history["DeleteMarkers"]) == len(keys)
            assert len(history["Versions"]) == len(keys)

    def test_multipart_put_get_copy_delete(self, context, cfg):
        ops = context.crud
        data = payload(cfg.multipart_part_size + 1024)
        # Threading is deliberately bounded: each MPU retains one payload in memory.
        for index in range(cfg.objects):
            key, copied = f"mpu/{index}", f"mpu-copy/{index}"
            ops.multipart(key, data, cfg.multipart_part_size)
            assert digest(ops.get(key)) == digest(data)
            ops.multipart(copied, data, cfg.multipart_part_size, source=key)
            assert digest(ops.get(copied)) == digest(data)
            assert {key, copied}.issubset(ops.list())
            ops.delete(key)
            ops.delete(copied)
            assert not ops.exists(key) and not ops.exists(copied)

    def test_multipart_list_abort(self, context, cfg):
        ops = context.crud
        for index in range(cfg.objects):
            key = f"incomplete/{index}"
            upload_id = ops.start_multipart(key)
            context.client.upload_part(
                Bucket=context.bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=1,
                Body=payload(cfg.object_size),
            )
            assert any(u["UploadId"] == upload_id for u in ops.uploads())
            assert [p["PartNumber"] for p in ops.parts(key, upload_id)] == [1]
            ops.abort(key, upload_id)
            assert not any(u["UploadId"] == upload_id for u in ops.uploads())
            assert not ops.exists(key)

    def test_version_history(self, context, cfg):
        if context.state != "versioned":
            pytest.skip("Version history applies to enabled versioning")
        ops = context.crud
        original, replacement = payload(cfg.object_size, "first"), payload(
            cfg.object_size, "second"
        )
        first = ops.put("history", original)["VersionId"]
        second = ops.put("history", replacement)["VersionId"]
        assert first != second
        assert ops.get("history", first) == original
        assert ops.get("history", second) == replacement
        ops.copy("history", "historical-copy", version=first)
        assert ops.get("historical-copy") == original
        marker = ops.delete("history")
        assert marker["DeleteMarker"]
        assert not ops.exists("history")
        assert len(ops.versions("history")["Versions"]) == 2
        ops.delete("history", marker["VersionId"])
        assert ops.get("history") == replacement
        ops.delete("history", second)
        assert ops.get("history") == original

    def test_suspended_null_version(self, context):
        if context.state != "suspended":
            pytest.skip("Null-version replacement applies to suspended versioning")
        ops = context.crud
        ops.put("null-version", b"first")
        ops.put("null-version", b"second")
        history = ops.versions("null-version")
        assert len(history["Versions"]) == 1
        assert history["Versions"][0]["VersionId"] == "null"
        assert ops.get("null-version", "null") == b"second"
        ops.delete("null-version")
        assert not ops.exists("null-version")
        history = ops.versions("null-version")
        assert history["Versions"] == []
        assert history["DeleteMarkers"][0]["VersionId"] == "null"
