"""Copy-object coverage: same/cross bucket, MPU copy, independence, LastModified BZ."""

import os
from datetime import datetime

import pytest

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.copy, pytest.mark.user_type]


def test_copy_object_matrix(
    user_label, s3_client_factory, account_root_client, object_sizes
):
    client = s3_client_factory(user_label)
    creator = account_root_client if user_label == "account_user" else None
    src_bkt = zs.unique_name("copy-src", user_label)
    dst_bkt = zs.unique_name("copy-dst", user_label)
    zs.ensure_bucket(client, src_bkt, creator=creator)
    zs.ensure_bucket(client, dst_bkt, creator=creator)

    try:
        # non-multipart copies at small/medium/large
        for size_name, nbytes in object_sizes.items():
            src_key = f"src/{size_name}.bin"
            data = os.urandom(int(nbytes))
            digest = zs.md5_bytes(data)
            client.put_object(
                Bucket=src_bkt, Key=src_key, Body=data, Metadata={"src": size_name}
            )

            # same-bucket
            dst_key = f"src/{size_name}-copy.bin"
            client.copy_object(
                Bucket=src_bkt,
                Key=dst_key,
                CopySource={"Bucket": src_bkt, "Key": src_key},
                MetadataDirective="COPY",
            )
            assert zs.md5_bytes(
                client.get_object(Bucket=src_bkt, Key=dst_key)["Body"].read()
            ) == digest

            # cross-bucket + REPLACE
            cross_key = f"dst/{size_name}.bin"
            client.copy_object(
                Bucket=dst_bkt,
                Key=cross_key,
                CopySource={"Bucket": src_bkt, "Key": src_key},
                MetadataDirective="REPLACE",
                Metadata={"copied": "true", "size": size_name},
                ContentType="application/octet-stream",
            )
            body = client.get_object(Bucket=dst_bkt, Key=cross_key)["Body"].read()
            assert zs.md5_bytes(body) == digest
            meta = client.head_object(Bucket=dst_bkt, Key=cross_key).get("Metadata") or {}
            assert meta.get("copied") == "true"

        # multipart source + UploadPartCopy
        big_key = "src/big.bin"
        part_size = 5 * 1024 * 1024
        big = os.urandom(part_size * 2 + 1024)
        client.put_object(Bucket=src_bkt, Key=big_key, Body=big)
        out_key = "dst/big-copied.bin"
        uid = client.create_multipart_upload(Bucket=dst_bkt, Key=out_key)["UploadId"]
        parts = []
        part_num = 1
        start = 0
        while start < len(big):
            end = min(start + part_size, len(big)) - 1
            resp = client.upload_part_copy(
                Bucket=dst_bkt,
                Key=out_key,
                PartNumber=part_num,
                UploadId=uid,
                CopySource={"Bucket": src_bkt, "Key": big_key},
                CopySourceRange=f"bytes={start}-{end}",
            )
            parts.append(
                {"ETag": resp["CopyPartResult"]["ETag"], "PartNumber": part_num}
            )
            part_num += 1
            start = end + 1
        client.complete_multipart_upload(
            Bucket=dst_bkt,
            Key=out_key,
            UploadId=uid,
            MultipartUpload={"Parts": parts},
        )
        assert zs.md5_bytes(
            client.get_object(Bucket=dst_bkt, Key=out_key)["Body"].read()
        ) == zs.md5_bytes(big)

        # independence after source delete
        k = "src/independent.bin"
        payload = b"independent-copy-payload"
        client.put_object(Bucket=src_bkt, Key=k, Body=payload)
        client.copy_object(
            Bucket=dst_bkt,
            Key="dst/independent.bin",
            CopySource={"Bucket": src_bkt, "Key": k},
        )
        client.delete_object(Bucket=src_bkt, Key=k)
        assert (
            client.get_object(Bucket=dst_bkt, Key="dst/independent.bin")["Body"].read()
            == payload
        )
    finally:
        wipe = account_root_client if user_label == "account_user" else client
        zs.wipe_bucket(wipe, src_bkt)
        zs.wipe_bucket(wipe, dst_bkt)


@pytest.mark.bug
def test_copy_object_last_modified_not_epoch(s3_client_factory):
    """IBMCEPH-18509: CopyObject response LastModified must not be 1970-01-01."""
    client = s3_client_factory("normal")
    bkt = zs.unique_name("copylm", "normal")
    zs.ensure_bucket(client, bkt)
    try:
        client.put_object(Bucket=bkt, Key="src.bin", Body=b"copy-lm-payload")
        resp = client.copy_object(
            Bucket=bkt,
            Key="dst.bin",
            CopySource={"Bucket": bkt, "Key": "src.bin"},
        )
        copy_result = resp.get("CopyObjectResult") or {}
        lm = copy_result.get("LastModified") or resp.get("LastModified")
        head = client.head_object(Bucket=bkt, Key="dst.bin")
        head_lm = head.get("LastModified")

        assert head_lm is not None
        assert not zs.epoch_timestamp(head_lm), f"head LastModified epoch: {head_lm}"
        # Known defect: CopyObjectResult.LastModified may be epoch
        if lm is None or zs.epoch_timestamp(lm):
            pytest.fail(
                f"IBMCEPH-18509: CopyObject LastModified is epoch/missing "
                f"(copy={lm}, head={head_lm})"
            )
        # sanity: copy LM roughly matches head
        if isinstance(lm, datetime) and isinstance(head_lm, datetime):
            assert abs((lm - head_lm).total_seconds()) < 120
    finally:
        zs.wipe_bucket(client, bkt)
