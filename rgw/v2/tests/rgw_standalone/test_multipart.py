"""Multipart upload coverage for zipper, including >1000 parts (IBMCEPH-17573)."""

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.multipart, pytest.mark.user_type]


def test_multipart_basic(
    endpoint, users, user_label, s3_client_factory, rgw_config, account_root_client
):
    client = s3_client_factory(user_label)
    creator = account_root_client if user_label == "account_user" else None
    bkt = zs.unique_name("mpu", user_label)
    zs.ensure_bucket(client, bkt, creator=creator)

    part_size = int(rgw_config.get("multipart_part_size", 5 * 1024 * 1024))
    num_parts = int(rgw_config.get("multipart_parts", 3))
    key = "multipart-large.bin"
    data = os.urandom(part_size * num_parts)

    try:
        uid = client.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts = []
        for i in range(num_parts):
            chunk = data[i * part_size : (i + 1) * part_size]
            resp = client.upload_part(
                Bucket=bkt,
                Key=key,
                PartNumber=i + 1,
                UploadId=uid,
                Body=chunk,
            )
            parts.append({"ETag": resp["ETag"], "PartNumber": i + 1})

        listed = client.list_parts(Bucket=bkt, Key=key, UploadId=uid).get("Parts") or []
        assert len(listed) == num_parts

        uploads = client.list_multipart_uploads(Bucket=bkt).get("Uploads") or []
        assert any(u.get("UploadId") == uid for u in uploads)

        client.complete_multipart_upload(
            Bucket=bkt,
            Key=key,
            UploadId=uid,
            MultipartUpload={"Parts": parts},
        )
        body = client.get_object(Bucket=bkt, Key=key)["Body"].read()
        assert len(body) == len(data)
        assert zs.md5_bytes(body) == zs.md5_bytes(data)

        # Multipart objects must appear in list-objects (IBMCEPH-17560)
        names = {
            o["Key"]
            for o in (client.list_objects_v2(Bucket=bkt).get("Contents") or [])
        }
        assert key in names

        # Abort path
        resp = client.create_multipart_upload(Bucket=bkt, Key="abort-me.bin")
        auid = resp["UploadId"]
        client.upload_part(
            Bucket=bkt,
            Key="abort-me.bin",
            PartNumber=1,
            UploadId=auid,
            Body=os.urandom(part_size),
        )
        client.abort_multipart_upload(Bucket=bkt, Key="abort-me.bin", UploadId=auid)
        left = client.list_multipart_uploads(Bucket=bkt).get("Uploads") or []
        assert not any(u.get("UploadId") == auid for u in left)
    finally:
        zs.wipe_bucket(
            client if user_label != "account_user" else account_root_client, bkt
        )


def _md5_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Stream MD5 of a file without loading it into memory."""
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _create_large_file_on_disk(path: Path, size_bytes: int, part_size: int) -> None:
    """Create a large file via dd (streaming) — same approach as awscli/s3 cp QE."""
    # Prefer dd from /dev/urandom so Python never holds the whole object
    count = size_bytes // part_size
    rem = size_bytes % part_size
    path.parent.mkdir(parents=True, exist_ok=True)
    if count:
        subprocess.run(
            [
                "dd",
                "if=/dev/urandom",
                f"of={path}",
                f"bs={part_size}",
                f"count={count}",
                "status=none",
                "conv=fsync",
            ],
            check=True,
        )
    if rem:
        mode = "ab" if count else "wb"
        with open(path, mode) as fh:
            # small remainder only — does not cause OOM
            fh.write(os.urandom(rem))
            fh.flush()
            os.fsync(fh.fileno())


def _split_file_into_parts(source: Path, parts_dir: Path, part_size: int) -> list[Path]:
    """Split source into fixed-size part files (like split -b), ordered for MPU."""
    parts_dir.mkdir(parents=True, exist_ok=True)
    # split -b writes xaa, xab, ... in lexical order for equal-width suffixes
    subprocess.run(
        [
            "split",
            "-b",
            str(part_size),
            "-d",
            "-a",
            "5",
            str(source),
            str(parts_dir / "part_"),
        ],
        check=True,
    )
    part_files = sorted(parts_dir.glob("part_*"))
    if not part_files:
        raise RuntimeError(f"split produced no parts under {parts_dir}")
    return part_files


@pytest.mark.bug
@pytest.mark.slow
def test_multipart_gt_1000_parts(s3_client_factory, rgw_config):
    """IBMCEPH-17573: complete_multipart_upload with >1000 parts must succeed.

    Memory-safe QE method (same idea as awscli s3 cp on a large file):
      1. Create a normal large file on disk (dd from /dev/urandom)
      2. Split into 5MiB part files in a separate directory
      3. Upload each part file via upload_part (file handle, not bytes in RAM)
      4. Download object to disk and verify md5 matches the source file
    """
    client = s3_client_factory("normal")
    bkt = zs.unique_name("mpu1k", "normal")
    zs.ensure_bucket(client, bkt)
    part_size = int(rgw_config.get("multipart_part_size", 5 * 1024 * 1024))
    num_parts = int(rgw_config.get("multipart_gt_1000_parts", 1001))
    # Optional override: total source size in MiB (e.g. 10240 for ~10GiB).
    # Default: exactly num_parts full part_size chunks (~5GiB for 1001 x 5MiB).
    size_mib = rgw_config.get("multipart_gt_1000_file_size_mib")
    if size_mib:
        total_size = int(size_mib) * 1024 * 1024
        # Ensure we still exercise >1000 parts
        expected_parts = (total_size + part_size - 1) // part_size
        if expected_parts <= 1000:
            pytest.fail(
                f"multipart_gt_1000_file_size_mib={size_mib} yields only "
                f"{expected_parts} parts; need >1000"
            )
    else:
        total_size = part_size * num_parts
    key = "mpu-gt-1000.bin"

    work = Path(tempfile.mkdtemp(prefix="mpu1k_"))
    source = work / "source.bin"
    parts_dir = work / "parts"
    download = work / "downloaded.bin"
    try:
        print(
            f"creating source file {total_size} bytes (~{total_size / (1024**3):.2f} GiB) "
            f"at {source}",
            flush=True,
        )
        _create_large_file_on_disk(source, total_size, part_size)
        src_md5 = _md5_file(source)
        print(f"source md5={src_md5} size={source.stat().st_size}", flush=True)

        part_files = _split_file_into_parts(source, parts_dir, part_size)
        assert len(part_files) > 1000, f"expected >1000 parts, got {len(part_files)}"
        print(f"split into {len(part_files)} part files", flush=True)

        uid = client.create_multipart_upload(Bucket=bkt, Key=key)["UploadId"]
        parts_meta = []
        for idx, part_path in enumerate(part_files, start=1):
            # Upload from file handle — boto3 streams; do not read() into memory
            with open(part_path, "rb") as body_fh:
                resp = client.upload_part(
                    Bucket=bkt,
                    Key=key,
                    PartNumber=idx,
                    UploadId=uid,
                    Body=body_fh,
                )
            parts_meta.append({"ETag": resp["ETag"], "PartNumber": idx})
            if idx % 100 == 0 or idx == len(part_files):
                print(f"uploaded part {idx}/{len(part_files)}", flush=True)

        client.complete_multipart_upload(
            Bucket=bkt,
            Key=key,
            UploadId=uid,
            MultipartUpload={"Parts": parts_meta},
        )
        head = client.head_object(Bucket=bkt, Key=key)
        assert int(head["ContentLength"]) == total_size

        # Download to disk streaming, then compare md5 (no full-object in RAM)
        with open(download, "wb") as out_fh:
            resp = client.get_object(Bucket=bkt, Key=key)
            body = resp["Body"]
            while True:
                chunk = body.read(8 * 1024 * 1024)
                if not chunk:
                    break
                out_fh.write(chunk)
        dst_md5 = _md5_file(download)
        assert dst_md5 == src_md5, f"md5 mismatch source={src_md5} downloaded={dst_md5}"
        print(f"PASS integrity md5={dst_md5}", flush=True)
    finally:
        zs.wipe_bucket(client, bkt)
        shutil.rmtree(work, ignore_errors=True)


@pytest.mark.bug
def test_rewrite_non_multipart_over_multipart(s3_client_factory):
    """IBMCEPH-17561: rewrite non-MPU object over MPU object must not 500."""
    client = s3_client_factory("normal")
    bkt = zs.unique_name("rewrite", "normal")
    zs.ensure_bucket(client, bkt)
    key = "rewrite.bin"
    try:
        zs.multipart_upload(
            client, bkt, key, os.urandom(5 * 1024 * 1024 * 2), part_size=5 * 1024 * 1024
        )
        # overwrite with simple PUT
        client.put_object(Bucket=bkt, Key=key, Body=b"simple-overwrite")
        body = client.get_object(Bucket=bkt, Key=key)["Body"].read()
        assert body == b"simple-overwrite"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        pytest.fail(f"rewrite failed status={status} code={code}: {e}")
    finally:
        zs.wipe_bucket(client, bkt)


@pytest.mark.bug
def test_repeated_multipart_uploads(s3_client_factory):
    """IBMCEPH-18035: repeated MPU uploads on non-versioned bucket should succeed."""
    client = s3_client_factory("normal")
    bkt = zs.unique_name("mpurep", "normal")
    zs.ensure_bucket(client, bkt)
    key = "repeat.bin"
    part_size = 5 * 1024 * 1024
    try:
        for i in range(5):
            data = os.urandom(part_size * 2)
            zs.multipart_upload(client, bkt, key, data, part_size=part_size)
            body = client.get_object(Bucket=bkt, Key=key)["Body"].read()
            assert zs.md5_bytes(body) == zs.md5_bytes(data), f"iteration {i} mismatch"
    finally:
        zs.wipe_bucket(client, bkt)
