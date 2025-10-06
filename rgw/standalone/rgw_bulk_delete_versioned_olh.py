#!/usr/bin/env python3
"""
RGW OLH Replay Reproducer & Analyzer
====================================

End-to-end Python utility to:
  1) Provision a versioned bucket (create if absent + enable versioning)
  2) Generate many versions of a single key by repeated PUTs
  3) Bulk delete object versions using S3 DeleteObjects in batches (up to 1000)
     with configurable concurrency, and resilient retries for 503 SlowDown
  4) Parse RGW logs to report:
      - Distinct request count (grep-like "req <id>")
      - Count of OLH-replay related entries (apply_olh_log/update_olh/apply_olh)
      - Top (req_id, oid) pairs that repeat, with sample lines
  5) Emit timings and throughput numbers for generate/delete phases

Example:
  python3 rgw_bulk_delete_reproducer.py \
    --endpoint http://rgw_ip:port \
    --access-key TESTER \
    --secret-key test123 \
    --bucket testv1 \
    --key r0-f0 \
    --versions 50000 \
    --min-size 2048 \
    --max-size 1048576 \
    --batch-size 1000 \
    --concurrency 32 \
    --queue-size 10000 \
    --log-file /var/log/ceph/<clusterid>/ceph-client.rgw.<host>.<something>.log \
    --mode all

Notes:
- Run on a host that can reach the RGW endpoint and (optionally) read the RGW log file path.
- For generation, repeated PUTs to the same key require bucket versioning=Enabled.
- DeleteObjects batch size is capped at 1000 by S3 API.
"""

import argparse
import concurrent.futures as cf
import hashlib
import os
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

# ---------- Utility formatting ----------


def human(n: float) -> str:
    """Human friendly number formatting for bytes or counts when appropriate."""
    # Simple format for counts
    if isinstance(n, int) and n < 10000:
        return str(n)
    # For floats/large ints
    for unit in ["", "K", "M", "B", "T"]:
        if abs(n) < 1000.0:
            return f"{n:3.1f}{unit}"
        n /= 1000.0
    return f"{n:.1f}P"


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)


# ---------- S3 helpers ----------


def make_s3_client(
    endpoint: str,
    access_key: str,
    secret_key: str,
    region: str = "us-east-1",
    max_pool: int = 64,
):
    cfg = Config(
        signature_version="s3v4",
        s3={"addressing_style": "path"},
        retries={"max_attempts": 10, "mode": "standard"},
        max_pool_connections=max_pool,
        connect_timeout=10,
        read_timeout=300,
    )
    return boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url=endpoint,
        region_name=region,
        config=cfg,
    )


def ensure_bucket_versioned(s3, bucket: str):
    # Create bucket if missing
    try:
        s3.head_bucket(Bucket=bucket)
        log(f"Bucket exists: {bucket}")
    except ClientError as e:
        err = e.response.get("Error", {}).get("Code")
        if err in ("404", "NoSuchBucket", "NotFound"):
            log(f"Creating bucket: {bucket}")
            s3.create_bucket(Bucket=bucket)
        else:
            raise

    # Enable versioning
    ver = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Suspended")
    if ver != "Enabled":
        log(f"Enabling versioning on {bucket}")
        s3.put_bucket_versioning(
            Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
        )
    else:
        log(f"Versioning already Enabled on {bucket}")


def rand_bytes(n: int) -> bytes:
    # Lightweight deterministic-ish random payload generator
    seed = random.getrandbits(64).to_bytes(8, "little") + int(time.time_ns()).to_bytes(
        8, "little"
    )
    h = hashlib.blake2b(seed, digest_size=32).digest()
    # Expand to size n
    out = bytearray()
    while len(out) < n:
        out.extend(h)
        h = hashlib.blake2b(h, digest_size=32).digest()
    return bytes(out[:n])


def put_versions(
    s3,
    bucket: str,
    key: str,
    versions: int,
    min_size: int,
    max_size: int,
    concurrency: int,
) -> Dict[str, float]:
    """
    Repeatedly PUT the same key to create multiple versions.
    Returns timing stats.
    """
    start = time.time()
    total_bytes = 0
    put_count = 0
    lock = threading.Lock()

    def worker(idx: int):
        nonlocal total_bytes, put_count
        size = random.randint(min_size, max_size)
        body = rand_bytes(size)
        try:
            s3.put_object(Bucket=bucket, Key=key, Body=body)
            with lock:
                total_bytes += size
                put_count += 1
            if idx % 1000 == 0 and idx > 0:
                log(f"PUT progress: {idx}/{versions}")
        except Exception as e:
            log(f"PUT error @ {idx}: {e}")

    log(
        f"Generating {versions} versions for key '{key}' in bucket '{bucket}' "
        f"(size {min_size}-{max_size} bytes, concurrency={concurrency})"
    )

    with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(worker, range(versions)))

    elapsed = time.time() - start
    throughput = put_count / elapsed if elapsed > 0 else 0
    bps = total_bytes / elapsed if elapsed > 0 else 0
    log(
        f"PUT done: {put_count} versions in {elapsed:.1f}s "
        f"({throughput:.1f} ops/s, {bps/1024:.1f} KiB/s)"
    )
    return {"elapsed": elapsed, "ops": put_count, "bytes": total_bytes}


def list_all_versions(
    s3, bucket: str, key: Optional[str] = None, limit: Optional[int] = None
) -> Iterable[Tuple[str, str]]:
    """
    Yield (Key, VersionId) pairs for all versions (optionally filtered by key).
    """
    kwargs = {"Bucket": bucket, "MaxKeys": 1000}
    if key:
        kwargs["Prefix"] = key

    while True:
        resp = s3.list_object_versions(**kwargs)
        versions = resp.get("Versions", []) + resp.get("DeleteMarkers", [])
        for v in versions:
            if key is None or v["Key"] == key:
                yield (v["Key"], v["VersionId"])
                if limit is not None:
                    limit -= 1
                    if limit <= 0:
                        return
        if resp.get("IsTruncated"):
            kwargs["KeyMarker"] = resp.get("NextKeyMarker")
            kwargs["VersionIdMarker"] = resp.get("NextVersionIdMarker")
        else:
            break


def chunker(iterable, size):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def delete_batch_with_retries(
    s3, bucket: str, batch: List[Tuple[str, str]], max_retries: int = 8
) -> Dict:
    """
    DeleteObjects for a batch of (Key, VersionId) with backoff on throttling/SlowDown/5xx.
    Returns the S3 response and error stats.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            objects = [{"Key": k, "VersionId": vid} for (k, vid) in batch]
            resp = s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": objects, "Quiet": True},
            )
            return {"ok": True, "attempt": attempt, "resp": resp}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            retriable = code in ("SlowDown", "Throttling", "RequestTimeout") or (
                500 <= int(status) < 600
            )
            if retriable and attempt < max_retries:
                backoff = min(60, 0.5 * (2 ** (attempt - 1)))
                log(
                    f"DeleteObjects retry {attempt} (code={code} status={status}); sleeping {backoff:.1f}s"
                )
                time.sleep(backoff)
                continue
            else:
                log(
                    f"DeleteObjects failed (attempts={attempt}) code={code} status={status}: {e}"
                )
                return {"ok": False, "attempt": attempt, "error": str(e)}
        except EndpointConnectionError as ee:
            if attempt < max_retries:
                backoff = min(60, 0.5 * (2 ** (attempt - 1)))
                log(f"Endpoint error retry {attempt}: {ee}; sleeping {backoff:.1f}s")
                time.sleep(backoff)
                continue
            return {"ok": False, "attempt": attempt, "error": str(ee)}
        except Exception as e:
            log(f"Unexpected delete error: {e}")
            return {"ok": False, "attempt": attempt, "error": str(e)}


def bulk_delete_versions(
    s3, bucket: str, key: str, batch_size: int, concurrency: int, queue_size: int
) -> Dict[str, float]:
    """
    List versions for a single key and delete them in parallel DeleteObjects batches.
    queue_size: prefetch count of (Key,VersionId) to buffer (controls memory/latency).
    """
    start = time.time()
    total = 0
    ok_batches = 0
    err_batches = 0
    attempts_acc = 0

    # Producer: list versions for the key
    q: Deque[Tuple[str, str]] = deque()

    def producer():
        nonlocal q
        for kv in list_all_versions(s3, bucket, key):
            q.append(kv)
            # Trim queue to queue_size
            while len(q) > queue_size:
                time.sleep(0.01)

    prod_th = threading.Thread(target=producer, daemon=True)
    prod_th.start()

    # Consumer workers
    lock = threading.Lock()

    def consume(batch: List[Tuple[str, str]]):
        nonlocal total, ok_batches, err_batches, attempts_acc
        res = delete_batch_with_retries(s3, bucket, batch)
        with lock:
            total += len(batch)
            attempts_acc += res.get("attempt", 1)
            if res.get("ok"):
                ok_batches += 1
            else:
                err_batches += 1

    log(
        f"Starting bulk delete for key '{key}' with batch_size={batch_size}, concurrency={concurrency}, queue_size={queue_size}"
    )

    with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = []
        # Continuously consume from queue until producer finishes and queue drains
        while prod_th.is_alive() or q:
            if len(q) >= batch_size:
                batch = [q.popleft() for _ in range(batch_size)]
                futures.append(ex.submit(consume, batch))
            else:
                # If producer finished and remaining < batch_size, flush them too
                if not prod_th.is_alive() and q:
                    batch = []
                    while q:
                        batch.append(q.popleft())
                        if len(batch) == batch_size:
                            futures.append(ex.submit(consume, batch))
                            batch = []
                    if batch:
                        futures.append(ex.submit(consume, batch))
                else:
                    time.sleep(0.01)
        # Wait for all delete batches to complete
        for f in cf.as_completed(futures):
            _ = f.result()

    elapsed = time.time() - start
    ops_per_sec = total / elapsed if elapsed > 0 else 0.0
    avg_attempts = attempts_acc / max(1, (ok_batches + err_batches))
    log(
        f"DELETE done: {total} versions in {elapsed:.1f}s "
        f"({ops_per_sec:.1f} versions/s, batches ok={ok_batches}, err={err_batches}, avg attempts/batch={avg_attempts:.2f})"
    )

    return {
        "elapsed": elapsed,
        "deleted": total,
        "ok_batches": ok_batches,
        "err_batches": err_batches,
        "avg_attempts": avg_attempts,
    }


# ---------- Log analysis ----------

REQ_ID_RE = re.compile(r"\breq\s+(\d+)\b")
OLH_RE = re.compile(r"(apply_olh_log|apply\s+olh|apply_olh|update_olh)", re.IGNORECASE)
# Attempt to extract object oid and request id on same or neighboring lines
OID_RE = re.compile(r"\boid[:=]\s*([A-Za-z0-9._\-~]+)")
FAILED_RE = re.compile(r"\b(fail|failed|error)\b", re.IGNORECASE)


def analyze_rgw_log(path: str, max_samples_per_key: int = 3) -> Dict:
    """
    Parse RGW log to compute:
      - distinct request IDs
      - total OLH-related lines
      - most frequent (req_id, oid) pairs among OLH lines
    Returns a dict with summary and a few sample lines per top pair.
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"RGW log not found: {path}")

    req_ids = set()
    olh_count = 0
    pair_counter: Counter = Counter()
    samples: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    # Keep a small lookback for correlating neighboring lines
    lookback: Deque[str] = deque(maxlen=2)

    with open(path, "r", errors="ignore") as f:
        for line in f:
            lookback.append(line.rstrip("\n"))
            # Count req ids globally
            for m in REQ_ID_RE.finditer(line):
                req_ids.add(m.group(1))
            # OLH-related line?
            if OLH_RE.search(line):
                olh_count += 1
                # Try to extract req id and oid from current or lookback lines
                rid = None
                oid = None
                m = REQ_ID_RE.search(line) or (
                    REQ_ID_RE.search(lookback[0]) if lookback else None
                )
                if m:
                    rid = m.group(1)
                mo = OID_RE.search(line) or (
                    OID_RE.search(lookback[0]) if lookback else None
                )
                if mo:
                    oid = mo.group(1)
                key = (rid or "unknown", oid or "unknown")
                pair_counter[key] += 1
                # Capture a few failure-scented sample lines
                if FAILED_RE.search(line) and len(samples[key]) < max_samples_per_key:
                    samples[key].append(line.strip())

    top_pairs = pair_counter.most_common(10)
    return {
        "distinct_requests": len(req_ids),
        "olh_related_lines": olh_count,
        "top_pairs": top_pairs,
        "samples": samples,
    }


# ---------- Orchestration ----------


def main():
    ap = argparse.ArgumentParser(description="RGW OLH replay reproducer & analyzer")
    ap.add_argument(
        "--endpoint", required=True, help="RGW/S3 endpoint, e.g., http://host:81"
    )
    ap.add_argument("--access-key", required=True)
    ap.add_argument("--secret-key", required=True)
    ap.add_argument(
        "--bucket", required=True, help="Bucket name (will be created if missing)"
    )
    ap.add_argument("--key", required=True, help="Object key to version repeatedly")
    ap.add_argument(
        "--versions", type=int, default=50000, help="Number of versions to create"
    )
    ap.add_argument(
        "--min-size", type=int, default=2048, help="Min object size in bytes"
    )
    ap.add_argument(
        "--max-size", type=int, default=1048576, help="Max object size in bytes (~1MiB)"
    )
    ap.add_argument(
        "--batch-size", type=int, default=1000, help="DeleteObjects batch size (<=1000)"
    )
    ap.add_argument(
        "--concurrency", type=int, default=32, help="Thread concurrency for PUT/DELETE"
    )
    ap.add_argument(
        "--queue-size", type=int, default=10000, help="Prefetch queue size for delete"
    )
    ap.add_argument("--log-file", default=None, help="Path to RGW log to analyze")
    ap.add_argument(
        "--mode",
        choices=["all", "prepare", "generate", "delete", "verify"],
        default="all",
        help="Run subset: prepare (bucket+versioning), generate (puts), delete (bulk delete), verify (logs); all runs everything",
    )
    args = ap.parse_args()

    s3 = make_s3_client(
        args.endpoint,
        args.access_key,
        args.secret_key,
        max_pool=max(args.concurrency * 2, 64),
    )

    if args.mode in ("all", "prepare"):
        ensure_bucket_versioned(s3, args.bucket)

    if args.mode in ("all", "generate"):
        put_versions(
            s3,
            args.bucket,
            args.key,
            args.versions,
            args.min_size,
            args.max_size,
            args.concurrency,
        )

    if args.mode in ("all", "delete"):
        # Gather and delete up to all versions for the key
        stats = bulk_delete_versions(
            s3,
            args.bucket,
            args.key,
            args.batch_size,
            args.concurrency,
            args.queue_size,
        )
        log(f"Delete stats: {stats}")

    if args.mode in ("all", "verify"):
        if args.log_file:
            try:
                summary = analyze_rgw_log(args.log_file)
                log("=== RGW Log Analysis Summary ===")
                log(
                    f"Distinct requests (grep -o 'req [0-9]+' | sort | uniq | wc -l): {summary['distinct_requests']}"
                )
                log(
                    f"OLH-related lines (apply_olh_log|apply_olh|update_olh): {summary['olh_related_lines']}"
                )
                log("Top (req_id, oid) pairs by frequency:")
                for (rid, oid), cnt in summary["top_pairs"]:
                    log(f"  req={rid} oid={oid} -> {cnt} hits")
                    for samp in summary["samples"].get((rid, oid), []):
                        log(f"    sample: {samp[:300]}")
            except Exception as e:
                log(f"Log analysis error: {e}")
        else:
            log("No --log-file provided; skipping RGW log verification.")

    log("Done.")


if __name__ == "__main__":
    main()
