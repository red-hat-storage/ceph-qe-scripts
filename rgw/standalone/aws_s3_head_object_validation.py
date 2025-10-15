import json
import os
import subprocess
import sys
import time

# ---------------- CONFIG ----------------
BUCKET_NAME = os.environ.get("BUCKET_NAME", "scale-bkt-1")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", f"50Mawsobj_validate_{BUCKET_NAME}")
LOG_EVERY = int(os.environ.get("LOG_EVERY", "100"))  # log progress every N objects
# ----------------------------------------


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, file=sys.stderr, flush=True)


def aws_cli(cmd):
    """Run an aws cli command and return parsed JSON."""
    try:
        res = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return json.loads(res.stdout)
    except subprocess.CalledProcessError as e:
        log(f"AWS CLI failed: {e.stderr.strip()}")
        return {}
    except json.JSONDecodeError as e:
        log(f"JSON parse failed: {e}")
        return {}


def list_objects(bucket, continuation_token=None):
    """List up to 1000 objects from bucket."""
    cmd = [
        "aws",
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--endpoint-url",
        "http://10.1.172.231:5000",
        "--max-items",
        "1000",
    ]
    if continuation_token:
        cmd.extend(["--starting-token", continuation_token])
    res = aws_cli(cmd)
    if not res:
        return [], None
    objs = res.get("Contents", [])
    next_token = res.get("NextToken")
    return objs, next_token


def head_object(bucket, key):
    """Get metadata of object."""
    cmd = [
        "aws",
        "s3api",
        "head-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--endpoint-url",
        "http://10.1.172.231:5000",
    ]
    return aws_cli(cmd)


def validate(obj_meta, key):
    """Check StorageClass vs expected."""
    size = int(obj_meta.get("ContentLength", 0))
    storage_class = obj_meta.get("StorageClass", "STANDARD")

    expected_sc = "STANDARD" if size < 1048576 else "ERASURE"
    status = "ERROR" if expected_sc != str(storage_class) else "PASS"

    return (
        f"Object: {key}\t"
        f"size: {size}\t"
        f"StorageClass: {storage_class}\t"
        f"Expected: {expected_sc}\t"
        f"Validation: {status}\n"
    )


def main():
    log(f"Starting head-object validation for bucket={BUCKET_NAME}")
    processed = 0
    token = None

    with open(OUTPUT_FILE, "w") as f:
        while True:
            objs, token = list_objects(BUCKET_NAME, token)
            if not objs:
                break
            for obj in objs:
                key = obj["Key"]
                meta = head_object(BUCKET_NAME, key)
                if meta:
                    f.write(validate(meta, key))
                processed += 1
                if processed % LOG_EVERY == 0:
                    log(f"Processed {processed} objects...")

            if not token:
                break

    log(f"Completed. Total processed={processed}. Results written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
