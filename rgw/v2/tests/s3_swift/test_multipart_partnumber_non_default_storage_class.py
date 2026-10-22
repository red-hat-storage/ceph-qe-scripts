"""
test_multipart_partnumber_non_default_storage_class.py

Usage:
    test_multipart_partnumber_non_default_storage_class.py -c configs/test_multipart_partnumber_non_default_storage_class.yaml

Tracker: https://tracker.ceph.com/issues/81780

Single-site cluster with no realm. Placement is stored on the local zone and
zonegroup, and RGW loads it when the daemons restart.

Operation:
    1. Add STANDARD_IA, with its own data pool, to default-placement.
    2. CreateMultipartUpload with StorageClass=STANDARD_IA, upload the parts,
       and complete the upload.
    3. Fetch the entire object. This read succeeds on both fixed and unfixed RGW.
    4. GET and HEAD the completed object with ?partNumber=1.

Unfixed RGW looks up the part head in the bucket's default pool and returns
400 InvalidPart. This test fails when that response is returned. A fixed RGW
returns the uploaded part.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import boto3
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()

TRACKER = "https://tracker.ceph.com/issues/81780"
MIB = 1024 * 1024
MIN_NON_FINAL_PART = 5 * MIB
_PROTECTED_POOLS = {
    ".rgw.root",
    "default.rgw.control",
    "default.rgw.meta",
    "default.rgw.log",
    "default.rgw.buckets.index",
    "default.rgw.buckets.data",
    "default.rgw.buckets.non-ec",
}


def _loads_doc(text, cmd):
    """Parse the first JSON value in command output."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        return parsed
    raise TestExecError(f"no JSON in output of {cmd}: {text[:400]}")


def _run(cmd):
    out = utils.exec_shell_cmd(cmd)
    if out is False:
        raise TestExecError(f"command failed: {cmd}")
    return out


def _json_cmd(cmd):
    return _loads_doc(_run(cmd), cmd)


def _zone_context(placement):
    zone_doc = _json_cmd("radosgw-admin zone get")
    zonegroup_doc = _json_cmd("radosgw-admin zonegroup get")
    return {
        "zone": zone_doc["name"],
        "zonegroup": zonegroup_doc["name"],
        "placement": placement,
        "zone_doc": zone_doc,
        "zonegroup_doc": zonegroup_doc,
    }


def _zone_storage_class(zone_doc, placement, storage_class):
    for entry in zone_doc.get("placement_pools", []):
        if entry.get("key") != placement:
            continue
        classes = entry.get("val", {}).get("storage_classes", {})
        return classes.get(storage_class)
    return None


def _zonegroup_has_class(zonegroup_doc, placement, storage_class):
    for target in zonegroup_doc.get("placement_targets", []):
        if target.get("name") != placement:
            continue
        classes = target.get("storage_classes") or []
        if isinstance(classes, dict):
            return storage_class in classes
        return storage_class in classes
    return False


def _require_single_site_without_realm(ctx):
    realm_doc = _json_cmd("radosgw-admin realm list")
    realms = realm_doc.get("realms") or []
    default_info = realm_doc.get("default_info") or ""
    realm_id = ctx["zonegroup_doc"].get("realm_id") or ""
    zones = ctx["zonegroup_doc"].get("zones") or []
    if realms or default_info or realm_id:
        raise TestExecError(
            "This test runs on a single-site cluster with no realm. "
            f"Found realms={realms}, default_info={default_info!r}, "
            f"zonegroup realm_id={realm_id!r}."
        )
    if len(zones) != 1:
        names = [
            zone.get("name", zone) if isinstance(zone, dict) else zone for zone in zones
        ]
        raise TestExecError(
            "This test runs on a single-site cluster with one zone. "
            f"Zonegroup {ctx['zonegroup']} has zones {names}."
        )
    if _zone_storage_class(ctx["zone_doc"], ctx["placement"], "STANDARD") is None:
        raise TestExecError(
            f"placement {ctx['placement']} is not configured on zone {ctx['zone']}"
        )
    log.info(
        "single-site cluster with no realm (zone=%s zonegroup=%s placement=%s)",
        ctx["zone"],
        ctx["zonegroup"],
        ctx["placement"],
    )


def _rgw_daemon_starts():
    listed = _json_cmd("ceph orch ps --daemon_type rgw --format json")
    if isinstance(listed, dict):
        listed = [listed]
    starts = {}
    for daemon in listed:
        if not isinstance(daemon, dict):
            continue
        name = daemon.get("daemon_name")
        if name:
            starts[name] = daemon.get("started", "")
    return starts


def _restart_rgw_daemons():
    """Restart RGW and wait until the new processes are the ones running.

    ``ceph orch restart`` returns before the old process exits. A following
    status check can still see the previous daemon, which does not have the
    storage class and rejects CreateMultipartUpload with InvalidArgument.
    """
    log.info("restarting RGW so it reloads the local zone and zonegroup")
    before = _rgw_daemon_starts()
    listed = _json_cmd("ceph orch ls --service-type rgw -f json")
    if isinstance(listed, dict):
        listed = [listed]
    if not listed:
        raise TestExecError("no RGW services found to restart")
    for service in listed:
        name = service.get("service_name")
        if not name:
            raise TestExecError(f"RGW service is missing service_name: {service}")
        if utils.exec_shell_cmd(f"ceph orch restart {name}") is False:
            raise TestExecError(f"failed to restart {name}")
    deadline = time.time() + 180
    while time.time() < deadline:
        time.sleep(5)
        try:
            utils.rgw_daemons_status()
        except TestExecError as exc:
            log.info("RGW daemons are not ready yet: %s", exc)
            continue
        after = _rgw_daemon_starts()
        restarted = [
            name
            for name, started in before.items()
            if after.get(name) and after.get(name) != started
        ]
        log.info(
            "RGW restart progress: %s/%s daemons have a new start time",
            len(restarted),
            len(before),
        )
        if before and len(restarted) == len(before):
            log.info("RGW daemons reloaded the zone and zonegroup")
            return
        if not before and after:
            log.info("RGW daemons are running")
            return
    raise TestExecError(
        "RGW daemons did not finish restarting after the placement change"
    )


def _pool_names():
    return set(_run("ceph osd pool ls").split())


def _delete_pool(pool_name):
    if pool_name not in _pool_names():
        return
    log.info("removing pool %s", pool_name)
    if utils.exec_shell_cmd("ceph config set mon mon_allow_pool_delete true") is False:
        raise TestExecError("failed to allow pool deletion")
    try:
        _run(
            f"ceph osd pool rm {pool_name} {pool_name} " "--yes-i-really-really-mean-it"
        )
    finally:
        utils.exec_shell_cmd("ceph config set mon mon_allow_pool_delete false")


def _remove_storage_class_if_present(storage_class, pool_name, ctx):
    existing = _zone_storage_class(ctx["zone_doc"], ctx["placement"], storage_class)
    on_zonegroup = _zonegroup_has_class(
        ctx["zonegroup_doc"], ctx["placement"], storage_class
    )
    pools_to_remove = set()
    if pool_name in _pool_names():
        pools_to_remove.add(pool_name)
    if not existing and not on_zonegroup:
        for name in pools_to_remove:
            _delete_pool(name)
        return
    log.info(
        "storage class %s already exists on placement %s; removing it before this run",
        storage_class,
        ctx["placement"],
    )
    if existing:
        data_pool = existing.get("data_pool") if isinstance(existing, dict) else None
        if data_pool in _PROTECTED_POOLS:
            log.info("leaving built-in pool %s in place", data_pool)
        elif data_pool:
            pools_to_remove.add(data_pool)
        _run(
            "radosgw-admin zone placement rm "
            f"--rgw-zone {ctx['zone']} "
            f"--placement-id {ctx['placement']} "
            f"--storage-class {storage_class}"
        )
    if on_zonegroup:
        _run(
            "radosgw-admin zonegroup placement rm "
            f"--rgw-zonegroup {ctx['zonegroup']} "
            f"--placement-id {ctx['placement']} "
            f"--storage-class {storage_class}"
        )
    for name in pools_to_remove:
        _delete_pool(name)


def _add_storage_class(storage_class, pool_name, ctx):
    log.info(
        "adding storage class %s on placement %s with data pool %s",
        storage_class,
        ctx["placement"],
        pool_name,
    )
    _run(f"ceph osd pool create {pool_name}")
    _run(f"ceph osd pool application enable {pool_name} rgw")
    _run(
        "radosgw-admin zonegroup placement add "
        f"--rgw-zonegroup {ctx['zonegroup']} "
        f"--placement-id {ctx['placement']} "
        f"--storage-class {storage_class}"
    )
    _run(
        "radosgw-admin zone placement add "
        f"--rgw-zone {ctx['zone']} "
        f"--placement-id {ctx['placement']} "
        f"--storage-class {storage_class} "
        f"--data-pool {pool_name} "
        "--compression none"
    )


def _setup_storage_class(storage_class, pool_name, placement, ready):
    ctx = _zone_context(placement)
    _require_single_site_without_realm(ctx)
    _remove_storage_class_if_present(storage_class, pool_name, ctx)
    ctx = _zone_context(placement)
    ready.append({"name": storage_class, "pool": pool_name})
    _add_storage_class(storage_class, pool_name, ctx)
    _restart_rgw_daemons()
    ctx = _zone_context(placement)
    info = _zone_storage_class(ctx["zone_doc"], placement, storage_class)
    if not isinstance(info, dict) or info.get("data_pool") != pool_name:
        raise TestExecError(
            f"storage class {storage_class} is not mapped to {pool_name} "
            f"on {placement} after RGW restart: {info}"
        )
    log.info("storage class %s is ready on %s", storage_class, placement)


def _teardown_storage_class(ready, placement):
    if not ready:
        return None
    problems = []
    try:
        ctx = _zone_context(placement)
    except TestExecError as exc:
        problems.append(str(exc))
        ctx = None
    if ctx:
        for spec in ready:
            for cmd in (
                "radosgw-admin zone placement rm "
                f"--rgw-zone {ctx['zone']} "
                f"--placement-id {placement} "
                f"--storage-class {spec['name']}",
                "radosgw-admin zonegroup placement rm "
                f"--rgw-zonegroup {ctx['zonegroup']} "
                f"--placement-id {placement} "
                f"--storage-class {spec['name']}",
            ):
                if utils.exec_shell_cmd(cmd) is False:
                    problems.append(f"command failed: {cmd}")
    if utils.exec_shell_cmd("ceph config set mon mon_allow_pool_delete true") is False:
        problems.append("failed to allow pool deletion")
    try:
        for spec in ready:
            cmd = (
                f"ceph osd pool rm {spec['pool']} {spec['pool']} "
                "--yes-i-really-really-mean-it"
            )
            if utils.exec_shell_cmd(cmd) is False:
                problems.append(f"command failed: {cmd}")
    finally:
        utils.exec_shell_cmd("ceph config set mon mon_allow_pool_delete false")
    try:
        _restart_rgw_daemons()
    except TestExecError as exc:
        problems.append(f"RGW restart after teardown failed: {exc}")
    if problems:
        log.error("storage class teardown problems: %s", problems)
        return "; ".join(problems)
    log.info("removed storage class and data pool")
    return None


def _part_sizes(config):
    raw = config.test_ops.get("part_sizes_mb", [5, 5, 1])
    try:
        sizes = [int(item) * MIB for item in raw]
    except (TypeError, ValueError) as exc:
        raise TestExecError(f"part_sizes_mb must be a list of integers: {raw}") from exc
    if len(sizes) < 2 or any(size < MIN_NON_FINAL_PART for size in sizes[:-1]):
        raise TestExecError(
            "each non-final part must be at least 5MiB and the object needs "
            f"at least 2 parts; got {sizes}"
        )
    if sizes[-1] <= 0:
        raise TestExecError(f"final part size must be positive; got {sizes}")
    return sizes


def _client_error(exc):
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status, error.get("Code", ""), error.get("Message", str(exc))


def _endpoint_is_up(endpoint_url):
    try:
        completed = subprocess.run(
            [
                "curl",
                "-k",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "5",
                endpoint_url,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.info("endpoint probe failed: %s", exc)
        return False
    code = (completed.stdout or "").strip()
    return code not in ("", "000")


def _wait_for_endpoint(endpoint_url):
    for attempt in range(1, 13):
        if _endpoint_is_up(endpoint_url):
            log.info("RGW endpoint %s is accepting connections", endpoint_url)
            return
        log.info("waiting for RGW endpoint %s (attempt %s/12)", endpoint_url, attempt)
        time.sleep(5)
    raise TestExecError(
        f"RGW endpoint {endpoint_url} did not accept connections after restart"
    )


def _safe_bucket_name(user_id):
    raw = utils.gen_bucket_name_from_userid(user_id, rand_no=0).lower()
    cleaned = "".join(char if char.isalnum() or char in ".-" else "-" for char in raw)
    cleaned = cleaned.strip(".-") or "mpu-standard-ia"
    return cleaned[:63]


def _bucket_region():
    zonegroup = _json_cmd("radosgw-admin zonegroup get")
    return zonegroup.get("api_name") or zonegroup.get("name") or "default"


def _s3_client(auth, region):
    """S3 client that does not attach a default checksum to every request.

    boto3 sends ``x-amz-checksum-algorithm`` on CreateMultipartUpload unless
    checksum calculation is limited to operations that require it. RGW answers
    that header with InvalidArgument and an empty message.
    """
    cfg_kwargs = {
        "signature_version": "s3v4",
        "s3": {"addressing_style": "path"},
        "retries": {"max_attempts": 2},
    }
    checksum_kwargs = {
        "request_checksum_calculation": "when_required",
        "response_checksum_validation": "when_required",
    }
    try:
        config = BotoConfig(**cfg_kwargs, **checksum_kwargs)
    except TypeError:
        config = BotoConfig(**cfg_kwargs)
    return boto3.client(
        "s3",
        aws_access_key_id=auth.access_key,
        aws_secret_access_key=auth.secret_key,
        aws_session_token=auth.session_token,
        endpoint_url=auth.endpoint_url,
        region_name=region,
        use_ssl=auth.ssl,
        verify=False,
        config=config,
    )


def _create_bucket(auth, bucket_name, zonegroup_region):
    regions = ["us-east-1"]
    if zonegroup_region and zonegroup_region not in regions:
        regions.append(zonegroup_region)
    last_error = "no response"
    for region in regions:
        client = _s3_client(auth, region)
        for attempt in range(1, 7):
            try:
                if region == "us-east-1":
                    client.create_bucket(Bucket=bucket_name)
                else:
                    client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
                log.info("created bucket %s", bucket_name)
                return client
            except ClientError as exc:
                status, code, message = _client_error(exc)
                last_error = f"{status} {code}: {message}"
                if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                    return client
                log.warning(
                    "create bucket attempt %s (%s): %s", attempt, region, last_error
                )
                if code in (
                    "InvalidLocationConstraint",
                    "IllegalLocationConstraintException",
                ):
                    break
            except BotoCoreError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                log.warning(
                    "create bucket attempt %s (%s): %s", attempt, region, last_error
                )
            time.sleep(5)
    raise TestExecError(f"bucket creation failed for {bucket_name}: {last_error}")


def _upload_multipart(client, bucket, key, part_sizes, storage_class):
    try:
        created = client.create_multipart_upload(
            Bucket=bucket, Key=key, StorageClass=storage_class
        )
    except ClientError as exc:
        status, code, message = _client_error(exc)
        error = exc.response.get("Error", {})
        raise TestExecError(
            "CreateMultipartUpload with StorageClass="
            f"{storage_class} failed ({status} {code}: {message}). "
            f"ArgumentName={error.get('ArgumentName')} "
            f"ArgumentValue={error.get('ArgumentValue')}"
        ) from exc
    upload_id = created["UploadId"]
    log.info(
        "CreateMultipartUpload %s storage_class=%s upload_id=%s",
        key,
        storage_class,
        upload_id,
    )
    parts = []
    bodies = []
    try:
        for number, size in enumerate(part_sizes, 1):
            data = bytes([number]) * size
            response = client.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=number,
                Body=data,
            )
            parts.append({"PartNumber": number, "ETag": response["ETag"]})
            bodies.append(data)
            log.info("uploaded part %s (%s bytes)", number, size)
        client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
    except Exception:
        try:
            client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        except ClientError as exc:
            log.warning("abort upload failed: %s", _client_error(exc))
        raise
    log.info("completed multipart upload %s (%s parts)", key, len(bodies))
    return bodies


def _read_part(client, call, bucket, key, part_number):
    """HEAD or GET one part. 400 InvalidPart is the unfixed bug."""
    try:
        if call == "HEAD":
            return client.head_object(Bucket=bucket, Key=key, PartNumber=part_number)
        return client.get_object(Bucket=bucket, Key=key, PartNumber=part_number)
    except ClientError as exc:
        status, code, message = _client_error(exc)
        if status == 400 and code == "InvalidPart":
            raise TestExecError(
                f"{call} ?partNumber={part_number} returned 400 InvalidPart "
                f"({message}). {TRACKER}: the part head was not found because "
                "the multipart upload is stored in STANDARD_IA."
            ) from exc
        raise TestExecError(
            f"{call} ?partNumber={part_number} failed ({status} {code}: {message})"
        ) from exc


def _fetch_entire_object(client, bucket, key, bodies):
    """Read the completed object with no partNumber before any part read."""
    expected = b"".join(bodies)
    log.info(
        "starting GET of the complete object %s/%s (%s bytes)",
        bucket,
        key,
        len(expected),
    )
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        status, code, message = _client_error(exc)
        raise TestExecError(
            f"GET of the entire object failed ({status} {code}: {message})"
        ) from exc
    payload = response["Body"].read()
    if payload != expected or response.get("ContentLength") != len(expected):
        raise TestExecError(
            f"GET of the entire object returned {len(payload)} bytes, "
            f"expected {len(expected)}"
        )
    log.info("fetched entire object %s (%s bytes)", key, len(payload))


def _check_part(client, bucket, key, part_number, part_body):
    head = _read_part(client, "HEAD", bucket, key, part_number)
    if head.get("ContentLength") != len(part_body):
        raise TestExecError(
            f"HEAD ?partNumber={part_number} ContentLength "
            f"{head.get('ContentLength')} != {len(part_body)}"
        )
    log.info(
        "HEAD ?partNumber=%s returned %s bytes",
        part_number,
        head.get("ContentLength"),
    )
    log.info(
        "starting GET of partNumber=%s for %s/%s (%s bytes)",
        part_number,
        bucket,
        key,
        len(part_body),
    )
    got = _read_part(client, "GET", bucket, key, part_number)
    payload = got["Body"].read()
    if got.get("ContentLength") != len(part_body) or payload != part_body:
        raise TestExecError(
            f"GET ?partNumber={part_number} returned {len(payload)} bytes, "
            f"expected {len(part_body)}"
        )
    log.info("GET ?partNumber=%s returned the uploaded part", part_number)


def _field_values(node, field):
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == field and isinstance(value, str):
                found.append(value)
            found.extend(_field_values(value, field))
    elif isinstance(node, list):
        for item in node:
            found.extend(_field_values(item, field))
    return found


def _bucket_index_storage_class(bucket, key):
    """Storage class from the bucket index. ``object stat`` omits that field."""
    listed = _json_cmd(f"radosgw-admin bucket list --bucket={bucket}")
    if isinstance(listed, dict):
        entries = listed.get("objects") or listed.get("entries") or []
    else:
        entries = listed
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("key")
        if name != key:
            continue
        storage_class = (entry.get("meta") or {}).get("storage_class", "")
        return storage_class or "STANDARD"
    return None


def _object_uses_class(bucket, key, storage_class, pool_name):
    """Confirm the completed object uses the storage class and its data pool."""
    recorded = _bucket_index_storage_class(bucket, key)
    stat = _json_cmd(f"radosgw-admin object stat --bucket={bucket} --object={key}")
    stat_classes = _field_values(stat, "storage_class")
    log.info(
        "bucket index storage_class=%s object stat storage_class values=%s",
        recorded,
        stat_classes,
    )
    if recorded != storage_class and storage_class not in stat_classes:
        raise TestExecError(
            f"object {key} storage class is {recorded}, expected {storage_class}"
        )
    listed = _run(f"rados -p {pool_name} ls")
    objects = [line for line in listed.splitlines() if line.strip()]
    log.info("data pool %s contains %s objects", pool_name, len(objects))
    if not objects:
        raise TestExecError(
            f"data pool {pool_name} has no objects after the {storage_class} upload"
        )


def _delete_bucket(client, bucket):
    try:
        uploads = client.list_multipart_uploads(Bucket=bucket)
        for upload in uploads.get("Uploads") or []:
            client.abort_multipart_upload(
                Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"]
            )
        listed = client.list_objects_v2(Bucket=bucket)
        for obj in listed.get("Contents") or []:
            client.delete_object(Bucket=bucket, Key=obj["Key"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        log.warning("bucket cleanup failed: %s", _client_error(exc))


def _run_upload(config, ssh_con, storage_class, pool_name, part_sizes, part_number):
    user = s3lib.create_users(config.user_count or 1)[0]
    client = None
    bucket_name = None
    try:
        auth = Auth(user, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        _wait_for_endpoint(auth.endpoint_url)
        bucket_name = _safe_bucket_name(user["user_id"])
        client = _create_bucket(auth, bucket_name, _bucket_region())
        key = "mpu-standard-ia"
        bodies = _upload_multipart(client, bucket_name, key, part_sizes, storage_class)
        if part_number < 1 or part_number > len(bodies):
            raise TestExecError(
                f"part_number {part_number} is outside 1..{len(bodies)}"
            )
        head = client.head_object(Bucket=bucket_name, Key=key)
        if head.get("StorageClass") != storage_class:
            raise TestExecError(
                f"HEAD StorageClass is {head.get('StorageClass')}, "
                f"expected {storage_class}"
            )
        _object_uses_class(bucket_name, key, storage_class, pool_name)
        _fetch_entire_object(client, bucket_name, key, bodies)
        _check_part(client, bucket_name, key, part_number, bodies[part_number - 1])
        log.info("GET/HEAD ?partNumber=%s succeeded for %s", part_number, storage_class)
    finally:
        if client and bucket_name:
            _delete_bucket(client, bucket_name)
        if config.user_remove:
            reusable.remove_user(user)


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    storage_class = config.storage_class or "STANDARD_IA"
    pool_name = config.pool_name or "standard.ia"
    placement = config.test_ops.get("placement_id", "default-placement")
    part_number = int(config.test_ops.get("part_number", 1))
    part_sizes = _part_sizes(config)
    ready = []
    try:
        _setup_storage_class(storage_class, pool_name, placement, ready)
        _run_upload(config, ssh_con, storage_class, pool_name, part_sizes, part_number)
    finally:
        teardown_error = _teardown_storage_class(ready, placement)
    if teardown_error:
        raise TestExecError(f"storage class teardown failed: {teardown_error}")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "STANDARD_IA multipart GET/HEAD partNumber",
        id="81780",
    )
    test_info.started_info()
    try:
        parser = argparse.ArgumentParser(description="RGW STANDARD_IA partNumber")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        CephConfOp(ssh_con)
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as exc:
        log.error(exc)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
