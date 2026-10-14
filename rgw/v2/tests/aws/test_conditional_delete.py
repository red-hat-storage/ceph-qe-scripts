"""
Usage: test_conditional_delete.py -c <input_yaml>
Polarion ID : 
<input_yaml>
    Note: Following yaml can be used
    configs/test_cond_delete_etag.yaml
    configs/test_cond_delete_etag_prefix.yaml
    configs/test_cond_delete_stale_attrs.yaml
    configs/test_cond_delete_lmt.yaml
    configs/test_cond_delete_size.yaml
    configs/test_cond_delete_correct_etag_and_incorrcet_size.yaml
    configs/test_cond_delete_correct_size_and_incorrcet_lmt.yaml
    configs/test_cond_delete_incorrect_etag_and_correct_lmt.yaml
    configs/test_cond_delete_all_correct.yaml
    configs/test_cond_put_if_none_match.yaml
    configs/test_cond_put_if_match.yaml
    configs/test_cond_put_if_none_match_ver.yaml
    configs/test_cond_put_if_match_ver.yaml
    configs/test_cond_put_multipart_if_none_match.yaml
    configs/test_cond_put_multipart_if_match.yaml

Operation:
Conditional delete scenarios.
test_cond_delete_etag_prefix.yaml checks that If-Match is an exact ETag:
<etag>EXTRA and "<etag>EXTRA" return 412 on the unversioned, current-version,
and versionId delete paths.
test_cond_delete_stale_attrs.yaml reads ETag, size, and mtime, overwrites the
object, then deletes with those old values. 204 after that overwrite is a
failure on unversioned and versioned buckets. The mtime-only repeat covers
the unversioned RADOS recheck and the versioned delete-marker path.
"""
import argparse
import json
import logging
import os
import random
import shlex
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger(__name__)
TEST_DATA_PATH = None
ETAG_PREFIX_SUFFIX = "EXTRA"


def _load_object_versions(cli_aws, bucket_name, endpoint):
    raw = aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
    if not raw:
        raise AssertionError(f"list-object-versions failed for {bucket_name}")
    return json.loads(raw)


def _versions_for(version_list, object_name, version_id=None):
    versions = version_list.get("Versions") or []
    matched = [v for v in versions if v.get("Key") == object_name]
    if version_id is not None:
        matched = [v for v in matched if v.get("VersionId") == version_id]
    return matched


def _latest_version(version_list, object_name):
    versions = _versions_for(version_list, object_name)
    latest = [v for v in versions if v.get("IsLatest")]
    if latest:
        return latest[0]
    return versions[0] if versions else None


def _delete_markers_for(version_list, object_name):
    markers = version_list.get("DeleteMarkers") or []
    return [m for m in markers if m.get("Key") == object_name]


def _etag_from_version(version):
    etag = (version.get("ETag") or "").strip('"')
    if not etag:
        raise AssertionError(f"object version has no ETag: {version}")
    return etag


def _precondition_failed(response):
    if not isinstance(response, str) or not response:
        return False
    lowered = response.lower()
    return (
        "preconditionfailed" in lowered
        or "precondition failed" in lowered
        or "pre-condition" in lowered
    )


def _delete_succeeded(response):
    if not isinstance(response, str):
        return False
    if _precondition_failed(response):
        return False
    if "error occurred" in response.lower():
        return False
    return True


def _reject_etag_prefix(
    cli_aws, bucket_name, object_name, endpoint, etag, version_id, path_name
):
    """If-Match of etag+EXTRA must be 412 and must not remove the object."""
    for form, if_match in (
        ("unquoted", f"{etag}{ETAG_PREFIX_SUFFIX}"),
        ("quoted", f'"{etag}{ETAG_PREFIX_SUFFIX}"'),
    ):
        log.info(
            "%s delete If-Match %s %r version_id=%s",
            path_name,
            form,
            if_match,
            version_id,
        )
        out = aws_reusable.conditional_delete_object(
            cli_aws,
            bucket_name,
            object_name,
            endpoint,
            versionid=version_id,
            etag=if_match,
            return_err=True,
        )
        log.info("%s If-Match %s response: %s", path_name, form, out)
        version_list = _load_object_versions(cli_aws, bucket_name, endpoint)
        if version_id:
            version_kept = bool(_versions_for(version_list, object_name, version_id))
        else:
            version_kept = bool(_versions_for(version_list, object_name))
        markers = _delete_markers_for(version_list, object_name)
        if not _precondition_failed(out) or not version_kept or markers:
            raise AssertionError(
                f"{path_name} If-Match {form} {if_match!r} must return 412 "
                f"and leave the object in place. response={out!r} "
                f"version_kept={version_kept} delete_markers={len(markers)}. "
                "If-Match is an exact ETag compare. etag+EXTRA matches only "
                "when the check uses etag.length() characters, which is the "
                "unversioned and current-version bug. Delete with versionId "
                "already rejects that value."
            )


def _delete_exact_etag(
    cli_aws, bucket_name, object_name, endpoint, etag, version_id, path_name
):
    log.info(
        "%s delete If-Match exact %s version_id=%s", path_name, etag, version_id
    )
    out = aws_reusable.conditional_delete_object(
        cli_aws,
        bucket_name,
        object_name,
        endpoint,
        versionid=version_id,
        etag=etag,
        return_err=True,
    )
    log.info("%s exact If-Match response: %s", path_name, out)
    if not _delete_succeeded(out):
        raise AssertionError(
            f"{path_name} exact If-Match {etag!r} should delete the object, "
            f"got {out!r}"
        )
    version_list = _load_object_versions(cli_aws, bucket_name, endpoint)
    if version_id:
        if _versions_for(version_list, object_name, version_id):
            raise AssertionError(
                f"{path_name} exact If-Match left version {version_id} in place"
            )
        return
    if path_name == "current-version":
        if not _delete_markers_for(version_list, object_name):
            raise AssertionError(
                f"{path_name} exact If-Match did not create a delete marker: {out!r}"
            )
        if not _versions_for(version_list, object_name):
            raise AssertionError(
                f"{path_name} exact If-Match removed the object version instead "
                "of creating a delete marker"
            )
        return
    if _versions_for(version_list, object_name) or _delete_markers_for(
        version_list, object_name
    ):
        raise AssertionError(
            f"{path_name} exact If-Match left object {object_name} in the bucket"
        )


def _test_etag_prefix_if_match(cli_aws, bucket_name, object_name, endpoint):
    """
    If-Match is an exact ETag compare on every delete path.

    For an object whose ETag is <etag>, If-Match <etag>EXTRA and
    "<etag>EXTRA" must return 412 and leave the object in place:
      - unversioned delete
      - current-version delete (versioned bucket, no versionId)
      - delete with versionId
    An exact If-Match still deletes, so a server that rejects every
    If-Match does not pass.
    """
    version_list = _load_object_versions(cli_aws, bucket_name, endpoint)
    current = _latest_version(version_list, object_name)
    if current is None:
        raise AssertionError(f"{object_name} missing before prefix If-Match checks")
    etag = _etag_from_version(current)
    log.info(
        "unversioned object %s ETag=%s; If-Match %s%s and \"%s%s\" must be 412",
        object_name,
        etag,
        etag,
        ETAG_PREFIX_SUFFIX,
        etag,
        ETAG_PREFIX_SUFFIX,
    )
    _reject_etag_prefix(
        cli_aws, bucket_name, object_name, endpoint, etag, None, "unversioned"
    )
    _delete_exact_etag(
        cli_aws, bucket_name, object_name, endpoint, etag, None, "unversioned"
    )

    log.info("enable versioning for current-version and versionId If-Match paths")
    aws_reusable.put_get_bucket_versioning(cli_aws, bucket_name, endpoint)
    ver_object = "testobj-ver"
    aws_reusable.put_object(
        cli_aws, bucket_name, ver_object, endpoint, body=object_name
    )
    version_list = _load_object_versions(cli_aws, bucket_name, endpoint)
    ver = _latest_version(version_list, ver_object)
    if ver is None:
        raise AssertionError(f"{ver_object} missing after versioned put")
    ver_etag = _etag_from_version(ver)
    ver_id = ver.get("VersionId")
    if not ver_id or ver_id == "null":
        raise AssertionError(
            f"versioned put of {ver_object} did not return a version id: {ver_id}"
        )
    log.info(
        "versioned object %s ETag=%s VersionId=%s", ver_object, ver_etag, ver_id
    )
    _reject_etag_prefix(
        cli_aws,
        bucket_name,
        ver_object,
        endpoint,
        ver_etag,
        None,
        "current-version",
    )
    _reject_etag_prefix(
        cli_aws,
        bucket_name,
        ver_object,
        endpoint,
        ver_etag,
        ver_id,
        "versionId",
    )
    _delete_exact_etag(
        cli_aws,
        bucket_name,
        ver_object,
        endpoint,
        ver_etag,
        None,
        "current-version",
    )
    _delete_exact_etag(
        cli_aws,
        bucket_name,
        ver_object,
        endpoint,
        ver_etag,
        ver_id,
        "versionId",
    )


def _normalize_lmt(last_modified, ceph_major):
    text = str(last_modified)
    if float(ceph_major) >= 20:
        return text.split("+")[0]
    return text.split(".")[0]


def _object_attrs(cli_aws, bucket_name, object_name, endpoint, ceph_major):
    version_list = _load_object_versions(cli_aws, bucket_name, endpoint)
    markers = _delete_markers_for(version_list, object_name)
    latest_versions = [
        version
        for version in _versions_for(version_list, object_name)
        if version.get("IsLatest")
    ]
    latest = (
        latest_versions[0]
        if latest_versions
        else _latest_version(version_list, object_name)
    )
    if latest is None:
        return None, markers
    return {
        "etag": _etag_from_version(latest),
        "size": int(latest["Size"]),
        "lmt": _normalize_lmt(latest["LastModified"], ceph_major),
        "version_id": latest.get("VersionId"),
    }, markers


def _put_sized_object(cli_aws, bucket_name, object_name, endpoint, size):
    body = (
        os.path.join(TEST_DATA_PATH, object_name)
        if TEST_DATA_PATH
        else object_name
    )
    quoted_body = shlex.quote(body)
    created = utils.exec_shell_cmd(
        f"rm -f {quoted_body} && fallocate -l {size} {quoted_body}"
    )
    if created is False:
        raise AssertionError(f"failed to create object body {body}")
    aws_reusable.put_object(
        cli_aws, bucket_name, object_name, endpoint, body=body
    )


def _overwrite_until_changed(
    cli_aws, bucket_name, object_name, endpoint, ceph_major, old, new_size
):
    """Overwrite until ETag, size, and mtime all differ from the values just read."""
    updated = None
    for _ in range(5):
        time.sleep(1)
        _put_sized_object(cli_aws, bucket_name, object_name, endpoint, new_size)
        updated, markers = _object_attrs(
            cli_aws, bucket_name, object_name, endpoint, ceph_major
        )
        if markers:
            raise AssertionError(
                f"overwrite of {object_name} created a delete marker"
            )
        if (
            updated
            and updated["etag"] != old["etag"]
            and updated["size"] != old["size"]
            and updated["lmt"] != old["lmt"]
        ):
            return updated
    raise AssertionError(
        f"overwrite of {object_name} did not change ETag, size, and mtime; "
        f"old={old} new={updated}"
    )


def _assert_stale_delete_keeps_object(
    cli_aws,
    bucket_name,
    object_name,
    endpoint,
    ceph_major,
    old,
    new,
    path_name,
    condition_name,
    send_etag,
    send_size,
    send_mtime,
):
    out = aws_reusable.conditional_delete_object(
        cli_aws,
        bucket_name,
        object_name,
        endpoint,
        etag=old["etag"] if send_etag else None,
        size=old["size"] if send_size else None,
        last_modified_time=old["lmt"] if send_mtime else None,
        return_err=True,
    )
    log.info("%s stale %s delete response: %s", path_name, condition_name, out)
    current, markers = _object_attrs(
        cli_aws, bucket_name, object_name, endpoint, ceph_major
    )
    kept = (
        _precondition_failed(out)
        and not markers
        and current is not None
        and current["etag"] == new["etag"]
        and current["size"] == new["size"]
        and current["version_id"] == new["version_id"]
    )
    if not kept:
        raise AssertionError(
            f"{path_name} delete with stale {condition_name} must return 412 "
            f"and keep the overwritten object. response={out!r} "
            f"current={current} delete_markers={len(markers)} "
            f"expected_etag={new['etag']} expected_size={new['size']}. "
            "Critical failure is 204 with the new data gone. ETag and size "
            "are checked in memory and are not tied to the RADOS delete; on "
            "a versioned bucket that check is also not tied to the "
            "delete-marker write. Unversioned mtime is rechecked in the "
            "RADOS operation; the versioned path does not recheck it."
        )


def _exercise_stale_delete(
    cli_aws,
    bucket_name,
    object_name,
    endpoint,
    ceph_major,
    path_name,
    send_etag,
    send_size,
    send_mtime,
):
    condition_name = "+".join(
        name
        for name, enabled in (
            ("etag", send_etag),
            ("size", send_size),
            ("mtime", send_mtime),
        )
        if enabled
    )
    _put_sized_object(cli_aws, bucket_name, object_name, endpoint, 1024)
    old, markers = _object_attrs(
        cli_aws, bucket_name, object_name, endpoint, ceph_major
    )
    if old is None or markers:
        raise AssertionError(f"{object_name} missing after the initial put")
    log.info(
        "%s read %s ETag=%s size=%s mtime=%s before overwrite",
        path_name,
        object_name,
        old["etag"],
        old["size"],
        old["lmt"],
    )
    new = _overwrite_until_changed(
        cli_aws,
        bucket_name,
        object_name,
        endpoint,
        ceph_major,
        old,
        2048,
    )
    log.info(
        "%s overwrite %s ETag=%s size=%s mtime=%s; delete immediately with stale %s",
        path_name,
        object_name,
        new["etag"],
        new["size"],
        new["lmt"],
        condition_name,
    )
    _assert_stale_delete_keeps_object(
        cli_aws,
        bucket_name,
        object_name,
        endpoint,
        ceph_major,
        old,
        new,
        path_name,
        condition_name,
        send_etag,
        send_size,
        send_mtime,
    )


def _purge_object(cli_aws, bucket_name, object_name, endpoint):
    version_list = _load_object_versions(cli_aws, bucket_name, endpoint)
    version_ids = []
    for entry in _versions_for(version_list, object_name) + _delete_markers_for(
        version_list, object_name
    ):
        version_id = entry.get("VersionId")
        if version_id and version_id != "null":
            version_ids.append(version_id)
    if version_ids:
        for version_id in version_ids:
            aws_reusable.delete_object(
                cli_aws, bucket_name, object_name, endpoint, versionid=version_id
            )
        return
    if _versions_for(version_list, object_name):
        aws_reusable.delete_object(cli_aws, bucket_name, object_name, endpoint)


def _test_stale_conditional_delete(
    cli_aws, bucket_name, seeded_object, endpoint, ceph_major
):
    """
    Read ETag, size, and mtime, overwrite the object, then conditional-delete
    with the values from before the overwrite.

    The delete is sent as soon as the overwrite returns. 204 means the new
    object was removed. ETag and size are an in-memory check on both the
    unversioned delete and the versioned delete-marker write. The mtime-only
    repeat expects the same 412: unversioned rechecks mtime in RADOS, and the
    versioned path does not.
    """
    cases = (
        ("stale-etag-size", True, True, False),
        ("stale-all", True, True, True),
        ("stale-mtime", False, False, True),
    )
    for key, send_etag, send_size, send_mtime in cases:
        _exercise_stale_delete(
            cli_aws,
            bucket_name,
            key,
            endpoint,
            ceph_major,
            "unversioned",
            send_etag,
            send_size,
            send_mtime,
        )
    for key, _, _, _ in cases:
        _purge_object(cli_aws, bucket_name, key, endpoint)
    _purge_object(cli_aws, bucket_name, seeded_object, endpoint)

    log.info("enable versioning for stale delete-marker checks")
    aws_reusable.put_get_bucket_versioning(cli_aws, bucket_name, endpoint)
    for key, send_etag, send_size, send_mtime in cases:
        _exercise_stale_delete(
            cli_aws,
            bucket_name,
            key + "-ver",
            endpoint,
            ceph_major,
            "versioned",
            send_etag,
            send_size,
            send_mtime,
        )
    for key, _, _, _ in cases:
        _purge_object(cli_aws, bucket_name, key + "-ver", endpoint)


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    user_name = (config.test_ops.get("user_name"), None)
    user_names = [user_name] if type(user_name) != list else user_name

    endpoint = aws_reusable.get_endpoint(
        ssh_con, ssl=config.ssl, haproxy=config.haproxy
    )

    ceph_version_id, _ = utils.get_ceph_version()
    ceph_version_id = ceph_version_id.split("-")
    ceph_version_id = ceph_version_id[0].split(".")

    if config.test_ops.get("user_name", False):
        op = json.loads(utils.exec_shell_cmd("radosgw-admin user list"))
        log.info(f"user {config.test_ops['user_name']} exist in cluster {op}")
        if config.test_ops["user_name"] not in op:
            log.info(f"number of user to create is {config.user_count}")
            user_info = resource_op.create_users(
                no_of_users_to_create=config.user_count,
                user_names=user_names,
            )
        elif config.user_count == 1:
            out = json.loads(
                utils.exec_shell_cmd(
                    f"radosgw-admin user info --uid={config.test_ops['user_name']}"
                )
            )
            user_info = [
                {
                    "user_id": out["user_id"],
                    "display_name": out["display_name"],
                    "access_key": out["keys"][0]["access_key"],
                    "secret_key": out["keys"][0]["secret_key"],
                }
            ]
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)
        incorrect = False
        gc_verify = True

        for bc in range(config.bucket_count):
            if config.test_ops.get("regular_and_version", False):
                bkt_suffix = bc + 1
                reg_bucket_name = config.test_ops["reg_bucket_name"] + f"{bkt_suffix}"
                ver_bucket_name = config.test_ops["ver_bucket_name"] + f"{bkt_suffix}"
                aws_reusable.create_bucket(cli_aws, reg_bucket_name, endpoint)
                aws_reusable.create_bucket(cli_aws, ver_bucket_name, endpoint)
                log.info(f"Bucket {reg_bucket_name} and {ver_bucket_name} created")
                log.info(f"bucket versioning enabled on bucket: {ver_bucket_name}")
                aws_reusable.put_get_bucket_versioning(
                    cli_aws, ver_bucket_name, endpoint
                )

            else:
                if config.test_ops.get("bucket_name", False):
                    bkt_suffix = bc + 1
                    bucket_name = config.test_ops["bucket_name"] + f"{bkt_suffix}"
                else:
                    bucket_name = utils.gen_bucket_name_from_userid(
                        user_name, rand_no=bc
                    )
                aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
                log.info(f"Bucket {bucket_name} created")

                if config.test_ops.get("enable_version", False):
                    log.info(f"bucket versioning test on bucket: {bucket_name}")
                    aws_reusable.put_get_bucket_versioning(
                        cli_aws, bucket_name, endpoint
                    )
                object_name = "testobj"
                utils.exec_shell_cmd(f"fallocate -l 6M {object_name}")
                aws_reusable.put_object(cli_aws, bucket_name, object_name, endpoint)
            if config.test_ops.get("conditional_put_if_none_match", False):
                if config.test_ops.get("enable_version", False):
                    gc_verify = False
                log.info("Validate conditional Put operations with if-none-match")
                object_name = "testobj-new"
                utils.exec_shell_cmd(f"fallocate -l 6M {object_name}")
                log.info("Validate conditional put with if-none-match * for 1st upload")
                aws_reusable.conditional_put_object(
                    cli_aws, bucket_name, object_name, endpoint
                )
                log.info("Validate conditional put with if-none-match * for 2nd upload")
                err = aws_reusable.conditional_put_object(
                    cli_aws, bucket_name, object_name, endpoint, return_err=True
                )
                if (
                    "argument of type 'NoneType' is not a container or iterable"
                    not in err
                ):
                    raise AssertionError(f"2nd time upload of same object should fail!")
            if config.test_ops.get("conditional_put_if_match", False):
                if config.test_ops.get("enable_version", False):
                    gc_verify = False
                log.info("Validate conditional Put operations with if-match")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = version_list["Versions"][0]["ETag"].split('"')[1]
                incorrect_etag = etag[:-1]
                log.info("Validate conditional put with if-match with incorret etag")
                err = aws_reusable.conditional_put_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    etag=incorrect_etag,
                    return_err=True,
                )
                if (
                    "argument of type 'NoneType' is not a container or iterable"
                    not in err
                ):
                    raise AssertionError(
                        f"conditional put with if-match with incorret etag should fail"
                    )
                log.info("Validate conditional put with if-match with correct Etag")
                aws_reusable.conditional_put_object(
                    cli_aws, bucket_name, object_name, endpoint, etag=etag
                )

            if config.test_ops.get("conditional_put_multipart_if_none_match", False):
                if config.test_ops.get("enable_version", False):
                    gc_verify = False
                log.info("Validate conditional Put (multipart) with if-none-match")
                multipart_key = "testobj-mp"
                if not hasattr(config, "obj_size") or config.obj_size is None:
                    config.obj_size = 15 * 1024 * 1024
                if not hasattr(config, "split_size") or config.split_size is None:
                    config.split_size = 5
                if not hasattr(config, "local_file_delete"):
                    config.local_file_delete = True
                log.info(
                    "Validate conditional put multipart with if-none-match * for 1st upload"
                )
                aws_reusable.conditional_put_multipart_upload(
                    cli_aws,
                    bucket_name,
                    multipart_key,
                    TEST_DATA_PATH,
                    endpoint,
                    config,
                )
                log.info(
                    "Validate conditional put multipart with if-none-match * for 2nd upload"
                )
                err = aws_reusable.conditional_put_multipart_upload(
                    cli_aws,
                    bucket_name,
                    multipart_key,
                    TEST_DATA_PATH,
                    endpoint,
                    config,
                    return_err=True,
                )
                if isinstance(err, dict) or not err:
                    raise AssertionError(
                        "2nd multipart upload of same object with if-none-match should fail!"
                    )

            if config.test_ops.get("conditional_put_multipart_if_match", False):
                if config.test_ops.get("enable_version", False):
                    gc_verify = False
                log.info("Validate conditional Put (multipart) with if-match")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = version_list["Versions"][0]["ETag"].split('"')[1]
                incorrect_etag = etag[:-1]
                if not hasattr(config, "obj_size") or config.obj_size is None:
                    config.obj_size = 15 * 1024 * 1024
                if not hasattr(config, "split_size") or config.split_size is None:
                    config.split_size = 5
                if not hasattr(config, "local_file_delete"):
                    config.local_file_delete = True
                log.info(
                    "Validate conditional put multipart with if-match with incorrect etag"
                )
                err = aws_reusable.conditional_put_multipart_upload(
                    cli_aws,
                    bucket_name,
                    object_name,
                    TEST_DATA_PATH,
                    endpoint,
                    config,
                    etag=incorrect_etag,
                    return_err=True,
                )
                if isinstance(err, dict) or not err:
                    raise AssertionError(
                        "conditional put multipart with if-match and incorrect etag should fail"
                    )
                log.info(
                    "Validate conditional put multipart with if-match with correct Etag"
                )
                aws_reusable.conditional_put_multipart_upload(
                    cli_aws,
                    bucket_name,
                    object_name,
                    TEST_DATA_PATH,
                    endpoint,
                    config,
                    etag=etag,
                )

            if config.test_ops.get("conditional_delete_with_etag", False):
                log.info("delete object using matching ETAG")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = version_list["Versions"][0]["ETag"].split('"')[1]
                log.info("Conditional delete object with incorrect Etag")
                incorrect_etag = etag[:-1]
                out = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    etag=incorrect_etag,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {out}")
                if not out:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect ETag"
                    )

                log.info("Conditional delete object with correct Etag")
                out = aws_reusable.conditional_delete_object(
                    cli_aws, bucket_name, object_name, endpoint, etag=etag
                )
                log.info(f"Conditional delete response is {out}")
            if config.test_ops.get("conditional_delete_with_lastmodifiedtime", False):
                log.info("delete object using matching Last Modified time")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                lmt = version_list["Versions"][0]["LastModified"].split(".")[0]
                if float(ceph_version_id[0]) >= 20:
                    lmt = version_list["Versions"][0]["LastModified"].split("+")[0]
                log.info("Conditional delete object with incorrect Last modified time")
                incorrect_lmt = lmt[:-1]
                out = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    last_modified_time=incorrect_lmt,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {out}")
                if not out:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect Last modified time"
                    )

                log.info("Conditional delete object with correct Last modified time")
                out = aws_reusable.conditional_delete_object(
                    cli_aws, bucket_name, object_name, endpoint, last_modified_time=lmt
                )
                log.info(f"Conditional delete response is {out}")
            if config.test_ops.get("conditional_delete_with_size", False):
                log.info("delete object using matching size")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                size = version_list["Versions"][0]["Size"]
                log.info("Conditional delete object with incorrect Size")
                incorrect_size = str(size)[:-1]
                out = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    size=incorrect_size,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {out}")
                if not out:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect size"
                    )

                log.info("Conditional delete object with correct size")
                out = aws_reusable.conditional_delete_object(
                    cli_aws, bucket_name, object_name, endpoint, size=size
                )
                log.info(f"Conditional delete response is {out}")
            if config.test_ops.get("conditional_delete_with_multi_condition", False):
                log.info("delete object using combination of conditions")
                version_list = json.loads(
                    aws_reusable.list_object_versions(cli_aws, bucket_name, endpoint)
                )
                etag = None
                lmt = None
                size = None
                if config.test_ops.get("size", False):
                    size = version_list["Versions"][0]["Size"]
                    if config.test_ops.get("size")[1] == "correct":
                        size = size
                    else:
                        incorrect = True
                        size = str(size)[:-1]
                if config.test_ops.get("etag", False):
                    etag = version_list["Versions"][0]["ETag"].split('"')[1]
                    if config.test_ops.get("etag")[1] == "correct":
                        etag = etag
                    else:
                        incorrect = True
                        etag = etag[:-1]
                if config.test_ops.get("last_modified_time", False):
                    lmt = version_list["Versions"][0]["LastModified"].split(".")[0]
                    if float(ceph_version_id[0]) >= 20:
                        lmt = version_list["Versions"][0]["LastModified"].split("+")[0]
                    if config.test_ops.get("last_modified_time")[1] == "correct":
                        lmt = lmt
                    else:
                        incorrect = True
                        lmt = lmt[:-1]

                err = aws_reusable.conditional_delete_object(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    etag=etag,
                    last_modified_time=lmt,
                    size=size,
                    return_err=True,
                )
                log.info(f"Conditional delete response is {err}")
                if not err and incorrect:
                    raise AssertionError(
                        f"Conditional delete failed! object removed with incorrect conditions"
                    )
            if config.test_ops.get("conditional_delete_etag_prefix", False):
                log.info(
                    "If-Match prefix (etag+EXTRA) must return 412 on unversioned, "
                    "current-version, and versionId deletes"
                )
                _test_etag_prefix_if_match(
                    cli_aws, bucket_name, object_name, endpoint
                )
            if config.test_ops.get("conditional_delete_stale_attrs", False):
                log.info(
                    "Stale ETag, size, and mtime must not delete an object "
                    "overwritten before the conditional delete"
                )
                _test_stale_conditional_delete(
                    cli_aws,
                    bucket_name,
                    object_name,
                    endpoint,
                    float(ceph_version_id[0]),
                )
            if not incorrect and gc_verify:
                aws_reusable.validate_gc()
        if config.user_remove is True:
            s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("Test Conditional Put and Delete using AWS")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Conditional Put and Delete using AWS"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW Conditional Put and Delete using using AWS"
        )
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
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = resource_op.Config(yaml_file)
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
