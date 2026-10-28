# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
IBMCEPH-19411 / 19412 / 19413 / 19417: operations that lose a race on the head
of a key must not leak RADOS objects and must not delete a newer write.

Sources: apple-ms/IBMCEPH-<id>/repro_<id>.py.  Lab only: needs two RGWs, the
orchestrator, ssh to the RGW-A host and gdb there.

gdb stands in for the injection points of the upstream Jiras
(write_meta_before_head_write, delete_obj_before_head_delete).  It stops RGW-A
at a function inside the operation, the test lets a PutObject through RGW-B win
the race, then releases RGW-A.

  19411  CompleteMultipartUpload that loses the head race leaks its parts
         (tracker 80897).  Hold: RGWRados::Object::prepare_atomic_modification,
         first hit ignored (the first _do_write_meta call is assume_noent and
         fails with -EEXIST for an existing key; the retry reads the state).
  19412  DeleteObject racing an overwrite leaks the new object's tail
         (tracker 80898).  Hold: RGWRados::Bucket::UpdateIndex::prepare.
  19413  CopyObject that loses the head race leaks the source's tail
         (tracker 80899).  Hold: prepare_atomic_modification, first hit ignored.
  19417  Conditional DeleteObject deletes an object that fails its If-Match
         (tracker 80898).  Hold: RGWRados::Bucket::UpdateIndex::prepare.

Each test has a control (no competing write) that must pass on every build.

PASSED  - fixed behaviour: no leftover RADOS objects / the newer write survives.
FAILED  - the bug: leaked objects remain / the newer write was deleted.
SKIPPED - the hold was not reached or the end state is not one of the two
          expected ones (inconclusive, run again).
"""

import logging

import pytest
from ibmceph_lib import code_of, hold_script, inconclusive, status_of

log = logging.getLogger(__name__)

PREPARE_INDEX = "RGWRados::Bucket::UpdateIndex::prepare"
PREPARE_ATOMIC = "RGWRados::Object::prepare_atomic_modification"
RACE_CONTROL = [
    pytest.param(False, id="race"),
    pytest.param(True, id="control", marks=pytest.mark.ibmceph_control),
]


@pytest.fixture
def gc_fast(lab):
    """rgw_gc_obj_min_wait is lowered for the test and removed afterwards."""
    with lab.configs(lab.gc_config()):
        yield lab


def head_status(client, bucket, key):
    try:
        etag = client.head_object(Bucket=bucket, Key=key)["ETag"]
        return 200, etag
    except Exception as e:
        return code_of(e), None


def objects_of(env, marker, before):
    """RADOS objects of the bucket that are not in `before`."""
    return [o for o in env.bucket_objs(marker) if o not in before]


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
@pytest.mark.parametrize("control", RACE_CONTROL)
def test_19411_complete_losing_head_race_leaks_parts(gc_fast, control):
    """A completion that loses the head race must send its parts to GC."""
    env = gc_fast
    a, b = env.a(), env.b()
    key = "obj"
    with env.bucket(b, "ibmceph19411") as (bucket, marker):
        b.put_object(Bucket=bucket, Key=key, Body=b"V0-original" * 1000)
        up, parts = env.upload_parts(b, bucket, key, n=2)
        part_objs = [o for o in env.bucket_objs(marker) if up in o]
        log.info("upload %s: %d part RADOS objects: %s", up, len(part_objs), part_objs)

        script = hold_script(
            env.go_file("19411"),
            PREPARE_ATOMIC,
            "head write about to be prepared (state already read)",
            ignore=1,
        )
        held = env.hold_request(
            "19411", script, lambda: env.complete(a, bucket, key, up, parts)
        )
        if not control:
            r = b.put_object(Bucket=bucket, Key=key, Body=b"V1-winner-put" * 1000)
            log.info("PutObject via RGW-B (winner) -> %s", r["ETag"])
        a_status = env.finish(held)
        log.info("CompleteMultipartUpload via RGW-A -> %s", a_status)

        h = b.head_object(Bucket=bucket, Key=key)
        log.info("HEAD after race: size %s etag %s", h["ContentLength"], h["ETag"])
        log.info(
            "open uploads: %d",
            len(b.list_multipart_uploads(Bucket=bucket).get("Uploads", [])),
        )

        b.delete_object(Bucket=bucket, Key=key)
        left = env.gc_and_list(marker)
        log.info(
            "after DeleteObject + gc process: %d objects left: %s", len(left), left
        )
        if control:
            assert a_status == 200 and not left, f"control: A {a_status}, left {left}"
        elif a_status == 200 and any(up in o for o in left):
            pytest.fail(
                "BUG IBMCEPH-19411: the completion answered 200 after losing the "
                f"head race and its part objects leaked: {left}"
            )


@pytest.mark.ibmceph_race
@pytest.mark.ibmceph_all
@pytest.mark.parametrize("control", RACE_CONTROL)
def test_19412_delete_racing_overwrite_leaks_tail(gc_fast, control):
    """A DeleteObject racing an overwrite must not leak the new object's tail."""
    env = gc_fast
    a, b = env.a(), env.b()
    key = "obj"
    with env.bucket(b, "ibmceph19412") as (bucket, marker):
        b.put_object(Bucket=bucket, Key=key, Body=b"0" * env.obj_size)
        v0 = env.bucket_objs(marker)
        log.info("V0 RADOS objects: %s", env.short(v0, marker))

        script = hold_script(
            env.go_file("19412"),
            PREPARE_INDEX,
            "delete read the head state, about to prepare the index op",
        )
        held = env.hold_request(
            "19412",
            script,
            lambda: status_of(lambda: a.delete_object(Bucket=bucket, Key=key)),
        )
        v1 = []
        if not control:
            r1 = b.put_object(Bucket=bucket, Key=key, Body=b"1" * env.obj_size)
            v1 = [o for o in objects_of(env, marker, v0) if not o.endswith("_" + key)]
            log.info(
                "PutObject V1 via RGW-B (winner) -> %s, tail %s",
                r1["ETag"],
                env.short(v1, marker),
            )
        del_status = env.finish(held)
        hs, _etag = head_status(b, bucket, key)
        listed = [
            o["Key"] for o in b.list_objects_v2(Bucket=bucket).get("Contents", [])
        ]
        log.info(
            "DeleteObject via RGW-A -> %s; HEAD %s; listing %s", del_status, hs, listed
        )

        if hs == 200 and not control:
            log.info(
                "key survived the race: deleting it, then GC (as the workunit does)"
            )
            b.delete_object(Bucket=bucket, Key=key)
        left = env.gc_and_list(marker)
        log.info(
            "after gc process --include-all: %d objects left: %s",
            len(left),
            env.short(left, marker),
        )

        if control:
            assert (
                del_status in (200, 204) and not left
            ), f"control: {del_status}, left {left}"
        elif left and set(left) <= set(v1) and hs == 404:
            pytest.fail(
                "BUG IBMCEPH-19412: the key is gone but the new object's tail "
                f"leaked: {env.short(left, marker)}"
            )
        elif left:
            inconclusive(f"unexpected leftovers {env.short(left, marker)}, HEAD {hs}")


@pytest.mark.ibmceph_race
@pytest.mark.ibmceph_all
@pytest.mark.parametrize("control", RACE_CONTROL)
def test_19413_copy_losing_head_race_leaks_source_tail(gc_fast, control):
    """A CopyObject that loses the head race must drop its tail references."""
    env = gc_fast
    a, b = env.a(), env.b()
    src, dst = "src", "dst"
    with env.bucket(b, "ibmceph19413") as (bucket, marker):
        b.put_object(Bucket=bucket, Key=src, Body=b"S" * env.obj_size)
        s_objs = env.bucket_objs(marker)
        s_tail = [o for o in s_objs if not o.endswith("_" + src)]
        b.put_object(Bucket=bucket, Key=dst, Body=b"D" * env.obj_size)
        log.info(
            "source objects %s, tail %s",
            env.short(s_objs, marker),
            env.short(s_tail, marker),
        )

        script = hold_script(
            env.go_file("19413"),
            PREPARE_ATOMIC,
            "copy took its tail references, head write about to be prepared",
            ignore=1,
        )
        held = env.hold_request(
            "19413",
            script,
            lambda: status_of(
                lambda: a.copy_object(
                    Bucket=bucket, Key=dst, CopySource={"Bucket": bucket, "Key": src}
                )
            ),
        )
        if not control:
            r1 = b.put_object(Bucket=bucket, Key=dst, Body=b"1" * env.obj_size)
            log.info(
                "PutObject over the destination via RGW-B (winner) -> %s", r1["ETag"]
            )
        copy_status = env.finish(held)
        h = b.head_object(Bucket=bucket, Key=dst)
        log.info(
            "CopyObject via RGW-A -> %s; destination size %s etag %s",
            copy_status,
            h["ContentLength"],
            h["ETag"],
        )

        for k in (src, dst):
            b.delete_object(Bucket=bucket, Key=k)
        left = env.gc_and_list(marker)
        log.info(
            "after gc process --include-all: %d objects left: %s",
            len(left),
            env.short(left, marker),
        )

        if control:
            assert (
                copy_status == 200 and not left
            ), f"control: {copy_status}, left {left}"
        elif left and set(left) <= set(s_tail):
            pytest.fail(
                "BUG IBMCEPH-19413: the source's tail is kept by the reference "
                f"the lost copy leaked: {env.short(left, marker)}"
            )
        elif left:
            inconclusive(f"unexpected leftovers {env.short(left, marker)}")


@pytest.mark.ibmceph_cond
@pytest.mark.ibmceph_all
@pytest.mark.parametrize("control", RACE_CONTROL)
def test_19417_conditional_delete_loses_id_tag_guard(gc_fast, control):
    """A DeleteObject whose If-Match fails against the current object must not delete it."""
    env = gc_fast
    a, b = env.a(), env.b()
    key = "obj"
    with env.bucket(b, "ibmceph19417") as (bucket, marker):
        etag0 = b.put_object(Bucket=bucket, Key=key, Body=b"0" * env.obj_size)["ETag"]
        log.info("V0 etag %s", etag0)

        if control:
            etag1 = b.put_object(Bucket=bucket, Key=key, Body=b"1" * env.obj_size)[
                "ETag"
            ]
            del_status = status_of(
                lambda: a.delete_object(Bucket=bucket, Key=key, IfMatch=etag0)
            )
            log.info(
                "control: V1 written first (%s); DeleteObject If-Match V0 -> %s",
                etag1,
                del_status,
            )
        else:
            script = hold_script(
                env.go_file("19417"),
                PREPARE_INDEX,
                "delete passed its If-Match check, about to prepare the index op",
            )
            held = env.hold_request(
                "19417",
                script,
                lambda: status_of(
                    lambda: a.delete_object(Bucket=bucket, Key=key, IfMatch=etag0)
                ),
            )
            etag1 = b.put_object(Bucket=bucket, Key=key, Body=b"1" * env.obj_size)[
                "ETag"
            ]
            log.info(
                "PutObject V1 via RGW-B -> %s (differs from If-Match: %s)",
                etag1,
                etag1 != etag0,
            )
            del_status = env.finish(held)
            log.info("DeleteObject If-Match %s via RGW-A -> %s", etag0, del_status)

        hs, he = head_status(b, bucket, key)
        log.info("after: HEAD %s etag %s", hs, he)
        if control:
            assert (
                del_status == 412 and hs == 200 and he == etag1
            ), f"control: expected 412 with V1 kept, got {del_status}, HEAD {hs}"
        elif del_status in (200, 204) and hs == 404:
            pytest.fail(
                "BUG IBMCEPH-19417: an object whose ETag does not match If-Match "
                "was deleted; DeleteObject answered " + str(del_status)
            )
        elif not (hs == 200 and he == etag1):
            inconclusive(
                f"V1 neither survived nor was deleted: HEAD {hs}, delete {del_status}"
            )
