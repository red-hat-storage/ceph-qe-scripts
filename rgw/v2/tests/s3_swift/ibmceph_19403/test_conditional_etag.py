# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
IBMCEPH-19423 (upstream tracker 80924): If-Match and If-None-Match match any
value that starts with the object's ETag.

Source of the checks: apple-ms/IBMCEPH-19423/repro_19423.py.

The RGW compares only the first etag.length() characters of the header value in
four places (RGWRados::Object::check_preconditions for PUT and DELETE,
RGWRados::Object::Read::prepare for GET, HEAD and the copy source).  RFC 7232
says the header is a list of entity-tags, each compared whole.

No race, no gdb, no configuration change: plain requests against RGW-B.
E is the object's ETag, "E-x" is E followed by a suffix inside the quotes.

PASSED  - every request got the status RFC 7232 requires.
FAILED  - at least one request got the buggy status (named in the message).
"""

import logging

import pytest
from ibmceph_lib import status_of

log = logging.getLogger(__name__)

BODY = b"ibmceph-19423" * 100
KEY = "obj"


class Ctx:
    """The bucket, the object and the header values the cases use."""

    def __init__(self, client, bucket, etag):
        self.c = client
        self.bkt = bucket
        self.etag = etag  # quoted, as returned by PutObject
        bare = etag.strip('"')
        self.suffixed = f'"{bare}-x"'
        self.other = '"00000000000000000000000000000000"'
        self.in_list = f"{self.other}, {etag}"  # the real ETag is the second entry


def _put(x, **kw):
    return x.c.put_object(Bucket=x.bkt, Key=KEY, Body=BODY, **kw)


def _get(x, **kw):
    return x.c.get_object(Bucket=x.bkt, Key=KEY, **kw)


def _head(x, **kw):
    return x.c.head_object(Bucket=x.bkt, Key=KEY, **kw)


def _copy(x, dest, **kw):
    return x.c.copy_object(
        Bucket=x.bkt, Key=dest, CopySource={"Bucket": x.bkt, "Key": KEY}, **kw
    )


# (id, request, expected status, status the bug gives or None for a control)
CASES = [
    ("put_ifmatch_exact", lambda x: _put(x, IfMatch=x.etag), 200, None),
    ("put_ifmatch_suffix", lambda x: _put(x, IfMatch=x.suffixed), 412, 200),
    ("put_ifnonematch_exact", lambda x: _put(x, IfNoneMatch=x.etag), 412, None),
    ("put_ifnonematch_suffix", lambda x: _put(x, IfNoneMatch=x.suffixed), 200, 412),
    ("get_ifmatch_exact", lambda x: _get(x, IfMatch=x.etag), 200, None),
    ("get_ifmatch_suffix", lambda x: _get(x, IfMatch=x.suffixed), 412, 200),
    ("get_ifnonematch_exact", lambda x: _get(x, IfNoneMatch=x.etag), 304, None),
    ("get_ifnonematch_suffix", lambda x: _get(x, IfNoneMatch=x.suffixed), 200, 304),
    ("head_ifmatch_suffix", lambda x: _head(x, IfMatch=x.suffixed), 412, 200),
    ("head_ifnonematch_suffix", lambda x: _head(x, IfNoneMatch=x.suffixed), 200, 304),
    (
        "copy_src_ifmatch_suffix",
        lambda x: _copy(x, "copy1", CopySourceIfMatch=x.suffixed),
        412,
        200,
    ),
    (
        "copy_src_ifnonematch_suffix",
        lambda x: _copy(x, "copy2", CopySourceIfNoneMatch=x.suffixed),
        200,
        304,
    ),
    ("get_ifmatch_list_second", lambda x: _get(x, IfMatch=x.in_list), 200, 412),
    ("get_ifnonematch_list_second", lambda x: _get(x, IfNoneMatch=x.in_list), 304, 200),
]


@pytest.fixture(scope="module")
def ctx(env):
    client = env.b()
    with env.bucket(client, "ibmceph19423") as (bucket, _marker):
        etag = client.put_object(Bucket=bucket, Key=KEY, Body=BODY)["ETag"]
        log.info("bucket %s, object %s, ETag %s", bucket, KEY, etag)
        yield Ctx(client, bucket, etag)


@pytest.mark.ibmceph_cond
@pytest.mark.ibmceph_all
@pytest.mark.parametrize("name,request_fn,expect,bug", CASES, ids=[c[0] for c in CASES])
def test_19423_etag_comparison(ctx, name, request_fn, expect, bug):
    """If-Match / If-None-Match compare whole entity-tags (RFC 7232)."""
    got = status_of(lambda: request_fn(ctx))
    log.info("%-30s expected %s got %s", name, expect, got)
    if got == expect:
        return
    if bug is not None and got == bug:
        pytest.fail(f"BUG IBMCEPH-19423: {name} answered {got}, expected {expect}")
    pytest.fail(f"UNEXPECTED {name}: expected {expect}, got {got}")


@pytest.mark.ibmceph_cond
@pytest.mark.ibmceph_all
def test_19423_delete_ifmatch_suffix(env):
    """DeleteObject with If-Match "E-x" must be refused and the object must stay."""
    client = env.b()
    with env.bucket(client, "ibmceph19423d") as (bucket, _marker):
        x = Ctx(
            client, bucket, client.put_object(Bucket=bucket, Key=KEY, Body=BODY)["ETag"]
        )
        got = status_of(
            lambda: client.delete_object(Bucket=bucket, Key=KEY, IfMatch=x.suffixed)
        )
        still = status_of(lambda: client.head_object(Bucket=bucket, Key=KEY)) == 200
        log.info(
            "delete If-Match %s -> %s, object still exists: %s", x.suffixed, got, still
        )
        assert not (got in (200, 204) and not still), (
            "BUG IBMCEPH-19423: DeleteObject with a non-matching If-Match "
            f"(ETag plus suffix) answered {got} and deleted the object"
        )
        assert (
            got == 412 and still
        ), f"expected 412 and the object to stay: {got}, {still}"
