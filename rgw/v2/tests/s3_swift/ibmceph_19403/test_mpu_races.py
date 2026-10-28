# -*- mode:Python; tab-width:4; indent-tabs-mode:nil -*-
"""
IBMCEPH-19405 / 19406 / 19407 / 19410 and the customer "check-then-commit gap":
multipart completion races that end as HEAD 200 / GET 404 (a ghost object).

Sources: apple-ms/IBMCEPH-<id>/repro_<id>.py and
apple-ms/IBMCEPH-19403-customer-gap/repro_19403_gap.py.  Lab only: two RGWs, the
orchestrator, ssh to the RGW-A host (gdb and podman there).

  19405  the multipart lock lapses AFTER the head is written (injected lock
         renewal errors + OSD reply delay on RGW-A); a retry on RGW-B
         re-completes and queues the shared tails to GC.
  19406  RGW-A is SIGKILLed right after the head becomes visible, before the
         .meta delete; after the lock lapses a retry on RGW-B re-completes.
  19407  meta_obj->delete_object() fails with -EIO (forced with gdb) after the
         head was written; the .meta survives and an immediate retry on RGW-B
         re-completes.
  19410  the lifecycle AbortIncompleteMultipartUpload path aborts an upload
         whose completion holds the completion lock (held with gdb).
  gap    two completions of one upload on two RGWs 33 s apart with every lock
         renewal failing and a 30 s lock TTL (customer case TS023088611).

PASSED  - after GC the object is readable: HEAD 200 and GET 200 with all bytes.
FAILED  - ghost object: HEAD 200 but GET not 200 (data loss).
SKIPPED - the trigger window was not reached (inconclusive, run again).
"""

import logging
import threading
import time

import pytest
from ibmceph_lib import code_of, hold_script, inconclusive, inject_script, status_of

log = logging.getLogger(__name__)

LC_DEBUG_INTERVAL = 10  # seconds that count as one lifecycle "day"
INJECT_KEYS = (
    "ms_inject_delay_type",
    "ms_inject_delay_max",
    "ms_inject_delay_probability",
)


def run_in_thread(fn, out, name):
    """Run fn() in a thread storing its result in out[name]."""

    def target():
        out[name] = fn()

    th = threading.Thread(target=target)
    th.start()
    return th


def final_state(env, client, bucket, key, marker=None):
    """GC everything, then (HEAD status, size, GET status, bytes read)."""
    time.sleep(env.gc_min_wait + 5)
    env.sh("radosgw-admin gc process --include-all")
    time.sleep(5)
    state = env.head_get(client, bucket, key)
    log.info("HEAD %s (size %s)  GET %s (read %s)", *state)
    return state


def assert_not_ghost(state, jira, what):
    hs, _hsize, gs, _got = state
    assert gs == 200, (
        f"BUG {jira}: {what}; HEAD {hs} but GET {gs} - the object is a ghost "
        "(its tail objects were garbage collected)"
    )


def delay_config(env, delay_max):
    a = env.a_daemon
    return [
        (a, "ms_inject_delay_type", "osd"),
        (a, "ms_inject_delay_max", delay_max),
        (a, "ms_inject_delay_probability", 1.0),
    ]


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19405_lock_lapses_after_head_write(lab):
    """The multipart lock lapsing after the head write must not lose the object."""
    env = lab
    a, b = env.a(), env.b()
    key = "obj-mpu"
    delay_max, init_timeout = 20, 1200
    items = (
        env.lock_config()
        + env.gc_config()
        + delay_config(env, delay_max)
        + [
            (env.a_daemon, "rgw_mp_lock_inject_renewal_error", -5),
            (env.a_daemon, "rgw_init_timeout", init_timeout),
        ]
    )
    with env.configs(items, restart=("a",), timeout=init_timeout):
        with env.bucket(b, "ibmceph19405") as (bucket, _marker):
            up, parts = env.upload_parts(b, bucket, key, n=5, size=8 * 1024 * 1024)
            res = {}
            t0 = time.time()
            th = run_in_thread(
                lambda: env.complete(a, bucket, key, up, parts), res, "a"
            )
            visible = env.wait_head(b, bucket, key, timeout=240)
            head_after = time.time() - t0
            running = th.is_alive()
            log.info(
                "head visible %s after %.1fs; RGW-A still running %s",
                visible,
                head_after,
                running,
            )
            # the renewal tick is lock_max_time/2: before it the error cannot have fired
            window = visible and running and head_after > env.lock_max_time / 2

            dropped = env.drop_meta_lock(up)
            log.info("lock dropped: %s; GC entries %s", dropped, env.gc_count())
            b_status = env.complete(b, bucket, key, up, parts)
            th.join(timeout=300)
            fired = env.injected_error_fired(up)
            log.info(
                "Request B -> %s; Request A -> %s; injected error logged: %s",
                b_status,
                res.get("a"),
                fired,
            )
            state = final_state(env, b, bucket, key)
            if not (window and dropped and fired):
                inconclusive(
                    f"window not reached (head_visible={visible}, A_running={running}, "
                    f"after_tick={head_after > env.lock_max_time / 2}, lock_dropped={dropped}, "
                    f"injected_error_fired={fired})"
                )
            assert_not_ghost(
                state, "IBMCEPH-19405", "a retry re-completed after the lock lapsed"
            )


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
@pytest.mark.parametrize(
    "suspended",
    [
        pytest.param(False, id="plain"),
        pytest.param(True, id="versioning-suspended"),
    ],
)
def test_19406_crash_between_head_write_and_meta_delete(lab, suspended):
    """RGW-A killed after the head write must not lose the object on a later retry."""
    env = lab
    a, b = env.a(), env.b()
    key = "obj-mpu"
    items = env.lock_config() + env.gc_config() + delay_config(env, 3)
    with env.configs(items, restart=("a",)):
        with env.bucket(b, "ibmceph19406") as (bucket, _marker):
            if suspended:
                b.put_bucket_versioning(
                    Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
                )
                b.put_bucket_versioning(
                    Bucket=bucket, VersioningConfiguration={"Status": "Suspended"}
                )
            up, parts = env.upload_parts(b, bucket, key)
            res = {}
            th = run_in_thread(
                lambda: env.complete(a, bucket, key, up, parts), res, "a"
            )
            visible = env.wait_head(b, bucket, key, timeout=240, interval=0.1)
            t_kill = time.time()
            killed = env.kill_rgw_a()
            still = th.is_alive()
            th.join(timeout=60)
            in_window = visible and bool(env.meta_oid(up))
            log.info(
                "head visible %s; A running at kill %s; kill -> %s; A -> %s; .meta left: %s",
                visible,
                still,
                killed,
                res.get("a"),
                in_window,
            )
            env.wait_rgw("a")
            wait = env.lock_max_time + 5 - (time.time() - t_kill)
            if wait > 0:
                log.info("waiting %.0fs for the abandoned lock to lapse", wait)
                time.sleep(wait)
            b_status = env.complete(b, bucket, key, up, parts)
            log.info("retry on RGW-B -> %s; GC entries %s", b_status, env.gc_count())
            state = final_state(env, b, bucket, key)
            if not in_window:
                inconclusive(
                    "RGW-A was not killed between the head write and the .meta delete"
                )
            assert_not_ghost(
                state, "IBMCEPH-19406", "RGW-A crashed after the head write"
            )


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
def test_19407_meta_delete_fails_then_retry(lab):
    """A failed .meta delete after the head write must not allow a retry to lose the object."""
    env = lab
    a, b = env.a(), env.b()
    key = "obj-mpu"
    with env.configs(env.lock_config() + env.gc_config()):
        with env.bucket(b, "ibmceph19407") as (bucket, _marker):
            up, parts = env.upload_parts(b, bucket, key)
            script = inject_script(
                "rgw::sal::RadosObject::delete_object",
                -5,
                "delete_object forced to return -5",
            )
            if not env.arm_gdb("19407", script):
                inconclusive("gdb did not arm on RGW-A")
            a_status = env.complete(a, bucket, key, up, parts)
            time.sleep(2)
            injected = env.gdb_seen("19407", "INJECT:", timeout=10)
            oid = env.meta_oid(up)
            lockers = env.lockers(oid) if oid else None
            log.info(
                "Request A -> %s; failure injected %s; .meta present %s; lockers %s",
                a_status,
                injected,
                bool(oid),
                lockers,
            )
            in_window = injected and bool(oid) and a_status == 200
            # the lock was released: retry immediately, no TTL wait
            b_status = env.complete(b, bucket, key, up, parts)
            log.info("retry on RGW-B -> %s; GC entries %s", b_status, env.gc_count())
            state = final_state(env, b, bucket, key)
            if not in_window:
                inconclusive(
                    "the .meta delete failure was not injected after a 200 completion"
                )
            assert_not_ghost(
                state,
                "IBMCEPH-19407",
                "the .meta delete failed and the upload was completed again",
            )


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
@pytest.mark.parametrize(
    "control",
    [
        pytest.param(False, id="lifecycle"),
        pytest.param(True, id="control", marks=pytest.mark.ibmceph_control),
    ],
)
def test_19410_lifecycle_abort_ignores_completion_lock(lab, control):
    """A lifecycle abort must not abort an upload whose completion holds the lock."""
    env = lab
    a, b = env.a(), env.b()
    key = "obj-mpu"
    with env.configs(env.gc_config()):
        with env.bucket(b, "ibmceph19410") as (bucket, _marker):
            b.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={
                    "Rules": [
                        {
                            "ID": "abort-mpu",
                            "Status": "Enabled",
                            "Filter": {"Prefix": ""},
                            "AbortIncompleteMultipartUpload": {
                                "DaysAfterInitiation": 1
                            },
                        }
                    ]
                },
            )
            up, parts = env.upload_parts(b, bucket, key)
            time.sleep(LC_DEBUG_INTERVAL + 3)  # older than one simulated day
            oid = env.meta_oid(up)
            script = hold_script(
                env.go_file("19410"),
                "RGWRados::Object::Write::write_meta",
                "write_meta reached (lock taken, parts listed)",
                temporary=True,
            )
            held = env.hold_request(
                "19410", script, lambda: env.complete(a, bucket, key, up, parts)
            )
            gc_pre = env.gc_count()
            if control:
                ab = status_of(
                    lambda: b.abort_multipart_upload(
                        Bucket=bucket, Key=key, UploadId=up
                    )
                )
                time.sleep(3)
                still = env.meta_oid(up)
                log.info(
                    "control: S3 AbortMultipartUpload while A holds the lock -> %s; .meta present %s",
                    ab,
                    bool(still),
                )
                in_window = bool(still) and env.gc_count() == gc_pre
            else:
                out = env.sh(
                    f"radosgw-admin lc process --bucket {bucket} "
                    f"--rgw-lc-debug-interval={LC_DEBUG_INTERVAL} 2>&1"
                )
                time.sleep(3)
                still = env.meta_oid(up)
                gc_mid = env.gc_count()
                log.info(
                    "lc process: .meta present %s; GC entries %s -> %s; %s",
                    bool(still),
                    gc_pre,
                    gc_mid,
                    out.strip()[:200].replace("\n", " "),
                )
                in_window = bool(oid)
                bug_seen = (not still) and gc_mid > gc_pre
                declined = bool(still) and gc_mid == gc_pre
            a_status = env.finish(held)
            log.info("Request A (complete) -> %s", a_status)
            state = final_state(env, b, bucket, key)
            if not in_window:
                inconclusive("the lifecycle trigger window was not reached")
            if control:
                assert (
                    a_status == 200 and state[2] == 200
                ), f"control: S3 abort must be refused and data intact: A {a_status}, GET {state[2]}"
            elif bug_seen and a_status == 200 and state[2] != 200:
                pytest.fail(
                    "BUG IBMCEPH-19410: the lifecycle abort ran under the held completion "
                    f"lock; completion answered 200, HEAD {state[0]} but GET {state[2]}"
                )
            elif not (declined and a_status == 200 and state[2] == 200):
                inconclusive(
                    f"lifecycle behaviour not one of the two expected end states "
                    f"(bug_seen={bug_seen}, declined={declined}, A={a_status}, GET={state[2]})"
                )


CUSTOMER_DELAYS = [10, 16, 12, 14, 12, 10, 14, 16, 12, 10]


@pytest.mark.ibmceph_mpu
@pytest.mark.ibmceph_all
@pytest.mark.slow
def test_gap_two_completions_lock_lapses_while_committing(lab):
    """Customer scenario: two completions 33 s apart with failing lock renewals."""
    env = lab
    iterations = int(env.cfg.get("gap_iterations", 10))
    min_valid = int(env.cfg.get("gap_min_valid", 3))
    offset = int(env.cfg.get("gap_offset", 33))
    ttl, gc_wait = 30, 5
    bucket = "ibmceph-mp-race"
    items = [
        ("global", "rgw_max_chunk_size", 16777216),
        ("global", "rgw_obj_stripe_size", 16777216),
        ("global", "rgw_dynamic_resharding", "false"),
        ("global", "rgw_gc_obj_min_wait", gc_wait),
        ("global", "rgw_gc_processor_period", 30),
        ("client.rgw", "rgw_mp_lock_max_time", ttl),
        (env.a_daemon, "ms_inject_delay_type", "osd"),
        (env.b_daemon, "ms_inject_delay_type", "osd"),
    ]
    losses, results = [], []
    with env.configs(items, restart=("a", "b")):
        a, b = env.a(), env.b()
        a.create_bucket(Bucket=bucket)
        try:
            for n in range(iterations):
                delay = CUSTOMER_DELAYS[n % len(CUSTOMER_DELAYS)]
                key = f"gap-{int(time.time())}-{n}"
                env.asok_both("rgw_mp_lock_inject_renewal_error", -5)
                up, parts = env.upload_parts(a, bucket, key, n=8, size=5 * 1024 * 1024)
                before = [
                    o
                    for o in env.sh(
                        f"rados -p {env.data_pool} ls | grep -F -- '{up}'"
                    ).splitlines()
                    if o
                ]
                env.asok_both("ms_inject_delay_max", delay)
                env.asok_both("ms_inject_delay_probability", 1)
                res = {}
                ta = run_in_thread(
                    lambda: env.complete(a, bucket, key, up, parts), res, "A"
                )
                time.sleep(offset)
                tb = run_in_thread(
                    lambda: env.complete(b, bucket, key, up, parts), res, "B"
                )
                ta.join()
                tb.join()
                env.asok_both("ms_inject_delay_probability", 0)
                env.asok_both("rgw_mp_lock_inject_renewal_error", 0)
                time.sleep(8)
                env.sh("radosgw-admin gc process --include-all")
                time.sleep(2)
                env.sh("radosgw-admin gc process --include-all")
                time.sleep(2)
                hs, _size, gs, _got = env.head_get(a, bucket, key)
                left = [
                    o
                    for o in env.sh(
                        f"rados -p {env.data_pool} ls | grep -F -- '{up}'"
                    ).splitlines()
                    if o
                ]
                log.info(
                    "[iter %d] D=%ds A %s B %s HEAD %s GET %s; upload objects left %d of %d",
                    n + 1,
                    delay,
                    res.get("A"),
                    res.get("B"),
                    hs,
                    gs,
                    len(left),
                    len(before),
                )
                if (
                    res.get("A") == 200
                    and res.get("B") == 200
                    and hs == 200
                    and gs != 200
                    and not left
                ):
                    losses.append(key)
                results.append((res.get("A"), res.get("B"), hs, gs))
                status_of(lambda: a.delete_object(Bucket=bucket, Key=key))
                env.purge(left)
        finally:
            env.asok_both("ms_inject_delay_probability", 0)
            env.asok_both("rgw_mp_lock_inject_renewal_error", 0)
            try:
                a.delete_bucket(Bucket=bucket)
            except Exception as e:
                log.warning("bucket cleanup: %s", code_of(e))
    assert not losses, (
        f"BUG IBMCEPH-19403 (check-then-commit gap): {len(losses)} of {iterations} "
        f"iterations ended HEAD 200 / GET not 200 with no object left: {losses}"
    )
    # only iterations where both completions answered 200 exercised the race
    valid = [r for r in results if r[0] == 200 and r[1] == 200]
    if len(valid) < min_valid:
        inconclusive(
            f"only {len(valid)} of {iterations} iterations had both completions "
            f"answer 200 (need {min_valid}); no loss seen, race not exercised enough"
        )
