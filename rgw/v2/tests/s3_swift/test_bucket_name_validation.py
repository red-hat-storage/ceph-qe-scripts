"""
test_bucket_name_validation - Validate S3 bucket creation against name length rules

Usage: test_bucket_name_validation.py -c configs/test_bucket_name_validation.yaml

<input_yaml>
    configs/test_bucket_name_validation.yaml

Operation:
    Create an RGW user and attempt bucket creation with names covering:
      - Minimum length (3 chars) — expect success
      - Below minimum (2 chars) — expect failure
      - Maximum length (63 chars) — expect success
      - Above maximum (64 chars) — expect failure
      - Boundary at 62 chars — expect success
      - Empty name — expect failure
      - 5 chars with adjacent '.-' and non-adjacent '.'/'-' (length counts separators) — expect success
"""

import argparse
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from botocore.exceptions import ClientError, ParamValidationError
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()


def _alphanumeric_name(length):
    """Valid DNS-style bucket name of exact length (starts/ends with alnum)."""
    if length < 3:
        return "a" * length
    return "a" + ("b" * (length - 2)) + "c"


def _name_with_hyphens_and_dots(length, adjacent=True):
    """
    Valid bucket name of exact length where hyphens and dots count toward the limit.

    Args:
        length: Target bucket name length.
        adjacent: If True, use consecutive '.-' pairs (e.g. a.-.-.-c).
                  If False, use '.' and '-' separated by alphanumerics
                  (e.g. a.b-c.d-e.c).
    """
    if length < 3:
        return _alphanumeric_name(length)

    if adjacent:
        name = "a"
        while len(name) + 3 <= length:
            name += ".-"
        suffix_len = length - len(name)
        if suffix_len == 1:
            name += "c"
        else:
            name += "b" * (suffix_len - 1) + "c"
        return name

    name = "a"
    idx = 0
    while len(name) < length - 1:
        remaining = length - len(name)
        if remaining < 3:
            break
        letter = chr(ord("b") + (idx % 24))
        chunk = f".{letter}-"
        if len(name) + len(chunk) > length - 1:
            break
        name += chunk
        idx += 1

    suffix_len = length - len(name)
    if suffix_len == 1:
        name += "c"
    else:
        name += "b" * (suffix_len - 1) + "c"
    return name


def _bucket_name_test_cases():
    """Return (case_id, description, bucket_name, should_succeed)."""
    return [
        (
            "minimum_length_3",
            "Minimum length (3 chars)",
            _alphanumeric_name(3),
            True,
        ),
        (
            "below_minimum_2",
            "Below minimum (2 chars)",
            _alphanumeric_name(2),
            False,
        ),
        (
            "maximum_length_63",
            "Maximum length (63 chars)",
            _alphanumeric_name(63),
            True,
        ),
        (
            "above_maximum_64",
            "Above maximum (64 chars)",
            _alphanumeric_name(64),
            False,
        ),
        (
            "boundary_62_chars",
            "Boundary: exactly 62 chars (valid)",
            _alphanumeric_name(62),
            True,
        ),
        (
            "empty_name",
            "Empty name",
            "",
            False,
        ),
        (
            "hyphens_dots_counted_adjacent",
            "Length with adjacent hyphens/dots counted (5 chars)",
            _name_with_hyphens_and_dots(5, adjacent=True),
            False,
        ),
        (
            "hyphens_dots_counted_non_adjacent",
            "Length with non-adjacent hyphens/dots counted (5 chars)",
            _name_with_hyphens_and_dots(5, adjacent=False),
            True,
        ),
    ]


def _attempt_create_bucket(s3_client, bucket_name):
    """Try to create a bucket. Returns (created: bool, error: Exception|None)."""
    try:
        s3_client.create_bucket(Bucket=bucket_name)
        return True, None
    except (ClientError, ParamValidationError) as exc:
        return False, exc
    except ValueError as exc:
        return False, exc


def _format_error(exc):
    if exc is None:
        return ""
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', type(exc).__name__)}: {err.get('Message', exc)}"
    return f"{type(exc).__name__}: {exc}"


def _assert_bucket_name_length(bucket_name, expected_len):
    actual = len(bucket_name)
    if actual != expected_len:
        raise TestExecError(
            f"Generated bucket name length {actual} != expected {expected_len}: "
            f"'{bucket_name}'"
        )


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    all_users_info = s3lib.create_users(config.user_count)

    for each_user in all_users_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        s3_client = auth.do_auth_using_client()
        buckets_to_cleanup = []

        if config.test_ops.get("bucket_name_validation", False) is True:
            log.info(
                "Running bucket name validation cases for user %s",
                each_user["user_id"],
            )
            failures = []

            for (
                case_id,
                description,
                bucket_name,
                should_succeed,
            ) in _bucket_name_test_cases():
                if case_id != "empty_name":
                    log.info(
                        "Case %s (%s): name=%r len=%d expect_success=%s",
                        case_id,
                        description,
                        bucket_name,
                        len(bucket_name),
                        should_succeed,
                    )
                else:
                    log.info(
                        "Case %s (%s): name=%r expect_success=%s",
                        case_id,
                        description,
                        bucket_name,
                        should_succeed,
                    )

                if case_id == "minimum_length_3":
                    _assert_bucket_name_length(bucket_name, 3)
                elif case_id == "below_minimum_2":
                    _assert_bucket_name_length(bucket_name, 2)
                elif case_id == "maximum_length_63":
                    _assert_bucket_name_length(bucket_name, 63)
                elif case_id == "above_maximum_64":
                    _assert_bucket_name_length(bucket_name, 64)
                elif case_id == "boundary_62_chars":
                    _assert_bucket_name_length(bucket_name, 62)
                elif case_id == "hyphens_dots_counted_adjacent":
                    _assert_bucket_name_length(bucket_name, 5)
                    if ".-" not in bucket_name:
                        failures.append(
                            f"{case_id}: expected adjacent '.-' in generated name"
                        )
                        continue
                elif case_id == "hyphens_dots_counted_non_adjacent":
                    _assert_bucket_name_length(bucket_name, 5)
                    if "." not in bucket_name or "-" not in bucket_name:
                        failures.append(
                            f"{case_id}: expected both '.' and '-' in generated name"
                        )
                        continue
                    if ".-" in bucket_name:
                        failures.append(
                            f"{case_id}: expected non-adjacent '.' and '-' in name"
                        )
                        continue

                created, error = _attempt_create_bucket(s3_client, bucket_name)

                if should_succeed and not created:
                    failures.append(
                        f"{case_id} ({description}): expected success, got failure — "
                        f"{_format_error(error)}"
                    )
                elif not should_succeed and created:
                    failures.append(
                        f"{case_id} ({description}): expected failure, bucket was created"
                    )
                    buckets_to_cleanup.append(bucket_name)
                elif should_succeed and created:
                    log.info("PASS: %s — bucket created as expected", case_id)
                    buckets_to_cleanup.append(bucket_name)
                else:
                    log.info(
                        "PASS: %s — creation failed as expected (%s)",
                        case_id,
                        _format_error(error),
                    )

            for bucket_name in buckets_to_cleanup:
                try:
                    s3_client.delete_bucket(Bucket=bucket_name)
                    log.info("Cleaned up bucket %s", bucket_name)
                except ClientError as exc:
                    log.warning(
                        "Failed to delete bucket %s during cleanup: %s",
                        bucket_name,
                        _format_error(exc),
                    )

            if failures:
                raise TestExecError(
                    "Bucket name validation failed:\n" + "\n".join(failures)
                )
        else:
            log.warning(
                "bucket_name_validation not enabled in test_ops; skipping validation"
            )

        if config.user_remove:
            reusable.remove_user(each_user)


if __name__ == "__main__":
    test_info = AddTestInfo("S3 bucket name length validation")
    test_info.started_info()

    try:
        parser = argparse.ArgumentParser(description="RGW bucket name validation")
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
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        CephConfOp(ssh_con)
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
