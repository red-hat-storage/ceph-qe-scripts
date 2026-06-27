"""
test_bucket_name_validation - Validate S3 bucket creation against name length rules

Usage: test_bucket_name_validation.py -c configs/test_bucket_name_validation.yaml

<input_yaml>
    configs/test_bucket_name_validation.yaml

Operation:
    Create an RGW user and attempt bucket creation with names covering length
    boundaries, empty names, hyphen/dot adjacency, and character-set rules
    (lowercase, digits, mixed valid/invalid characters, unicode, etc.).
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


def _length_test_cases():
    """Length boundary cases: (case_id, description, bucket_name, should_succeed)."""
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


def _character_set_test_cases():
    """Character-set cases: (case_id, description, bucket_name, should_succeed)."""
    return [
        (
            "lowercase_letters_only",
            "Lowercase letters only",
            "abcxyz",
            True,
        ),
        (
            "digits_only",
            "Digits only (start/end rule met)",
            "123456",
            True,
        ),
        (
            "letters_and_digits",
            "Letters + digits",
            "ab1c2d",
            True,
        ),
        (
            "hyphens_in_middle",
            "Hyphens in middle",
            "a-b-c",
            True,
        ),
        (
            "single_period",
            "Single period (not adjacent)",
            "a.bc",
            True,
        ),
        (
            "uppercase_letters",
            "Uppercase letters",
            "ABCdef",
            False,
        ),
        (
            "underscore",
            "Underscore",
            "a_b_c",
            False,
        ),
        (
            "space",
            "Space",
            "a b c",
            False,
        ),
        (
            "slash_path_like",
            "Slash / path-like",
            "a/b/c",
            False,
        ),
        (
            "special_chars",
            "Special chars @#%&",
            "a@b#c",
            False,
        ),
        (
            "unicode_non_ascii",
            "Unicode / non-ASCII",
            "caf\u00e9",
            False,
        ),
        (
            "mixed_valid_set",
            "Mixed valid set",
            "a1b2-c3.d4",
            True,
        ),
    ]


def _bucket_name_test_cases():
    """Return (case_id, description, bucket_name, should_succeed)."""
    return _length_test_cases() + _character_set_test_cases()


_CASE_PRECHECKS = {
    "minimum_length_3": lambda n: _assert_bucket_name_length(n, 3) or None,
    "below_minimum_2": lambda n: _assert_bucket_name_length(n, 2) or None,
    "maximum_length_63": lambda n: _assert_bucket_name_length(n, 63) or None,
    "above_maximum_64": lambda n: _assert_bucket_name_length(n, 64) or None,
    "boundary_62_chars": lambda n: _assert_bucket_name_length(n, 62) or None,
    "hyphens_dots_counted_adjacent": lambda n: _check_hyphens_dots_adjacent(n, 5),
    "hyphens_dots_counted_non_adjacent": lambda n: _check_hyphens_dots_non_adjacent(
        n, 5
    ),
    "lowercase_letters_only": lambda n: (
        None if n.isalpha() and n.islower() else "expected lowercase letters only"
    ),
    "digits_only": lambda n: (
        None if n.isdigit() and len(n) >= 3 else "expected digits only (len >= 3)"
    ),
    "letters_and_digits": lambda n: (
        None
        if any(c.isalpha() for c in n) and any(c.isdigit() for c in n) and n.islower()
        else "expected lowercase letters and digits"
    ),
    "hyphens_in_middle": lambda n: (
        None
        if "-" in n[1:-1] and not n.startswith("-") and not n.endswith("-")
        else "expected hyphen only in the middle"
    ),
    "single_period": lambda n: (
        None
        if n.count(".") == 1 and ".." not in n
        else "expected a single period, not adjacent periods"
    ),
    "uppercase_letters": lambda n: (
        None if any(c.isupper() for c in n) else "expected uppercase letters in name"
    ),
    "underscore": lambda n: (None if "_" in n else "expected underscore in name"),
    "space": lambda n: (None if " " in n else "expected space in name"),
    "slash_path_like": lambda n: (None if "/" in n else "expected slash in name"),
    "special_chars": lambda n: (
        None if any(c in n for c in "@#%&") else "expected @#%& in name"
    ),
    "unicode_non_ascii": lambda n: (
        None if any(ord(c) > 127 for c in n) else "expected non-ASCII character in name"
    ),
    "mixed_valid_set": lambda n: (
        None
        if all(c.islower() or c.isdigit() or c in ".-" for c in n)
        and any(c.isdigit() for c in n)
        and any(c.isalpha() for c in n)
        and "-" in n
        and "." in n
        else "expected mixed valid lowercase, digits, hyphen, and period"
    ),
}


def _check_hyphens_dots_adjacent(name, expected_len):
    _assert_bucket_name_length(name, expected_len)
    if ".-" not in name:
        return "expected adjacent '.-' in generated name"
    return None


def _check_hyphens_dots_non_adjacent(name, expected_len):
    _assert_bucket_name_length(name, expected_len)
    if "." not in name or "-" not in name:
        return "expected both '.' and '-' in generated name"
    if ".-" in name:
        return "expected non-adjacent '.' and '-' in name"
    return None


def _precheck_case(case_id, bucket_name):
    """Run shape validation for a case. Returns error message or None."""
    if case_id == "empty_name":
        return None
    checker = _CASE_PRECHECKS.get(case_id)
    if checker is None:
        return None
    try:
        return checker(bucket_name)
    except TestExecError as exc:
        return str(exc)


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

                precheck_error = _precheck_case(case_id, bucket_name)
                if precheck_error:
                    failures.append(f"{case_id}: {precheck_error}")
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
    test_info = AddTestInfo("S3 bucket name length and character-set validation")
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
