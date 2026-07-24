"""
Generate and run STS role (and optional session) policy permutations.

Each permutation varies policy statement fields (Effect, Action, Resource, Condition)
for every S3 action that has a mapped boto test helper in sts_permutations.py.
"""

import json
import logging
import random
import string
from collections import namedtuple

from botocore.exceptions import ClientError
from v2.lib.exceptions import TestExecError
from v2.lib.s3.auth import Auth
from v2.tests.s3_swift.reusables import sts_permutations as sts_perm

log = logging.getLogger()

PermutationCase = namedtuple(
    "PermutationCase",
    [
        "case_id",
        "s3_action",
        "effect",
        "resource_type",
        "condition_name",
        "condition_variant",
        "policy_scope",
        "session_effect",
    ],
)

RESOURCE_ARN_TEMPLATES = {
    "arn_access_all_buckets_and_objects": lambda tenant, bucket: [
        f"arn:aws:s3::{tenant}:*"
    ],
    "arn_access_only_the_bucket": lambda tenant, bucket: [
        f"arn:aws:s3::{tenant}:{bucket}"
    ],
    "arn_access_all_objects_under_all_buckets": lambda tenant, bucket: [
        f"arn:aws:s3::{tenant}:*/*"
    ],
    "arn_access_all_objects_under_the_bucket": lambda tenant, bucket: [
        f"arn:aws:s3::{tenant}:{bucket}/*"
    ],
    "arn_pseudo_directory_access": lambda tenant, bucket: [
        f"arn:aws:s3::{tenant}:{bucket}/warehouse",
        f"arn:aws:s3::{tenant}:{bucket}/warehouse/",
        f"arn:aws:s3::{tenant}:{bucket}/warehouse/*",
    ],
}

# condition_name -> {match, mismatch} Condition blocks (None = omit Condition)
CONDITION_PRESETS = {
    "none": {"match": None, "mismatch": None},
    "aws_secure_transport": {
        "match": {"Bool": {"aws:SecureTransport": "false"}},
        "mismatch": {"Bool": {"aws:SecureTransport": "true"}},
    },
    "s3_prefix": {
        "match": {"StringLike": {"s3:prefix": ["warehouse*"]}},
        "mismatch": {"StringLike": {"s3:prefix": ["other-prefix/*"]}},
    },
    "aws_current_time": {
        "match": {"DateGreaterThan": {"aws:CurrentTime": "2000-01-01T00:00:00Z"}},
        "mismatch": {"DateGreaterThan": {"aws:CurrentTime": "2099-01-01T00:00:00Z"}},
    },
    "string_equals_userid": {
        "match": {"StringEquals": {"aws:userid": "<role_userid>"}},
        "mismatch": {"StringEquals": {"aws:userid": "wrong-role-id:wrong-session"}},
    },
}

# All dimensions for the full cartesian product (no sampling).
FULL_CARTESIAN_TEST_OPS = {
    "permutation_effects": ["Allow", "Deny"],
    "permutation_conditions": [
        "none",
        "aws_secure_transport",
        "s3_prefix",
        "aws_current_time",
        "string_equals_userid",
    ],
    "permutation_condition_variants": ["match", "mismatch"],
    "permutation_policy_scopes": ["role_only", "role_and_session"],
    "permutation_s3_actions": "all",
    "permutation_resource_types": "auto",
    "permutation_max_cases": 0,
    "permutation_stop_on_failure": False,
}


def apply_full_cartesian_config(config):
    """Merge FULL_CARTESIAN_TEST_OPS into config.test_ops when enabled."""
    if not config.test_ops.get("permutation_full_cartesian", False):
        return
    for key, value in FULL_CARTESIAN_TEST_OPS.items():
        config.test_ops[key] = value
    log.info(
        "permutation_full_cartesian enabled: running entire cartesian product "
        "(Effect x Action x Resource x Condition x scope, no sampling)"
    )


def _condition_combos(condition_names, condition_variants):
    count = 0
    for condition_name in condition_names:
        for condition_variant in condition_variants:
            if condition_name == "none" and condition_variant == "mismatch":
                continue
            count += 1
    return count


def estimate_permutation_count(config):
    """Return the number of cases that generate_permutation_cases would produce."""
    apply_full_cartesian_config(config)
    effects = config.test_ops.get("permutation_effects", ["Allow", "Deny"])
    condition_names = config.test_ops.get(
        "permutation_conditions", ["none", "aws_secure_transport", "s3_prefix"]
    )
    policy_scopes = config.test_ops.get(
        "permutation_policy_scopes", ["role_only", "role_and_session"]
    )
    condition_variants = config.test_ops.get(
        "permutation_condition_variants", ["match", "mismatch"]
    )
    cond_count = _condition_combos(condition_names, condition_variants)
    total = 0
    for s3_action in list_testable_s3_actions(config):
        resource_types = sts_perm.s3_action_required_resource.get(
            s3_action, ["arn_access_all_buckets_and_objects"]
        )
        if config.test_ops.get("permutation_resource_types") not in (None, "auto"):
            resource_types = [
                rt
                for rt in resource_types
                if rt in config.test_ops["permutation_resource_types"]
            ]
        total += (
            len(resource_types)
            * len(effects)
            * cond_count
            * len(policy_scopes)
        )
    max_cases = config.test_ops.get("permutation_max_cases", 0)
    if max_cases and total > max_cases:
        return max_cases
    return total


def list_testable_s3_actions(config):
    """S3 IAM actions that have at least one mapped boto test helper."""
    actions = config.test_ops.get("permutation_s3_actions", "all")
    if actions == "all":
        return sorted(
            action
            for action, methods in sts_perm.s3_action_allowed_methods.items()
            if methods
        )
    return list(actions)


def generate_permutation_cases(config):
    """Build the cartesian product of configured policy field permutations."""
    apply_full_cartesian_config(config)
    effects = config.test_ops.get("permutation_effects", ["Allow", "Deny"])
    condition_names = config.test_ops.get(
        "permutation_conditions", ["none", "aws_secure_transport", "s3_prefix"]
    )
    policy_scopes = config.test_ops.get(
        "permutation_policy_scopes", ["role_only", "role_and_session"]
    )
    condition_variants = config.test_ops.get(
        "permutation_condition_variants", ["match", "mismatch"]
    )
    max_cases = config.test_ops.get("permutation_max_cases", 0)

    cases = []
    case_num = 0
    for s3_action in list_testable_s3_actions(config):
        resource_types = sts_perm.s3_action_required_resource.get(
            s3_action, ["arn_access_all_buckets_and_objects"]
        )
        if config.test_ops.get("permutation_resource_types") not in (None, "auto"):
            resource_types = [
                rt
                for rt in resource_types
                if rt in config.test_ops["permutation_resource_types"]
            ]
        for effect in effects:
            for resource_type in resource_types:
                for condition_name in condition_names:
                    for condition_variant in condition_variants:
                        if condition_name == "none" and condition_variant == "mismatch":
                            continue
                        for policy_scope in policy_scopes:
                            session_effect = None
                            if policy_scope == "role_and_session":
                                session_effect = (
                                    "Deny" if effect == "Allow" else "Allow"
                                )
                            case_num += 1
                            cases.append(
                                PermutationCase(
                                    case_id=f"p{case_num:05d}",
                                    s3_action=s3_action,
                                    effect=effect,
                                    resource_type=resource_type,
                                    condition_name=condition_name,
                                    condition_variant=condition_variant,
                                    policy_scope=policy_scope,
                                    session_effect=session_effect,
                                )
                            )

    if max_cases and len(cases) > max_cases:
        random.shuffle(cases)
        cases = cases[:max_cases]
        log.info(
            "sampled %s permutation cases (permutation_max_cases=%s)",
            len(cases),
            max_cases,
        )
    return cases


def resolve_resources(resource_type, tenant_name, bucket_name):
    resolver = RESOURCE_ARN_TEMPLATES.get(resource_type)
    if resolver is None:
        raise TestExecError(f"unknown resource_type {resource_type}")
    resources = resolver(tenant_name, bucket_name)
    if len(resources) == 1:
        return resources[0]
    return resources


def build_policy_statement(case, tenant_name, bucket_name, role_userid=None):
    """Build a single IAM policy statement for the permutation case."""
    resources = resolve_resources(case.resource_type, tenant_name, bucket_name)
    statement = {
        "Effect": case.effect,
        "Action": [case.s3_action],
        "Resource": resources,
    }
    condition_block = None
    if case.condition_name != "none":
        preset = CONDITION_PRESETS[case.condition_name][case.condition_variant]
        if preset is not None:
            preset_json = json.dumps(preset)
            if "<role_userid>" in preset_json:
                if not role_userid:
                    raise TestExecError(
                        "role_userid required for aws:userid condition (role_id:session_name)"
                    )
                preset_json = preset_json.replace("<role_userid>", role_userid)
            condition_block = json.loads(preset_json)
    if condition_block:
        statement["Condition"] = condition_block
    return statement


def build_assumed_role_userid(role_id, role_session_name):
    """aws:userid for assumed-role requests is role_id:role_session_name."""
    return f"{role_id}:{role_session_name}"


def build_trust_policy(tenant_name, principal_user_id):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [f"arn:aws:iam::{tenant_name}:user/{principal_user_id}"]
                },
                "Action": ["sts:AssumeRole"],
            }
        ],
    }


def build_permissive_session_policy(tenant_name):
    """Broad session policy used when role policy is Deny (session cannot override)."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": [f"arn:aws:s3::{tenant_name}:*"],
            }
        ],
    }


def expected_access(case):
    """
    Return True if the S3 API helpers for this action should succeed.
    """
    if case.effect == "Deny":
        return False
    if case.condition_variant == "mismatch":
        return False
    if case.policy_scope == "role_and_session" and case.session_effect == "Deny":
        return False
    return True


def _delete_iam_role(iam_client, role_name, policy_name="PermutationPolicy"):
    try:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError:
        pass
    try:
        iam_client.delete_role(RoleName=role_name)
    except ClientError:
        pass


def run_single_permutation(
    case,
    tenant_name,
    bucket_name,
    object_key,
    owner_user,
    principal_user,
    ssh_con,
    config,
    iam_client,
    sts_client,
    bucket_owner_s3,
):
    """Execute one permutation case and return (passed, message)."""
    principal_id = principal_user["user_id"]
    method_names = sts_perm.s3_action_allowed_methods.get(case.s3_action, [])
    if not method_names:
        return True, "skipped (no boto helpers mapped)"

    sts_perm.init_sts_permutation_globals(bucket_name, object_key, bucket_owner_s3)
    sts_perm.ensure_bucket_and_object(
        bucket_owner_s3, bucket_name, object_key, tenant_name
    )

    role_name = f"PermRole-{case.case_id}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=4))}"
    role_session_name = f"sess-{case.case_id}"
    trust_policy = build_trust_policy(tenant_name, principal_id)

    session_policy = None
    if case.policy_scope == "role_and_session":
        if case.session_effect == "Deny":
            session_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": [case.s3_action],
                        "Resource": resolve_resources(
                            case.resource_type, tenant_name, bucket_name
                        ),
                    }
                ],
            }
        else:
            session_policy = build_permissive_session_policy(tenant_name)

    try:
        create_role_resp = iam_client.create_role(
            RoleName=role_name,
            Path="/",
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="STS role policy permutation test role",
        )
        role_arn = create_role_resp["Role"]["Arn"]
        role_id = create_role_resp["Role"]["RoleId"]
        role_userid = build_assumed_role_userid(role_id, role_session_name)

        role_statement = build_policy_statement(
            case, tenant_name, bucket_name, role_userid
        )
        role_policy = {"Version": "2012-10-17", "Statement": [role_statement]}
        log.info(
            "case %s: role_id=%s role_session_name=%s aws:userid=%s",
            case.case_id,
            role_id,
            role_session_name,
            role_userid,
        )
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="PermutationPolicy",
            PolicyDocument=json.dumps(role_policy),
        )

        assume_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": role_session_name,
        }
        if session_policy is not None:
            assume_kwargs["Policy"] = json.dumps(session_policy)
        assumed = sts_client.assume_role(**assume_kwargs)
        creds = assumed["Credentials"]
        temp_user = {
            "user_id": principal_id,
            "access_key": creds["AccessKeyId"],
            "secret_key": creds["SecretAccessKey"],
            "session_token": creds["SessionToken"],
        }
        auth = Auth(temp_user, ssh_con, ssl=config.ssl)
        s3_client = auth.do_auth_using_client(**{"region_name": "us-east-1"})

        passed_actions, failed_actions = sts_perm.exercise_s3api_methods(
            s3_client, method_names
        )
        should_allow = expected_access(case)

        log.info(
            "case %s: action=%s effect=%s resource=%s condition=%s/%s scope=%s "
            "expected_allow=%s passed=%s failed=%s",
            case.case_id,
            case.s3_action,
            case.effect,
            case.resource_type,
            case.condition_name,
            case.condition_variant,
            case.policy_scope,
            should_allow,
            passed_actions,
            failed_actions,
        )

        if should_allow:
            if failed_actions or not passed_actions:
                return False, (
                    f"expected allow but failed={failed_actions} passed={passed_actions}"
                )
        else:
            if passed_actions:
                return False, (
                    f"expected deny but passed={passed_actions} failed={failed_actions}"
                )

        sts_perm.ensure_bucket_and_object(
            bucket_owner_s3, bucket_name, object_key, tenant_name
        )
        return True, "ok"

    except ClientError as exc:
        if not expected_access(case):
            return True, f"assume/setup denied as expected: {exc}"
        return False, f"unexpected ClientError: {exc}"
    finally:
        _delete_iam_role(iam_client, role_name)


def run_sts_role_policy_permutations(tenant_name, owner_user, principal_user, ssh_con, config):
    """
    Run all generated permutation cases. Raises TestExecError on any mismatch.
    """
    auth_owner = Auth(owner_user, ssh_con, ssl=config.ssl)
    iam_client = auth_owner.do_auth_iam_client()
    bucket_owner_s3 = auth_owner.do_auth_using_client(**{"region_name": "us-east-1"})

    auth_principal = Auth(principal_user, ssh_con, ssl=config.ssl)
    sts_client = auth_principal.do_auth_sts_client()

    if config.test_ops.get("same_bucket_owner_and_principal", False):
        bucket_owner_s3 = auth_principal.do_auth_using_client(
            **{"region_name": "us-east-1"}
        )

    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
    bucket_name = f"bkt-perm-{rand}"
    object_key = f"warehouse/test-object-{rand}"

    estimated = estimate_permutation_count(config)
    cases = generate_permutation_cases(config)
    log.info(
        "running %s STS role policy permutation cases (estimated=%s)",
        len(cases),
        estimated,
    )

    failures = []
    for idx, case in enumerate(cases, start=1):
        log.info(
            "\n%s\n=== permutation %s/%s: %s ===\n%s",
            "=" * 80,
            idx,
            len(cases),
            case,
            "=" * 80,
        )
        ok, message = run_single_permutation(
            case,
            tenant_name,
            bucket_name,
            object_key,
            owner_user,
            principal_user,
            ssh_con,
            config,
            iam_client,
            sts_client,
            bucket_owner_s3,
        )
        if not ok:
            failures.append((case, message))
            log.error("permutation FAILED: %s -> %s", case, message)
            if config.test_ops.get("permutation_stop_on_failure", False):
                break

    try:
        bucket_owner_s3.delete_object(Bucket=bucket_name, Key=object_key)
    except ClientError:
        pass
    try:
        bucket_owner_s3.delete_bucket(Bucket=bucket_name)
    except ClientError:
        pass

    log.info(
        "permutation summary: total=%s passed=%s failed=%s",
        len(cases),
        len(cases) - len(failures),
        len(failures),
    )
    if failures:
        for case, message in failures[:20]:
            log.error("  %s: %s", case, message)
        raise TestExecError(
            f"{len(failures)}/{len(cases)} STS role policy permutations failed"
        )
