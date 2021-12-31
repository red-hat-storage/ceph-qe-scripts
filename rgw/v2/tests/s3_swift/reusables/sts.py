import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import json
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.lib.rgw_config_opts import ConfigOpts
from v2.lib.s3.auth import Auth

log = logging.getLogger()
TEST_DATA_PATH = None


def add_sts_config_to_ceph_conf(
    ceph_config_set, rgw_service, sesison_encryption_token="abcdefghijklmnoq"
):
    """adding sts config to ceph conf
       this should be done initialay to have sts feature tested

    Args:
        ceph_config_set (object): ceph config class object
        rgw_service (object): rgw service object
        sesison_encryption_token (str, optional): Defaults to "abcdefghijklmnoq".

    Raises:
        TestExecError: if rgw service restart fails
    """
    log.info("adding sts config to ceph.conf")
    ceph_config_set.set_to_ceph_conf(
        "global", ConfigOpts.rgw_sts_key, sesison_encryption_token
    )
    ceph_config_set.set_to_ceph_conf("global", ConfigOpts.rgw_s3_auth_use_sts, "True")
    srv_restarted = rgw_service.restart()
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")


def add_caps(user_info, caps="roles=*"):
    """for RGW STS, we need to enable caps on user_1

    Args:
        user_info (dict): user info dict
        caps (str, optional): Defaults to "roles=*".
    """
    log.info("adding caps to user info")
    add_caps_cmd = 'sudo radosgw-admin caps add --uid="{user_id}" --caps={caps}'.format(
        user_id=user_info["user_id"], caps=caps
    )
    utils.exec_shell_cmd(add_caps_cmd)


def create_role(iam_client, policy_document, role_name):
    """create role

    Args:
        iam_client (auth): auth object using from iam
        policy_document (string): policy document string
        role_name (string): role to be used in the document

    Returns:
        http role_response
    """
    log.info("creating role")
    role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path="/",
        RoleName=role_name,
    )
    log.info(f"role_response\n:{role_response}")
    return role_response


def put_role_policy(iam_client, role_name, policy_name, role_policy):
    """put policy to the role

    Args:
        iam_client (auth): iam auth object
        role_name (sting): role name created using create_role
        policy_name (string): policy name
        role_policy (string): a dict like string, role policy document

    Returns:
        put policy http response
    """
    log.info("putting role policy")
    put_policy_response = iam_client.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=role_policy
    )

    log.info(f"put_policy\n:{put_policy_response}")
    return put_policy_response


def assume_role(sts_client, **kwargs):
    """assuming role

    Args:
        sts_client (auth): sts client auth
        kwargs (dict): assume role params

    Returns:
         assume role http response
    """
    log.info("assuming role")
    assume_role_response = sts_client.assume_role(**kwargs)
    log.info(f"assume_role_response:\n{assume_role_response}")
    return assume_role_response
