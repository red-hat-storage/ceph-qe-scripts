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


obtain_oidc_thumbprint_sh = """
#!/bin/bash

# Get the 'x5c' from this response to turn into an IDP-cert
KEY1_RESPONSE=$(curl -k -v \
     -X GET \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     'http://localhost:8180/realms/master/protocol/openid-connect/certs' 2>/dev/null \
     | jq -r .keys[0].x5c)

KEY2_RESPONSE=$(curl -k -v \
     -X GET \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     'http://localhost:8180/realms/master/protocol/openid-connect/certs' 2>/dev/null \
     | jq -r .keys[1].x5c)

# Assemble Cert1
echo '-----BEGIN CERTIFICATE-----' > certificate1.crt
echo $(echo $KEY1_RESPONSE) | sed 's/^.//;s/.$//;s/^.//;s/.$//;s/^.//;s/.$//' >> certificate1.crt
echo '-----END CERTIFICATE-----' >> certificate1.crt

# Assemble Cert2
echo '-----BEGIN CERTIFICATE-----' > certificate2.crt
echo $(echo $KEY2_RESPONSE) | sed 's/^.//;s/.$//;s/^.//;s/.$//;s/^.//;s/.$//' >> certificate2.crt
echo '-----END CERTIFICATE-----' >> certificate2.crt

# Create Thumbprint for both certs
PRETHUMBPRINT1=$(openssl x509 -in certificate1.crt -fingerprint -noout)
PRETHUMBPRINT2=$(openssl x509 -in certificate2.crt -fingerprint -noout)

PRETHUMBPRINT1=$(echo $PRETHUMBPRINT1 | awk '{ print substr($0, 18) }')
PRETHUMBPRINT2=$(echo $PRETHUMBPRINT2 | awk '{ print substr($0, 18) }')

echo ${PRETHUMBPRINT1//:}
echo ${PRETHUMBPRINT2//:}

#clean up the temp files
rm certificate1.crt
rm certificate2.crt
"""


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
        TestExecError: if restart fails
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


# todo: add --show-error and --fail flags to curl commands
def install_keycloak():
    out = utils.exec_shell_cmd(
        "podman run -d --name keycloak -p 8180:8180 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:22.0.0-0 start-dev --http-port 8180"
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def get_keycloak_web_acccess_token():
    out = utils.exec_shell_cmd(
        'curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8180/realms/master/protocol/openid-connect/token | jq -r .access_token'
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out.strip()


def get_keycloack_openid_configuration():
    out = utils.exec_shell_cmd(
        "curl http://localhost:8180/realms/master/.well-known/openid-configuration | jq -r .jwks_uri"
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def get_keycloack_certs():
    out = utils.exec_shell_cmd(
        "curl http://localhost:8180/realms/master/protocol/openid-connect/certs | jq ."
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def get_keycloak_user(username="admin"):
    access_token = get_keycloak_web_acccess_token()
    out = utils.exec_shell_cmd(
        f'curl -H "Content-Type: application/json" -H "Authorization: bearer {access_token}" http://localhost:8180/admin/realms/master/users/?username={username}'
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def get_keycloak_clients():
    access_token = get_keycloak_web_acccess_token()
    out = utils.exec_shell_cmd(
        f'curl -H "Content-Type: application/json" -H "Authorization: bearer {access_token}" http://localhost:8180/admin/realms/master/clients'
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def add_keycloak_user_attributes(attributes, username="admin"):
    access_token = get_keycloak_web_acccess_token()
    admin_user = get_keycloak_user("admin")[0]
    user_id = admin_user["id"]
    existing_attributes = admin_user["attributes"]
    existing_attributes.update(attributes)
    out = utils.exec_shell_cmd(
        f'curl -X PUT -H "Content-Type: application/json" -H "Authorization: bearer {access_token}" http://localhost:8180/admin/realms/master/users/{user_id} -d \'{{"attributes":{existing_attributes}}}\''
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def introspect_token():
    access_token = get_keycloak_web_acccess_token()
    out = utils.exec_shell_cmd(
        f'curl -d "token={access_token}" -u "account:n2BnvKAYWD1bn1jqpWhAMJB7HxkJ0AFX" http://localhost:8180/realms/master/protocol/openid-connect/token/introspect | jq .'
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def enable_client_authentication(client_name="account"):
    access_token = get_keycloak_web_acccess_token()
    out = utils.exec_shell_cmd(
        f'curl -X PUT -H "Content-Type: application/json" -H "Authorization: bearer {access_token}" http://localhost:8180/admin/realms/master/clients/65e70a29-629f-4c53-9c56-4e8b26fe9f1c -d \'{{"publicClient":false, "secret": "client_secret1"}}\''
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def disable_client_authentication(client_name="account"):
    access_token = get_keycloak_web_acccess_token()
    out = utils.exec_shell_cmd(
        f'curl -X PUT -H "Content-Type: application/json" -H "Authorization: bearer {access_token}" http://localhost:8180/admin/realms/master/clients/65e70a29-629f-4c53-9c56-4e8b26fe9f1c -d \'{{"publicClient":true}}\''
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def enable_client_direct_access_grants(client_name="account"):
    access_token = get_keycloak_web_acccess_token()
    out = utils.exec_shell_cmd(
        f'curl -X PUT -H "Content-Type: application/json" -H "Authorization: bearer {access_token}" http://localhost:8180/admin/realms/master/clients/65e70a29-629f-4c53-9c56-4e8b26fe9f1c -d \'{{"directAccessGrantsEnabled":true}}\''
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def create_open_id_connect_provider(iam_client):
    # obtain oidc idp thumbprint
    global obtain_oidc_thumbprint_sh
    thumbprints = utils.exec_shell_cmd(
        f'echo "{obtain_oidc_thumbprint_sh}" > obtain_oidc_thumbprint.sh'
    )
    thumbprints = thumbprints.strip().split("\n")

    # create openid connect provider
    oidc_response = iam_client.create_open_id_connect_provider(
        Url="http://localhost:8180/realms/master",
        ClientIDList=[
            "account",
        ],
        ThumbprintList=thumbprints,
    )
    log.info(f"oidc response: {oidc_response}")
    out = utils.exec_shell_cmd(
        "curl http://localhost:8180/realms/master/protocol/openid-connect/certs | jq ."
    )
    if out is False:
        raise Exception("keycloack deployment failed")
    return out


def list_open_id_connect_provider(iam_client):
    # list openid connect providers
    oidc_response = iam_client.list_open_id_connect_providers()
    log.info(f"oidc response: {oidc_response}")


def delete_open_id_connect_provider(iam_client):
    # delete openid connect provider
    oidc_response = iam_client.delete_open_id_connect_provider(
        OpenIDConnectProviderArn="arn:aws:iam:::oidc-provider/localhost"
    )
    log.info(f"oidc response: {oidc_response}")
    oidc_response = iam_client.delete_open_id_connect_provider(
        OpenIDConnectProviderArn="arn:aws:iam:::oidc-provider/localhost:8180/realms/master"
    )
    log.info(f"oidc response: {oidc_response}")
    time.sleep(5)
