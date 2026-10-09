"""Bucket/object features: ACL, checksum, bucket policy, public access block."""

import json
import os

import pytest
from botocore.exceptions import ClientError

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.feature, pytest.mark.user_type]


def test_acl_checksum_policy_pab(
    user_label, s3_client_factory, account_root_client
):
    client = s3_client_factory(user_label)
    creator = account_root_client if user_label == "account_user" else None
    bkt = zs.unique_name("feat", user_label)
    zs.ensure_bucket(client, bkt, creator=creator)
    key = "feat-obj.txt"

    try:
        client.put_object(Bucket=bkt, Key=key, Body=b"feature-test-payload")
        client.put_object_acl(Bucket=bkt, Key=key, ACL="private")
        obj_acl = client.get_object_acl(Bucket=bkt, Key=key)
        assert obj_acl.get("Grants")
        client.put_bucket_acl(Bucket=bkt, ACL="private")
        bkt_acl = client.get_bucket_acl(Bucket=bkt)
        assert bkt_acl.get("Grants")

        data = b"checksum-data-" + os.urandom(32)
        client.put_object(
            Bucket=bkt, Key="chk.bin", Body=data, ChecksumAlgorithm="CRC32"
        )
        head = client.head_object(Bucket=bkt, Key="chk.bin", ChecksumMode="ENABLED")
        got = client.get_object(Bucket=bkt, Key="chk.bin", ChecksumMode="ENABLED")
        assert head.get("ChecksumCRC32") or got.get("ChecksumCRC32")

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyInsecureDelete",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:DeleteBucket",
                    "Resource": f"arn:aws:s3:::{bkt}",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
        client.put_bucket_policy(Bucket=bkt, Policy=json.dumps(policy))
        got_policy = client.get_bucket_policy(Bucket=bkt)["Policy"]
        assert "DenyInsecureDelete" in got_policy
        client.delete_bucket_policy(Bucket=bkt)

        cfg = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        client.put_public_access_block(
            Bucket=bkt, PublicAccessBlockConfiguration=cfg
        )
        pab = client.get_public_access_block(Bucket=bkt)[
            "PublicAccessBlockConfiguration"
        ]
        assert pab.get("BlockPublicAcls") is True
        client.delete_public_access_block(Bucket=bkt)
    finally:
        wipe = account_root_client if user_label == "account_user" else client
        zs.wipe_bucket(wipe, bkt)


@pytest.mark.bug
def test_object_lock_default_retention(s3_client_factory):
    """IBMCEPH-18592: bucket DefaultRetention must apply to new objects."""
    client = s3_client_factory("normal")
    bkt = zs.unique_name("oldef", "normal")
    try:
        client.create_bucket(
            Bucket=bkt,
            ObjectLockEnabledForBucket=True,
        )
        client.put_object_lock_configuration(
            Bucket=bkt,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2}
                },
            },
        )
        client.put_object(Bucket=bkt, Key="locked.bin", Body=b"default-retention")
        try:
            ret = client.get_object_retention(Bucket=bkt, Key="locked.bin")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            pytest.fail(
                f"IBMCEPH-18592: GetObjectRetention after default rule failed: {code}"
            )
        assert ret.get("Retention", {}).get("Mode") == "COMPLIANCE"
    finally:
        # compliance lock may block deletes; best-effort
        try:
            zs.wipe_bucket(client, bkt)
        except Exception:
            pass


@pytest.mark.bug
def test_versioning_basic_workflows(s3_client_factory):
    """IBMCEPH-18038: versioning enable/put/list/get-by-version/delete-marker."""
    client = s3_client_factory("normal")
    bkt = zs.unique_name("ver", "normal")
    zs.ensure_bucket(client, bkt)
    try:
        client.put_bucket_versioning(
            Bucket=bkt, VersioningConfiguration={"Status": "Enabled"}
        )
        status = client.get_bucket_versioning(Bucket=bkt).get("Status")
        assert status == "Enabled"

        v1 = client.put_object(Bucket=bkt, Key="k", Body=b"v1")["VersionId"]
        v2 = client.put_object(Bucket=bkt, Key="k", Body=b"v2")["VersionId"]
        assert v1 and v2 and v1 != v2

        versions = client.list_object_versions(Bucket=bkt).get("Versions") or []
        ids = {v["VersionId"] for v in versions if v["Key"] == "k"}
        assert v1 in ids and v2 in ids

        assert client.get_object(Bucket=bkt, Key="k", VersionId=v1)["Body"].read() == b"v1"
        dm = client.delete_object(Bucket=bkt, Key="k")
        assert dm.get("DeleteMarker") in (True, None) or dm.get("VersionId")

        client.put_bucket_versioning(
            Bucket=bkt, VersioningConfiguration={"Status": "Suspended"}
        )
        assert client.get_bucket_versioning(Bucket=bkt).get("Status") == "Suspended"
    finally:
        zs.wipe_bucket(client, bkt)
