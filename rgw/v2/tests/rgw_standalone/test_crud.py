"""CRUD ops against zipper: PUT/GET/HEAD/list/Delete/get-object-attributes."""

import os

import pytest
from botocore.exceptions import ClientError

from v2.tests.rgw_standalone.reusables import rgw_standalone as zs

pytestmark = [pytest.mark.sanity, pytest.mark.user_type]


def test_crud_small_medium_large(
    user_label, s3_client_factory, object_sizes, account_root_client
):
    """PUT/GET/HEAD/list/Delete/get-object-attributes for small/medium/large."""
    client = s3_client_factory(user_label)
    creator = account_root_client if user_label == "account_user" else None
    bkt = zs.unique_name("crud", user_label)
    zs.ensure_bucket(client, bkt, creator=creator)

    digests = {}
    try:
        for size_name, nbytes in object_sizes.items():
            key = f"obj-{size_name}"
            data = os.urandom(int(nbytes))
            digests[key] = zs.md5_bytes(data)

            client.put_object(
                Bucket=bkt,
                Key=key,
                Body=data,
                ContentType="application/octet-stream",
            )
            head = client.head_object(Bucket=bkt, Key=key)
            assert int(head["ContentLength"]) == int(nbytes)

            body = client.get_object(Bucket=bkt, Key=key)["Body"].read()
            assert zs.md5_bytes(body) == digests[key]

            try:
                attrs = client.get_object_attributes(
                    Bucket=bkt,
                    Key=key,
                    ObjectAttributes=["ETag", "ObjectSize", "StorageClass", "Checksum"],
                )
                assert int(attrs.get("ObjectSize", nbytes)) == int(nbytes)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                pytest.fail(f"get-object-attributes failed: {code}: {e}")

        listed = {
            o["Key"]
            for o in (client.list_objects_v2(Bucket=bkt).get("Contents") or [])
        }
        for key in digests:
            assert key in listed, f"{key} missing from list-objects"

        for key in digests:
            client.delete_object(Bucket=bkt, Key=key)
        assert client.list_objects_v2(Bucket=bkt).get("KeyCount", 0) == 0
    finally:
        zs.wipe_bucket(client if user_label != "account_user" else account_root_client, bkt)
