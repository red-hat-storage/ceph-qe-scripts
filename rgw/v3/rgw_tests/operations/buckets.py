"""Bucket setup and paginated removal of all owned bucket contents."""

from rgw_tests.resources import unique_name


class Buckets:
    def __init__(self, client, resources):
        self.client, self.resources = client, resources

    def create(self, state="normal"):
        name = unique_name("bucket")
        self.client.create_bucket(Bucket=name)
        self.resources.defer(f"bucket {name}", self.remove, name)
        if state in ("versioned", "suspended"):
            self.client.put_bucket_versioning(
                Bucket=name, VersioningConfiguration={"Status": "Enabled"}
            )
        if state == "suspended":
            self.client.put_bucket_versioning(
                Bucket=name, VersioningConfiguration={"Status": "Suspended"}
            )
        return name

    def remove(self, name):
        # Stop producers before enumerating their resources.
        self.client.put_bucket_notification_configuration(
            Bucket=name, NotificationConfiguration={}
        )
        self.client.delete_bucket_lifecycle(Bucket=name)
        for page in self.client.get_paginator("list_multipart_uploads").paginate(
            Bucket=name
        ):
            for upload in page.get("Uploads", []):
                self.client.abort_multipart_upload(
                    Bucket=name, Key=upload["Key"], UploadId=upload["UploadId"]
                )
        for page in self.client.get_paginator("list_object_versions").paginate(
            Bucket=name
        ):
            versions = page.get("Versions", []) + page.get("DeleteMarkers", [])
            self._delete(
                name,
                [
                    {"Key": item["Key"], "VersionId": item["VersionId"]}
                    for item in versions
                ],
            )
        for page in self.client.get_paginator("list_objects_v2").paginate(Bucket=name):
            self._delete(
                name, [{"Key": item["Key"]} for item in page.get("Contents", [])]
            )
        self.client.delete_bucket(Bucket=name)

    def _delete(self, bucket, objects):
        for start in range(0, len(objects), 1000):
            result = self.client.delete_objects(
                Bucket=bucket,
                Delete={"Objects": objects[start : start + 1000], "Quiet": True},
            )
            if result.get("Errors"):
                raise RuntimeError(
                    f"Bucket {bucket}: failed to delete {len(result['Errors'])} objects"
                )
