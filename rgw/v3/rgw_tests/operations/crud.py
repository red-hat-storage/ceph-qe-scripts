"""Boto3 CRUD and multipart primitives, safe for independent object threads."""

import hashlib
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payload(size, seed="rgwv3"):
    block = hashlib.sha256(seed.encode()).digest()
    return (block * ((size + len(block) - 1) // len(block)))[:size]


class CRUD:
    def __init__(self, client, bucket):
        self.client, self.bucket = client, bucket

    def put(self, key, body):
        return self.client.put_object(Bucket=self.bucket, Key=key, Body=body)

    def get(self, key, version=None):
        args = {"VersionId": version} if version is not None else {}
        response = self.client.get_object(Bucket=self.bucket, Key=key, **args)
        stream = response["Body"]
        try:
            return stream.read()
        finally:
            stream.close()

    def delete(self, key, version=None):
        args = {"VersionId": version} if version is not None else {}
        return self.client.delete_object(Bucket=self.bucket, Key=key, **args)

    def exists(self, key):
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def copy(self, source, target, version=None):
        source_ref = {"Bucket": self.bucket, "Key": source}
        if version is not None:
            source_ref["VersionId"] = version
        return self.client.copy_object(
            Bucket=self.bucket, Key=target, CopySource=source_ref
        )

    def list(self, prefix=""):
        return [
            item["Key"]
            for page in self.client.get_paginator("list_objects_v2").paginate(
                Bucket=self.bucket, Prefix=prefix
            )
            for item in page.get("Contents", [])
        ]

    def versions(self, prefix=""):
        pages = self.client.get_paginator("list_object_versions").paginate(
            Bucket=self.bucket, Prefix=prefix
        )
        result = {"Versions": [], "DeleteMarkers": []}
        for page in pages:
            for kind in result:
                result[kind].extend(page.get(kind, []))
        return result

    def start_multipart(self, key):
        return self.client.create_multipart_upload(Bucket=self.bucket, Key=key)[
            "UploadId"
        ]

    def uploads(self):
        return [
            item
            for page in self.client.get_paginator("list_multipart_uploads").paginate(
                Bucket=self.bucket
            )
            for item in page.get("Uploads", [])
        ]

    def parts(self, key, upload_id):
        return [
            part
            for page in self.client.get_paginator("list_parts").paginate(
                Bucket=self.bucket, Key=key, UploadId=upload_id
            )
            for part in page.get("Parts", [])
        ]

    def abort(self, key, upload_id):
        self.client.abort_multipart_upload(
            Bucket=self.bucket, Key=key, UploadId=upload_id
        )

    def multipart(self, key, body, part_size, source=None):
        if not body or part_size <= 0:
            raise ValueError(
                "Multipart uploads require nonempty data and positive part size"
            )
        upload_id = self.start_multipart(key)
        parts = []
        try:
            for number, offset in enumerate(range(0, len(body), part_size), 1):
                args = dict(
                    Bucket=self.bucket, Key=key, UploadId=upload_id, PartNumber=number
                )
                if source is None:
                    result = self.client.upload_part(
                        **args, Body=body[offset : offset + part_size]
                    )
                    etag = result["ETag"]
                else:
                    result = self.client.upload_part_copy(
                        **args,
                        CopySource={"Bucket": self.bucket, "Key": source},
                        CopySourceRange=f"bytes={offset}-{min(offset + part_size, len(body)) - 1}",
                    )
                    etag = result["CopyPartResult"]["ETag"]
                parts.append({"PartNumber": number, "ETag": etag})
            return self.client.complete_multipart_upload(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except BaseException:
            # Preserve the primary failure; the bucket finalizer retries cleanup.
            try:
                self.abort(key, upload_id)
            except Exception:
                pass
            raise

    @staticmethod
    def parallel(function, items, workers):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(function, items))
