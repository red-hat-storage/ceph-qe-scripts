"""Lifecycle configuration helpers (processing is left to the cluster)."""


class Lifecycle:
    def __init__(self, client, bucket):
        self.client, self.bucket = client, bucket

    def configure(self, *, days=1, prefix="expire/", noncurrent=False, abort=False):
        rule = {"ID": "rgwv3", "Status": "Enabled", "Filter": {"Prefix": prefix}}
        if abort:
            rule["AbortIncompleteMultipartUpload"] = {"DaysAfterInitiation": days}
        elif noncurrent:
            rule["NoncurrentVersionExpiration"] = {"NoncurrentDays": days}
        else:
            rule["Expiration"] = {"Days": days}
        self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket, LifecycleConfiguration={"Rules": [rule]}
        )
        return rule

    def rules(self):
        return self.client.get_bucket_lifecycle_configuration(Bucket=self.bucket)[
            "Rules"
        ]
