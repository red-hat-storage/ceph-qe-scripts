"""Explicit resharding of an owned bucket."""


class Resharding:
    def __init__(self, admin, bucket, tenant=None):
        self.admin, self.bucket = admin, bucket
        self.tenant = tenant

    def shards(self):
        return self.admin.run(
            "bucket", "stats", bucket=self.bucket, tenant=self.tenant
        )["num_shards"]

    def reshard(self, count):
        self.admin.run(
            "bucket",
            "reshard",
            bucket=self.bucket,
            tenant=self.tenant,
            num_shards=count,
            json_output=False,
        )
