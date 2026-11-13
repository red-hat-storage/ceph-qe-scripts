"""Observe GC entries for this bucket only; never process the global queue."""


class GarbageCollection:
    def __init__(self, admin, bucket, tenant=None):
        self.admin = admin
        stats = admin.run("bucket", "stats", bucket=bucket, tenant=tenant)
        self.marker = stats["marker"]

    def entries(self):
        entries = self.admin.run("gc", "list", include_all=True) or []
        return [
            entry
            for entry in entries
            if any(
                item.get("oid", "").startswith(self.marker + "_")
                for item in entry.get("objs", [])
            )
        ]
