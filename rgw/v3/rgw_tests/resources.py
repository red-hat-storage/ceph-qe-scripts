"""Resource ownership and reverse-order cleanup, including partial setup failures."""

import logging
import uuid

LOG = logging.getLogger(__name__)


def unique_name(label="resource"):
    return f"rgwv3-{label}-{uuid.uuid4().hex[:20]}"


class CleanupError(RuntimeError):
    pass


class Resources:
    def __init__(self):
        self.callbacks = []

    def defer(self, label, callback, *args, **kwargs):
        self.callbacks.append((label, callback, args, kwargs))

    def close(self):
        failed = []
        while self.callbacks:
            label, callback, args, kwargs = self.callbacks.pop()
            try:
                callback(*args, **kwargs)
            except Exception:
                # Do not log exception bodies that could include credentials.
                LOG.error("Cleanup failed: %s", label)
                failed.append(label)
        if failed:
            raise CleanupError("Cleanup failed for: " + ", ".join(failed))
