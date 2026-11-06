"""Bounded polling; unexpected API errors propagate immediately."""

import time


class PollTimeout(TimeoutError):
    pass


def wait_for(probe, *, timeout, interval, description):
    deadline = time.monotonic() + timeout
    attempts = 0
    while True:
        attempts += 1
        result = probe()
        if result:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PollTimeout(
                f"Timed out waiting for {description}; attempts={attempts}"
            )
        time.sleep(min(interval, remaining))
