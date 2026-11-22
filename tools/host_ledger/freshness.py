"""Renewable signed-state freshness, separate from an immutable operation cap."""
import math
import threading
import time

from egress_authority import DIGEST, positive


class FreshnessLatch:
    """A larger signed revision may renew only before the previous lease expires."""
    def __init__(self, revision, digest, deadline, absolute_deadline, clock=time.monotonic):
        if (not positive(revision) or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                or not math.isfinite(deadline) or not math.isfinite(absolute_deadline)):
            raise ValueError('invalid initial signed freshness')
        self.revision = revision
        self.digest = digest
        self.expires_at = min(deadline, absolute_deadline)
        self.absolute_deadline = absolute_deadline
        self.clock = clock
        self.stopped = False
        self.lock = threading.Lock()

    def _current(self, now):
        if now >= self.expires_at or now >= self.absolute_deadline:
            self.stopped = True
        return None if self.stopped else self.expires_at

    def deadline(self):
        with self.lock:
            return self._current(self.clock())

    def stop(self):
        with self.lock:
            self.stopped = True

    def observe(self, revision, digest, expires_unix_ms, wall_unix_ms, started_at):
        """Trusted caller already verified source signatures, commit and scope.

        started_at precedes wall sampling and all I/O; source lifetime is never
        credited from the completion of the check. Same revision cannot extend.
        """
        with self.lock:
            now = self.clock()
            if self._current(now) is None:
                return False
            try:
                if (not positive(revision) or revision < self.revision
                        or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                        or not positive(expires_unix_ms) or type(wall_unix_ms) is not int
                        or not math.isfinite(started_at) or started_at > now
                        or not 0 < expires_unix_ms - wall_unix_ms <= 30000):
                    raise ValueError('invalid signed freshness update')
                if revision == self.revision:
                    if digest != self.digest:
                        raise ValueError('signed state changed without a new revision')
                    return True
                expires = min(started_at + (expires_unix_ms - wall_unix_ms) / 1000,
                              self.absolute_deadline)
                if expires <= now:
                    raise ValueError('freshness update arrived too late')
                self.revision, self.digest, self.expires_at = revision, digest, expires
                return True
            except (TypeError, ValueError):
                self.stopped = True
                return False
