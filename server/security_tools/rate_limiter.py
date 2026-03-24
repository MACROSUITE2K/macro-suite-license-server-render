from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[int]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check_and_increment(self, *, bucket_key: str, max_requests: int, window_seconds: int) -> int:
        now_ts = int(time.time())
        cutoff = now_ts - int(window_seconds)

        with self._lock:
            queue = self._buckets[bucket_key]
            while queue and queue[0] <= cutoff:
                queue.popleft()

            if len(queue) >= int(max_requests):
                return -1

            queue.append(now_ts)
            return len(queue)


RATE_LIMITER = SlidingWindowRateLimiter()
