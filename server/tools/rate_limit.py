"""Small in-memory sliding-window rate limiter, shared by tools that hit external APIs."""

import time
from collections import deque


class SlidingWindowLimiter:
    """Allows at most `max_calls` within any rolling `window_seconds` window."""

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: deque[float] = deque()

    def check(self) -> bool:
        """Return True and record the call if allowed; False if the limit is exceeded."""
        now = time.monotonic()
        while self._calls and now - self._calls[0] > self.window_seconds:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            return False
        self._calls.append(now)
        return True


if __name__ == "__main__":
    limiter = SlidingWindowLimiter(max_calls=3, window_seconds=5)
    for i in range(5):
        print(f"call {i}: allowed={limiter.check()}")
