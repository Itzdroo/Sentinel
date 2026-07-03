from __future__ import annotations

import random
import time
from collections import deque
from collections.abc import Callable
from threading import Lock
from typing import TypeVar


T = TypeVar("T")


class CallsPerSecondLimiter:
    def __init__(self, calls_per_second: int) -> None:
        self.calls_per_second = max(1, calls_per_second)
        self._timestamps: deque[float] = deque()
        self._lock = Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            while self._timestamps and now - self._timestamps[0] >= 1:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.calls_per_second:
                sleep_for = 1 - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= 1:
                    self._timestamps.popleft()
            self._timestamps.append(time.monotonic())


def is_retryable_message(message: str) -> bool:
    text = message.lower()
    retryable_tokens = (
        "429",
        "rate limit",
        "too many requests",
        "timeout",
        "timed out",
        "connection aborted",
        "connection reset",
        "temporarily unavailable",
        "bad gateway",
        "service unavailable",
        "gateway timeout",
        "502",
        "503",
        "504",
    )
    return any(token in text for token in retryable_tokens)


def retry_with_backoff(
    operation: Callable[[], T],
    *,
    max_attempts: int = 5,
    base_delay_seconds: float = 0.4,
    max_delay_seconds: float = 8.0,
    should_retry: Callable[[Exception], bool] | None = None,
) -> T:
    last_error: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return operation()
        except Exception as exc:
            last_error = exc
            retryable = should_retry(exc) if should_retry else is_retryable_message(str(exc))
            if not retryable or attempt == max_attempts - 1:
                raise
            jitter = random.uniform(0, base_delay_seconds)
            delay = min(max_delay_seconds, base_delay_seconds * (2**attempt)) + jitter
            time.sleep(delay)
    if last_error is not None:
        raise last_error
    raise RuntimeError("retry loop exited without running operation")
