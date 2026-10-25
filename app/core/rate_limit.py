"""
Simple in-memory sliding-window rate limiter (no extra dependencies).

Per client IP and per route group. Good for a single-process demo/server.
For several workers or servers, move the counters to Redis.
Set RATE_LIMIT_DISABLED=1 to switch it off (load tests, debugging).
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import deque

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float) -> int:
        """Records one request. Returns 0 if allowed, else seconds to wait."""
        now = self._clock()
        with self._lock:
            if len(self._hits) > 10_000:  # drop idle keys
                self._hits = {
                    k: v for k, v in self._hits.items()
                    if v and now - v[-1] < window
                }

            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= window:
                hits.popleft()

            if len(hits) >= limit:
                return max(1, math.ceil(window - (now - hits[0])))

            hits.append(now)
            return 0


limiter = SlidingWindowLimiter()


def rate_limit(name: str, limit: int, window: int = 60):
    """FastAPI dependency: at most `limit` requests per `window` seconds."""

    def dependency(request: Request) -> None:
        if os.getenv("RATE_LIMIT_DISABLED") == "1":
            return

        client = request.client.host if request.client else "unknown"
        wait = limiter.hit(f"{name}:{client}", limit, window)

        if wait:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Try again in {wait} seconds.",
                headers={"Retry-After": str(wait)},
            )

    return dependency