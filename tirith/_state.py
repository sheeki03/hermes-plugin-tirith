"""Small thread-safe in-memory stores. Nothing here is written to disk."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from typing import Any

_MISSING = object()


class BoundedStore:
    """A size- and age-bounded mapping (LRU order, TTL per entry) guarded by one lock.

    Hermes runs parallel tool calls on worker threads, so every access takes the lock.
    """

    def __init__(self, max_entries: int = 512, ttl: float = 600.0, clock: Callable[[], float] = time.monotonic):
        self._max_entries = max_entries
        self._ttl = ttl
        self._clock = clock
        self._data: OrderedDict[Hashable, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        while self._data:
            key, (stamp, _value) = next(iter(self._data.items()))
            if now - stamp <= self._ttl and len(self._data) <= self._max_entries:
                break
            del self._data[key]

    def set(self, key: Hashable, value: Any) -> None:
        with self._lock:
            now = self._clock()
            self._data.pop(key, None)
            self._data[key] = (now, value)
            self._expire(now)

    def get(self, key: Hashable, default: Any = None) -> Any:
        with self._lock:
            now = self._clock()
            self._expire(now)
            entry = self._data.get(key, _MISSING)
            if entry is _MISSING:
                return default
            return entry[1]

    def pop(self, key: Hashable, default: Any = None) -> Any:
        with self._lock:
            now = self._clock()
            self._expire(now)
            entry = self._data.pop(key, _MISSING)
            if entry is _MISSING:
                return default
            return entry[1]

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            self._expire(self._clock())
            return len(self._data)


class RateLimiter:
    """Allows one event per ``interval`` seconds for each key."""

    def __init__(self, interval: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self._interval = interval
        self._clock = clock
        self._last: dict[Hashable, float] = {}
        self._lock = threading.Lock()

    def allow(self, key: Hashable) -> bool:
        with self._lock:
            now = self._clock()
            last = self._last.get(key)
            if last is not None and now - last < self._interval:
                return False
            self._last[key] = now
            if len(self._last) > 256:
                self._last = {k: v for k, v in self._last.items() if now - v < self._interval}
            return True

    def clear(self) -> None:
        with self._lock:
            self._last.clear()
