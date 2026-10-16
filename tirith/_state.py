"""Small thread-safe in-memory stores. Nothing here is written to disk."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from typing import Any

_MISSING = object()


class BoundedStore:
    """A size- and age-bounded mapping guarded by one lock; the oldest entry goes first.

    Hermes runs parallel tool calls on worker threads, so every access takes the lock. An entry's
    age and position count from its last ``set``. With ``refresh_on_get`` a read counts as a use
    too (LRU): the entry moves to the newest end and its age restarts, so the size bound evicts the
    entry used longest ago, not one that is still being read.
    """

    def __init__(
        self,
        max_entries: int = 512,
        ttl: float = 600.0,
        clock: Callable[[], float] = time.monotonic,
        *,
        refresh_on_get: bool = False,
    ):
        self._max_entries = max_entries
        self._ttl = ttl
        self._clock = clock
        self._refresh_on_get = refresh_on_get
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
            if self._refresh_on_get:
                self._data[key] = (now, entry[1])
                self._data.move_to_end(key)
            return entry[1]

    def pop(self, key: Hashable, default: Any = None) -> Any:
        with self._lock:
            now = self._clock()
            self._expire(now)
            entry = self._data.pop(key, _MISSING)
            if entry is _MISSING:
                return default
            return entry[1]

    def values(self) -> list[Any]:
        with self._lock:
            self._expire(self._clock())
            return [value for _stamp, value in self._data.values()]

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
