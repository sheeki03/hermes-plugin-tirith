from __future__ import annotations

import math

from tirith._state import BoundedStore


def test_size_bound_drops_the_oldest_set():
    store = BoundedStore(max_entries=2)
    store.set("a", 1)
    store.set("b", 2)
    assert store.get("a") == 1  # a plain read does not count as a use
    store.set("c", 3)
    assert store.get("a") is None and store.get("b") == 2 and store.get("c") == 3


def test_refresh_on_get_keeps_an_entry_that_is_read():
    store = BoundedStore(max_entries=2, ttl=math.inf, refresh_on_get=True)
    store.set("active", "/repo")
    for index in range(10):
        store.set(f"other-{index}", "/elsewhere")
        assert store.get("active") == "/repo"  # used between every other set: never the oldest
    assert len(store) == 2


def test_refresh_on_get_restarts_the_age():
    now = [0.0]
    store = BoundedStore(ttl=10.0, clock=lambda: now[0], refresh_on_get=True)
    store.set("k", "v")
    for _ in range(5):
        now[0] += 8.0
        assert store.get("k") == "v"
    now[0] += 11.0
    assert store.get("k") is None


def test_ttl_still_expires_without_reads():
    now = [0.0]
    store = BoundedStore(ttl=10.0, clock=lambda: now[0])
    store.set("k", "v")
    now[0] += 8.0
    assert store.get("k") == "v"
    now[0] += 3.0
    assert store.get("k") is None
