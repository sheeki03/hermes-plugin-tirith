from __future__ import annotations

import functools
import os
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for entry in (str(ROOT), str(TESTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import tirith as plugin  # noqa: E402

PLUGIN_DIR = ROOT / "tirith"
# Test inputs, not tirith settings: kept when the tests clear TIRITH* variables.
TEST_INPUTS = frozenset({"TIRITH_TEST_BIN", "TIRITH_OLD_BIN", "TIRITH_CORPUS_REPORT", "TIRITH_CORPUS_DATA_HOME"})


class RecordingCtx:
    """A stand-in for Hermes's PluginContext: records hooks, serves settings from a dict."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config: dict[str, Any] = dict(config or {})
        self.hooks: dict[str, Any] = {}
        self.get_config_calls = 0

    def register_hook(self, name: str, callback: Any) -> None:
        @functools.wraps(callback)
        def invoke(**kwargs):
            ids = {
                "task_id": "task-1",
                "session_id": "sess-1",
                "turn_id": "t",
                "api_request_id": "r",
                **kwargs,
            }
            return callback(**ids)

        self.hooks[name] = invoke

    def get_config(self, key: str, default: Any = None) -> Any:
        self.get_config_calls += 1
        return self.config.get(key, default)


@pytest.fixture(autouse=True)
def _clean_plugin_state(monkeypatch):
    for key in list(os.environ):
        if key.upper().startswith("TIRITH") and key not in TEST_INPUTS:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("TERMINAL_CWD", raising=False)
    plugin._reset_for_tests()
    yield
    plugin._reset_for_tests()


@pytest.fixture
def ctx_factory():
    def make(**config: Any) -> tuple[RecordingCtx, dict[str, Any]]:
        ctx = RecordingCtx(config)
        plugin.register(ctx)
        return ctx, ctx.hooks

    return make
