from __future__ import annotations

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
from tirith import _locate  # noqa: E402

PLUGIN_DIR = ROOT / "tirith"
# Tests are about decisions, not speed: on a loaded machine a fake or debug tirith can take seconds to
# start. Tests about timeouts set their own short timeout and a slow fake.
TEST_TIMEOUT = 25  # the largest timeout the plugin accepts without a warning
TEST_GATE_LIMITS = {"VERSION_TIMEOUT": 60.0, "PROBE_TIMEOUT": 60.0, "GATE_BUDGET": 180.0}
# Test inputs, not tirith settings: kept when the tests clear TIRITH* variables.
TEST_INPUTS = frozenset(
    {"TIRITH_TEST_BIN", "TIRITH_OLD_BIN", "TIRITH_NO_APPROVAL_BIN", "TIRITH_CORPUS_REPORT", "TIRITH_CORPUS_DATA_HOME"}
)


class RecordingCtx:
    """A stand-in for Hermes's PluginContext: records hooks, serves settings from a dict."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config: dict[str, Any] = dict(config or {})
        self.hooks: dict[str, Any] = {}
        self.get_config_calls = 0

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback  # called with exactly the ids a test passes, like Hermes does

    def get_config(self, key: str, default: Any = None) -> Any:
        self.get_config_calls += 1
        return self.config.get(key, default)


@pytest.fixture(autouse=True)
def _clean_plugin_state(monkeypatch):
    for key in list(os.environ):
        if key.upper().startswith("TIRITH") and key not in TEST_INPUTS:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("TERMINAL_CWD", raising=False)
    for name, value in TEST_GATE_LIMITS.items():
        monkeypatch.setattr(_locate, name, value)
    plugin._reset_for_tests()
    yield
    plugin._reset_for_tests()


@pytest.fixture
def ctx_factory():
    def make(**config: Any) -> tuple[RecordingCtx, dict[str, Any]]:
        config.setdefault("timeout", TEST_TIMEOUT)
        ctx = RecordingCtx(config)
        plugin.register(ctx)
        return ctx, ctx.hooks

    return make
