"""Plugin version and the per-process nonce used to salt session-only approval keys."""

from __future__ import annotations

import os

PLUGIN_VERSION = "0.1.0"  # must match plugin.yaml (tests/test_manifest.py)

# Random per Hermes process. Salted approval keys include it, so an "Always" answer for a
# blocked command or a failed check can never match again after Hermes restarts.
PROCESS_NONCE = os.urandom(16).hex()
