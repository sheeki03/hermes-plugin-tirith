"""Find the user's tirith and check that it speaks the check contract this plugin needs.

The plugin never downloads, installs or updates tirith. It only runs a binary that is
already on the machine.

Gate: tirith releases before 0.5.0 treat an unknown option before ``--`` as part of the
command to analyse, so a check request can be misread and an attack missed. The gate
sends ``check`` an option no tirith knows (``PROBE_FLAG``) with ``true`` on stdin. A
tirith with the 0.5.0 contract rejects the option with a usage error: exit code 2, no
verdict, and stderr naming the option (``error: unexpected argument '<option>' found``).
An older one analyses the text and prints a verdict: refused as too old. Any other answer
(a crash, another exit code, an error about something else) is not trusted either.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from . import _scan

MIN_TIRITH = (0, 5, 0)
MIN_TIRITH_TEXT = "0.5.0"
PROBE_FLAG = "--hermes-plugin-capability-probe"
USAGE_ERROR_RC = 2  # clap's exit code for a usage error
NEGATIVE_TTL = 60.0
VERSION_TIMEOUT = 5.0
PROBE_TIMEOUT = 10.0  # first call: --version + probe + scan must fit Hermes's 30 s hook budget

_VERSION_RE = re.compile(r"tirith\s+v?(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True)
class GateResult:
    status: str  # ok | too_old | error | not_found
    path: str = ""
    version: str = ""
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _is_windows() -> bool:
    return os.name == "nt"


def _executable(path: str) -> bool:
    return os.path.isfile(path) and (_is_windows() or os.access(path, os.X_OK))


def _names(name: str, env: Mapping[str, str]) -> list[str]:
    if not _is_windows() or os.path.splitext(name)[1]:
        return [name]
    pathext = env.get("PATHEXT") or ".COM;.EXE;.BAT;.CMD"
    return [name + ext.lower() for ext in pathext.split(";") if ext.strip()]


def search_path(name: str, env: Mapping[str, str]) -> str | None:
    """Like ``shutil.which`` but only absolute ``PATH`` entries are searched.

    ``shutil.which`` also searches the current directory on Windows, and an empty or ``.``
    entry means the current directory everywhere. Hermes's current directory is usually the
    project the agent works in, so a ``tirith`` planted there must never be picked up.
    """
    for entry in (env.get("PATH") or "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        for candidate_name in _names(name, env):
            candidate = os.path.join(entry, candidate_name)
            if _executable(candidate):
                return candidate
    return None


def candidates(path_setting: str, env: Mapping[str, str] | None = None) -> list[str]:
    """Executables to try, in order. An explicit ``path`` setting is the only candidate.

    Only absolute locations are used: never anything relative to the current directory.
    """
    source = os.environ if env is None else env
    if path_setting:
        expanded = os.path.expanduser(path_setting)
        if os.path.isabs(expanded):
            return [expanded]
        if os.sep in expanded or (os.altsep is not None and os.altsep in expanded):
            return []  # a relative path would depend on the project directory
        found_on_path = search_path(expanded, source)
        return [found_on_path] if found_on_path else []

    home = os.path.expanduser("~")
    found: list[str] = []
    on_path = search_path("tirith", source)
    if on_path:
        found.append(on_path)
    if _is_windows():
        local = source.get("LOCALAPPDATA", "")
        profile = source.get("USERPROFILE", home)
        appdata = source.get("APPDATA", "")
        extra = [
            os.path.join(local, "tirith", "bin", "tirith.exe") if local else "",
            os.path.join(profile, "scoop", "shims", "tirith.exe"),
            os.path.join(profile, ".cargo", "bin", "tirith.exe"),
            os.path.join(appdata, "npm", "tirith.cmd") if appdata else "",
        ]
        hermes_name = "tirith.exe"
    else:
        extra = [
            "/opt/homebrew/bin/tirith",
            "/usr/local/bin/tirith",
            "/home/linuxbrew/.linuxbrew/bin/tirith",
            os.path.join(home, ".local", "bin", "tirith"),
            os.path.join(home, ".cargo", "bin", "tirith"),
            os.path.join(home, ".nix-profile", "bin", "tirith"),
            "/run/current-system/sw/bin/tirith",
            "/usr/bin/tirith",
        ]
        hermes_name = "tirith"
    hermes_home = source.get("HERMES_HOME") or os.path.join(home, ".hermes")
    extra.append(os.path.join(hermes_home, "bin", hermes_name))  # Hermes <= 0.21.5 kept a copy here
    found.extend(path for path in extra if path and os.path.isabs(path) and _executable(path))

    unique: list[str] = []
    seen: set[str] = set()
    for path in found:
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            unique.append(path)
    return unique


def _parse_version(text: str) -> tuple[tuple[int, int, int] | None, str]:
    match = _VERSION_RE.search(text)
    if not match:
        return None, ""
    parts = tuple(int(group) for group in match.groups())
    return parts, ".".join(str(part) for part in parts)  # type: ignore[return-value]


Runner = Callable[[list, bytes, str, Mapping[str, str], float], "_scan.RunResult"]


def gate(path: str, env: Mapping[str, str], timeout: float, runner: Runner | None = None) -> GateResult:
    """Run ``--version`` and the capability probe against one binary."""
    run = runner or _scan.run
    if not _executable(path):
        return GateResult("not_found", path=path, reason=f"tirith was not found at {path}")
    cwd = tempfile.gettempdir()
    version_run = run([path, "--version"], b"", cwd, env, min(VERSION_TIMEOUT, timeout))
    if version_run.error:
        return GateResult("error", path=path, reason=f"tirith at {path} could not be started")
    if version_run.timed_out:
        return GateResult("error", path=path, reason=f"tirith at {path} did not answer --version in time")
    parsed, version = _parse_version(version_run.stdout.decode("utf-8", errors="replace"))

    probe = run([path, *_scan.CHECK_ARGV, PROBE_FLAG], b"true\n", cwd, env, min(PROBE_TIMEOUT, timeout))
    if probe.error:
        return GateResult("error", path=path, version=version, reason=f"tirith at {path} could not be started")
    if probe.timed_out:
        return GateResult("error", path=path, version=version, reason=f"tirith at {path} did not answer in time")
    swallowed = probe.rc == 0 or _scan.parse_verdict(probe.stdout.decode("utf-8", errors="replace")) is not None
    if swallowed:
        shown = version or "(unknown version)"
        return GateResult(
            "too_old",
            path=path,
            version=version,
            reason=(
                f"tirith {shown} at {path} is older than {MIN_TIRITH_TEXT}; older releases can mis-read a "
                "check request and miss attacks. Upgrade tirith (for example: brew upgrade tirith)"
            ),
        )
    rejected = probe.rc == USAGE_ERROR_RC and PROBE_FLAG in probe.stderr.decode("utf-8", errors="replace")
    if not rejected:
        return GateResult(
            "error",
            path=path,
            version=version,
            reason=(
                f"tirith at {path} gave an unexpected answer to the plugin's capability check "
                f"(exit code {probe.rc}, expected a usage error for {PROBE_FLAG})"
            ),
        )
    note = ""
    if parsed is not None and parsed < MIN_TIRITH:
        note = f"pre-release build with the {MIN_TIRITH_TEXT} check contract"
    return GateResult("ok", path=path, version=version, reason=note)


class Locator:
    """Finds and gates tirith, caching results per binary (by size and mtime)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, runner: Runner | None = None):
        self._clock = clock
        self._runner = runner
        self._cache: dict[str, tuple[int, int, float, GateResult]] = {}
        self._lock = threading.Lock()
        self._gate_lock = threading.Lock()

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def _stat(self, path: str) -> tuple[str, int, int] | None:
        try:
            real = os.path.realpath(path)
            info = os.stat(real)
        except OSError:
            return None
        return real, info.st_size, info.st_mtime_ns

    def _cached(self, path: str) -> GateResult | None:
        stat = self._stat(path)
        if stat is None:
            return None
        real, size, mtime = stat
        with self._lock:
            entry = self._cache.get(real)
        if entry is None:
            return None
        c_size, c_mtime, stamp, result = entry
        if (c_size, c_mtime) != (size, mtime):
            return None
        if not result.ok and self._clock() - stamp > NEGATIVE_TTL:
            return None
        return GateResult(result.status, path=path, version=result.version, reason=result.reason)

    def check(self, path: str, env: Mapping[str, str], timeout: float) -> GateResult:
        cached = self._cached(path)
        if cached is not None:
            return cached
        with self._gate_lock:
            cached = self._cached(path)
            if cached is not None:
                return cached
            before = self._stat(path)
            result = gate(path, env, timeout, runner=self._runner)
            after = self._stat(path)
            if result.status in ("ok", "too_old") and before is not None and before == after:
                real, size, mtime = before
                with self._lock:
                    self._cache[real] = (size, mtime, self._clock(), result)
            return result

    def resolve(self, path_setting: str, env: Mapping[str, str], timeout: float) -> GateResult:
        """The first candidate that passes the gate, else the first candidate's failure."""
        paths = candidates(path_setting, env)
        if not paths and path_setting:
            return GateResult(
                "not_found",
                reason=(
                    f"tirith was not found at the configured path {path_setting!r} "
                    "(use an absolute path, or a program name found on PATH)"
                ),
            )
        if not paths:
            return GateResult(
                "not_found",
                reason=(
                    "tirith was not found (looked on PATH and in the usual install folders). "
                    f"Install tirith {MIN_TIRITH_TEXT} or later, or set the plugin's path setting"
                ),
            )
        first: GateResult | None = None
        for path in paths:
            result = self.check(path, env, timeout)
            if result.ok:
                return result
            if first is None:
                first = result
        assert first is not None
        return first
