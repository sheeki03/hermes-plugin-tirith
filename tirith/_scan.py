"""Run ``tirith check`` on one command and turn the result into a ``ScanOutcome``."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from . import _settings
from ._version import PLUGIN_VERSION, PROCESS_NONCE

MAX_COMMAND_BYTES = 1024 * 1024  # tirith's own stdin cap; larger input fails closed there too
MAX_FINDINGS = 200
CHECK_ARGV = ("check", "--json", "--non-interactive", "--shell", "posix")

# Environment variables that must never reach the child: an agent-visible bypass
# request, a deferred (exit 4) block, and interactive prompting.
STRIPPED_ENV = frozenset({"TIRITH", "TIRITH_DEFER", "TIRITH_INTERACTIVE"})

IS_WINDOWS = os.name == "nt"


@dataclass(frozen=True)
class RunResult:
    rc: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    error: str | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    custom_rule_id: str = ""

    @property
    def key(self) -> str:
        """The id shown to people and used by ``ignore_rules``."""
        if self.custom_rule_id:
            return f"custom_rule_match:{self.custom_rule_id}"
        return self.rule_id


@dataclass(frozen=True)
class ScanOutcome:
    kind: str  # allow | bypass | warn | warn_ack | block | error
    reason: str = ""
    reason_class: str = ""
    rc: int | None = None
    findings: tuple[Finding, ...] = ()
    deferred: bool = False
    binary: str = ""
    version: str = ""
    duration_ms: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)


def error_outcome(reason_class: str, reason: str, **kwargs: Any) -> ScanOutcome:
    return ScanOutcome(kind="error", reason=reason, reason_class=reason_class, **kwargs)


def _kill_tree(proc: subprocess.Popen) -> None:
    if IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def run(argv: list[str], stdin: bytes, cwd: str, env: Mapping[str, str], timeout: float) -> RunResult:
    """Run ``argv`` with ``stdin``; never waits much longer than ``timeout``."""
    kwargs: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": cwd,
        "env": dict(env),
    }
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        kwargs["start_new_session"] = True
    started = time.monotonic()
    try:
        proc = subprocess.Popen(argv, **kwargs)
    except (OSError, ValueError) as exc:
        return RunResult(rc=None, error=f"could not start {os.path.basename(argv[0])}: {exc.__class__.__name__}")
    try:
        stdout, stderr = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=2)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        return RunResult(rc=None, timed_out=True, duration_ms=int((time.monotonic() - started) * 1000))
    except BaseException:
        _kill_tree(proc)
        raise
    return RunResult(
        rc=proc.returncode,
        stdout=stdout or b"",
        stderr=stderr or b"",
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def session_id_for(session_id: str, task_id: str) -> str:
    """A tirith session id (``[A-Za-z0-9_-]``) derived from the Hermes session."""
    seed = session_id or task_id or PROCESS_NONCE
    digest = hashlib.sha256(("tirith-session\0" + seed).encode("utf-8", "surrogatepass")).hexdigest()
    return "hermes-" + digest[:32]


def child_env(
    settings: _settings.Settings,
    *,
    session_id: str = "",
    task_id: str = "",
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The environment for every tirith run (gate probe and scans)."""
    source = os.environ if base is None else base
    env = {key: value for key, value in source.items() if key.upper() not in STRIPPED_ENV}
    env["TIRITH_INTEGRATION"] = "hermes"
    env["TIRITH_INTEGRATION_VERSION"] = PLUGIN_VERSION
    env["TIRITH_SESSION_ID"] = session_id_for(session_id, task_id)
    if IS_WINDOWS:
        # cmd.exe (npm's tirith.cmd shim) must not run programs from the project directory.
        env["NoDefaultCurrentDirectoryInExePath"] = "1"
    if settings.offline:
        for key in [k for k in env if k.upper() == "TIRITH_OFFLINE"]:
            del env[key]
        env["TIRITH_OFFLINE"] = "1"
    return env


def _usable_dir(path: Any) -> str | None:
    if not isinstance(path, str) or not path.strip():
        return None
    expanded = os.path.expanduser(path.strip())
    if not os.path.isabs(expanded):
        return None
    return expanded if os.path.isdir(expanded) else None


def _process_cwd() -> str:
    try:
        return os.getcwd()
    except OSError:
        return tempfile.gettempdir()


def resolve_cwd(args: Mapping[str, Any] | None, tracked_cwd: Any, env: Mapping[str, str] | None = None) -> str:
    """The directory tirith runs in, so repo policy and relative paths match the command.

    Order: the call's ``workdir``; the cwd last reported by this task's terminal results;
    ``TERMINAL_CWD``; the Hermes process cwd. The first existing directory wins.
    """
    source_env = os.environ if env is None else env
    base = _usable_dir(tracked_cwd) or _usable_dir(source_env.get("TERMINAL_CWD")) or _process_cwd()
    workdir = (args or {}).get("workdir") if isinstance(args, Mapping) else None
    if isinstance(workdir, str) and workdir.strip():
        expanded = os.path.expanduser(workdir.strip())
        if not os.path.isabs(expanded):
            expanded = os.path.join(base, expanded)
        if os.path.isdir(expanded):
            return expanded
    return base


def parse_verdict(stdout: str) -> dict[str, Any] | None:
    """The tirith JSON verdict in ``stdout`` (the last JSON object line with action + findings)."""
    candidates = [stdout.strip()] + [line.strip() for line in reversed(stdout.splitlines())]
    for text in candidates:
        if not text.startswith("{"):
            continue
        try:
            value = json.loads(text)
        except ValueError:
            continue
        if isinstance(value, dict) and isinstance(value.get("action"), str) and isinstance(value.get("findings"), list):
            return value
    return None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def normalise_findings(raw: list[Any]) -> tuple[Finding, ...]:
    findings = []
    for item in raw[:MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        rule_id = _text(item.get("rule_id")).strip() or "unknown"
        severity = _text(item.get("severity")).strip().upper()
        if severity not in _settings.SEVERITY_RANK:
            severity = "HIGH"
        title = _text(item.get("title")).strip() or rule_id
        custom = _text(item.get("custom_rule_id")).strip()
        findings.append(Finding(rule_id=rule_id, severity=severity, title=title, custom_rule_id=custom))
    return tuple(findings)


# How strict each kind is, for rc / JSON disagreements.
_STRICTNESS = {"allow": 0, "warn": 1, "warn_ack": 2, "bypass": 2, "error": 3, "block": 4}
_RC_KIND = {0: "allow", 1: "block", 2: "warn", 3: "warn_ack", 4: "block"}
_ACTION_KIND = {"allow": "allow", "warn": "warn", "warn_ack": "warn_ack", "block": "block"}


def classify(result: RunResult, binary: str = "", version: str = "") -> ScanOutcome:
    """Map one tirith run to a ``ScanOutcome`` (see the decision table in the README)."""
    common = {"rc": result.rc, "binary": binary, "version": version, "duration_ms": result.duration_ms}
    if result.error:
        return error_outcome("spawn", result.error, **common)
    if result.timed_out:
        return error_outcome("timeout", "tirith did not answer in time", **common)
    rc = result.rc
    verdict = parse_verdict(result.stdout.decode("utf-8", errors="replace"))
    if verdict is None:
        if rc in _RC_KIND:
            return error_outcome("no_verdict", f"tirith exited with code {rc} without a verdict", **common)
        return error_outcome("exit_code", f"tirith exited with code {rc}", **common)
    findings = normalise_findings(verdict.get("findings") or [])
    action_kind = _ACTION_KIND.get(verdict.get("action", ""), "error")
    if action_kind == "allow" and verdict.get("bypass_honored") is True:
        action_kind = "bypass"
    rc_kind = _RC_KIND.get(rc, "error") if isinstance(rc, int) else "error"
    notes: list[str] = []
    kind = action_kind
    if rc_kind != action_kind and not (rc_kind == "allow" and action_kind == "bypass"):
        kind = rc_kind if _STRICTNESS[rc_kind] > _STRICTNESS[action_kind] else action_kind
        notes.append(f"tirith exit code {rc} and verdict {verdict.get('action')!r} disagree; using {kind}")
    if kind == "error":
        if action_kind == "error":
            reason_class, reason = "verdict", "tirith returned a verdict this plugin does not know"
        else:
            reason_class, reason = "exit_code", f"tirith exited with code {rc}"
        return error_outcome(reason_class, reason, findings=findings, notes=tuple(notes), **common)
    return ScanOutcome(kind=kind, findings=findings, deferred=(rc == 4), notes=tuple(notes), **common)


def encode_command(command: str) -> bytes | ScanOutcome:
    try:
        data = command.encode("utf-8")
    except UnicodeEncodeError:
        return error_outcome("encoding", "the command is not valid text")
    if len(data) > MAX_COMMAND_BYTES:
        return error_outcome("too_large", "the command is too large to check (over 1 MiB)")
    return data


def scan(
    command: str,
    *,
    binary: str,
    version: str,
    cwd: str,
    env: Mapping[str, str],
    timeout: float,
) -> ScanOutcome:
    """Run ``tirith check`` with the command on stdin (never on the command line)."""
    data = encode_command(command)
    if isinstance(data, ScanOutcome):
        return data
    result = run([binary, *CHECK_ARGV], data, cwd, env, timeout)
    return classify(result, binary=binary, version=version)
