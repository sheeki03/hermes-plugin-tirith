"""Hermes plugin: check terminal commands with the user's installed tirith before they run.

``register()`` only registers hooks. The binary is located and gated lazily on the first
hook call, never at import or registration time.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import logging
import sys
from collections.abc import Mapping
from typing import Any

from . import _decide, _locate, _scan, _settings, _state
from ._version import PLUGIN_VERSION

__version__ = PLUGIN_VERSION

logger = logging.getLogger(__name__)

TERMINAL_TOOLS = frozenset({"terminal"})
PROCESS_TOOLS = frozenset({"process_manage", "process"})
WATCHED_TOOLS = TERMINAL_TOOLS | PROCESS_TOOLS

_LOCATOR = _locate.Locator()
_CWD_BY_TASK = _state.BoundedStore()  # task id -> cwd reported by the last terminal result
_SCANNED = _state.BoundedStore()  # tool_call_id -> command text that tirith checked
_WARN_CONTEXT = _state.BoundedStore()  # tool_call_id -> warning text to append to the result
_FAIL_OPEN_LIMIT = _state.RateLimiter(60.0)
_TIMEOUT_LIMIT = _state.RateLimiter(60.0)


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", functools.partial(_on_pre_tool_call, ctx))
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)


def _reset_for_tests() -> None:
    _LOCATOR.clear()
    _CWD_BY_TASK.clear()
    _SCANNED.clear()
    _WARN_CONTEXT.clear()
    _FAIL_OPEN_LIMIT.clear()
    _TIMEOUT_LIMIT.clear()
    _settings._reset_warnings_for_tests()


def _has_text(value: str) -> bool:
    return any(not (ch.isspace() or ord(ch) < 32 or ord(ch) == 127) for ch in value)


def command_to_check(tool_name: str, args: Any, settings: _settings.Settings) -> str | None:
    """The shell input this tool call would run, or ``None`` when there is nothing to check."""
    if not isinstance(args, Mapping):
        return None
    if tool_name in TERMINAL_TOOLS:
        command = args.get("command")
        return command if isinstance(command, str) and command.strip() else None
    if tool_name in PROCESS_TOOLS and settings.scan_process_input:
        action = args.get("action")
        data = args.get("data")
        if not isinstance(data, str) or not _has_text(data):
            return None
        if action == "submit" or (action == "write" and ("\n" in data or "\r" in data)):
            return data
    return None


def _double_scan_check() -> None:
    # Hermes 0.21.5 and earlier also run a built-in tirith check. Only look when Hermes's
    # own ``tools`` package is already loaded, so nothing is imported on our behalf.
    if "tools" not in sys.modules:
        return
    try:
        present = importlib.util.find_spec("tools.tirith_security") is not None
    except (ImportError, ValueError):
        present = False
    if present:
        _settings.warn_once(
            "tirith plugin: this Hermes still has its built-in tirith check, so commands may be checked twice. "
            "Turn the built-in one off with: hermes config set security.tirith_enabled false"
        )


def _command_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def _log_decision(decision: _decide.Decision, outcome: _scan.ScanOutcome, command: str) -> None:
    for note in outcome.notes:
        _settings.warn_once(f"tirith plugin: {note}")
    if outcome.deferred:
        _settings.warn_once(
            "tirith plugin: tirith returned a deferred block (exit 4); treated as a block. "
            "Check your tirith policy for defer settings"
        )
    if outcome.kind == "error":
        if outcome.reason_class == "timeout":
            if _TIMEOUT_LIMIT.allow("timeout"):
                logger.warning("tirith plugin: tirith did not answer within the timeout setting")
        elif outcome.reason_class in ("not_found", "too_old", "spawn"):
            _settings.warn_once(f"tirith plugin: {outcome.reason}")
        if decision.action == "none" and _FAIL_OPEN_LIMIT.allow("fail-open"):
            logger.warning(
                "tirith plugin: a command ran without a tirith check because fail_closed is off (%s)", outcome.reason
            )
    if decision.action != "none" or decision.context:
        logger.info(
            "tirith plugin: kind=%s action=%s rules=%s key=%s cmd_sha=%s rc=%s ms=%s",
            outcome.kind,
            decision.action if decision.action != "none" else "allow+context",
            ",".join(sorted({f.key for f in outcome.findings})) or "-",
            decision.rule_key[:40] or "-",
            _command_hash(command),
            outcome.rc,
            outcome.duration_ms,
        )
    logger.debug(
        "tirith plugin: binary=%s version=%s kind=%s rc=%s ms=%s",
        outcome.binary,
        outcome.version,
        outcome.kind,
        outcome.rc,
        outcome.duration_ms,
    )


def check_command(
    command: str,
    settings: _settings.Settings,
    *,
    args: Mapping[str, Any] | None,
    task_id: str,
    session_id: str,
) -> tuple[_decide.Decision, _scan.ScanOutcome, str]:
    cwd = _scan.resolve_cwd(args, _CWD_BY_TASK.get(task_id))
    env = _scan.child_env(settings, session_id=session_id, task_id=task_id)
    located = _LOCATOR.resolve(settings.path, env, settings.timeout)
    if not located.ok:
        outcome = _scan.error_outcome(located.status, located.reason, binary=located.path, version=located.version)
    else:
        if located.reason:
            _settings.warn_once(f"tirith plugin: using tirith {located.version} at {located.path}: {located.reason}")
        outcome = _scan.scan(
            command, binary=located.path, version=located.version, cwd=cwd, env=env, timeout=settings.timeout
        )
    decision = _decide.decide(outcome, settings, command=command, cwd=cwd, session_id=session_id, task_id=task_id)
    return decision, outcome, cwd


def _internal_error(command: str, settings: _settings.Settings, task_id: str, session_id: str) -> dict | None:
    outcome = _scan.error_outcome("internal", "the tirith plugin hit an internal error")
    decision = _decide.decide(outcome, settings, command=command, cwd="", session_id=session_id, task_id=task_id)
    return decision.directive()


def _on_pre_tool_call(
    ctx: Any,
    *,
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_kwargs: Any,
) -> dict | None:
    if tool_name not in WATCHED_TOOLS:
        return None
    settings = _settings.Settings()  # defaults (fail closed) until the user's settings are read
    command = ""
    try:
        found = command_to_check(tool_name, args, settings)
        if found is None:
            return None
        command = found
        settings = _settings.load(ctx.get_config)
        if command_to_check(tool_name, args, settings) is None:
            return None  # scan_process_input is off
        _double_scan_check()
        task_id = task_id if isinstance(task_id, str) else ""
        session_id = session_id if isinstance(session_id, str) else ""
        decision, outcome, _cwd = check_command(command, settings, args=args, task_id=task_id, session_id=session_id)
        if isinstance(tool_call_id, str) and tool_call_id:
            _SCANNED.set(tool_call_id, command)
            if decision.context:
                _WARN_CONTEXT.set(tool_call_id, decision.context)
        _log_decision(decision, outcome, command)
        return decision.directive()
    except Exception:
        logger.exception("tirith plugin: internal error while checking a %s call", tool_name)
        try:
            return _internal_error(command, settings, str(task_id or ""), str(session_id or ""))
        except Exception:
            return {"action": "block", "message": "BLOCKED: the tirith plugin failed while checking this command."}


def _result_cwd(result: Any) -> str | None:
    if not isinstance(result, str) or '"cwd"' not in result:
        return None
    try:
        parsed = json.loads(result)
    except ValueError:
        return None
    cwd = parsed.get("cwd") if isinstance(parsed, dict) else None
    return cwd if isinstance(cwd, str) and cwd else None


def _on_post_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    tool_call_id: str = "",
    **_kwargs: Any,
) -> None:
    if tool_name not in WATCHED_TOOLS:
        return None
    try:
        scanned = _SCANNED.pop(tool_call_id) if isinstance(tool_call_id, str) and tool_call_id else None
        if not isinstance(args, Mapping):
            return None
        if scanned is not None:
            executed = args.get("command") if tool_name in TERMINAL_TOOLS else args.get("data")
            if executed != scanned:
                _settings.warn_once(
                    "tirith plugin: another plugin changed a command after tirith checked it; "
                    "the changed command was not checked"
                )
        if tool_name in TERMINAL_TOOLS and not args.get("workdir"):
            cwd = _result_cwd(result)
            if cwd is not None:
                _CWD_BY_TASK.set(task_id if isinstance(task_id, str) else "", cwd)
    except Exception:
        logger.debug("tirith plugin: post_tool_call bookkeeping failed", exc_info=True)
    return None


def _on_transform_tool_result(
    *,
    tool_name: str = "",
    result: Any = None,
    tool_call_id: str = "",
    **_kwargs: Any,
) -> str | None:
    if tool_name not in WATCHED_TOOLS or not isinstance(tool_call_id, str) or not tool_call_id:
        return None
    try:
        context = _WARN_CONTEXT.pop(tool_call_id)
        if context and isinstance(result, str):
            return result + context
    except Exception:
        logger.debug("tirith plugin: transform_tool_result failed", exc_info=True)
    return None
