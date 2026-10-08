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

from . import _decide, _input, _locate, _scan, _settings, _state
from ._version import PLUGIN_VERSION

__version__ = PLUGIN_VERSION

logger = logging.getLogger(__name__)

TERMINAL_TOOLS = frozenset({"terminal"})
PROCESS_TOOLS = frozenset({"process_manage", "process"})
WATCHED_TOOLS = TERMINAL_TOOLS | PROCESS_TOOLS

_LOCATOR = _locate.Locator()
_CWD_BY_TASK = _state.BoundedStore()  # task id -> cwd reported by the last terminal result
_SCANNED = _state.BoundedStore()  # tool_call_id -> command (terminal) or data (process) that was checked
_WARN_CONTEXT = _state.BoundedStore()  # tool_call_id -> warning text to append to the result
_PROCESS_INPUT = _input.ProcessInput()  # background process -> input typed but not run yet
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
    _PROCESS_INPUT.clear()
    _FAIL_OPEN_LIMIT.clear()
    _TIMEOUT_LIMIT.clear()
    _settings._reset_warnings_for_tests()


def terminal_command(args: Any) -> str | None:
    """The command a ``terminal`` call runs, or ``None`` when there is nothing to check."""
    if not isinstance(args, Mapping):
        return None
    command = args.get("command")
    return command if isinstance(command, str) and command.strip() else None


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


def check_process_input(
    plan: _input.Plan,
    settings: _settings.Settings,
    *,
    args: Mapping[str, Any],
    task_id: str,
    session_id: str,
) -> tuple[_decide.Decision, _scan.ScanOutcome, str]:
    """Check what a ``process_manage`` write/submit/close completes (``plan.scan``), or fail closed."""
    if plan.scan is not None and plan.error is None:
        decision, outcome, _cwd = check_command(plan.scan, settings, args=args, task_id=task_id, session_id=session_id)
        return decision, outcome, plan.scan
    if plan.error is None:
        return _decide.Decision("none", "allow"), _scan.ScanOutcome(kind="allow"), plan.text  # nothing runs yet
    outcome = _scan.error_outcome(*plan.error)
    cwd = _scan.resolve_cwd(args, _CWD_BY_TASK.get(task_id))
    decision = _decide.decide(outcome, settings, command=plan.text, cwd=cwd, session_id=session_id, task_id=task_id)
    return decision, outcome, plan.text


def _track_process_input(plan: _input.Plan, tool_call_id: str, directive: dict | None) -> None:
    """Count the call's keys as typed unless it is refused outright; its result confirms them."""
    if directive is not None and directive.get("action") == "block":
        return
    if tool_call_id:
        _PROCESS_INPUT.started(tool_call_id, plan.process, plan.keys)
    else:
        _PROCESS_INPUT.record(plan.process, plan.keys, confirmed=directive is None)


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
    plan: _input.Plan | None = None
    call_id = tool_call_id if isinstance(tool_call_id, str) else ""
    try:
        if tool_name in TERMINAL_TOOLS:
            found = terminal_command(args)
            checked = found
        else:
            found = _input.keystrokes(args)
            checked = args.get("data") if found is not None else None
        if found is None:
            return None
        command = found
        if tool_name in PROCESS_TOOLS:
            process = _input.canonical_id(args.get("session_id"))
            if not process:
                return None  # Hermes refuses a write without a process id
            plan = _input.Plan(process, found, found)  # tracked even if a later step fails
        settings = _settings.load(ctx.get_config)
        if plan is not None:
            if not settings.scan_process_input:
                return None
            plan = _PROCESS_INPUT.plan(plan.process, found, eof=_input.ends_input(args)) or plan
            command = plan.text
        _double_scan_check()
        task_id = task_id if isinstance(task_id, str) else ""
        session_id = session_id if isinstance(session_id, str) else ""
        if plan is None:
            decision, outcome, _cwd = check_command(
                command, settings, args=args, task_id=task_id, session_id=session_id
            )
        else:
            decision, outcome, command = check_process_input(
                plan, settings, args=args, task_id=task_id, session_id=session_id
            )
        if call_id:
            _SCANNED.set(call_id, checked)
            if decision.context:
                _WARN_CONTEXT.set(call_id, decision.context)
        _log_decision(decision, outcome, command)
        directive = decision.directive()
        if plan is not None:
            _track_process_input(plan, call_id, directive)
        return directive
    except Exception:
        logger.exception("tirith plugin: internal error while checking a %s call", tool_name)
        try:
            directive = _internal_error(command, settings, str(task_id or ""), str(session_id or ""))
            if plan is not None:
                _track_process_input(plan, call_id, directive)
            return directive
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


def _process_result(args: Any, result: Any, call_id: str, status: Any) -> None:
    if call_id:
        keys = _input.keystrokes(args)
        process = _input.canonical_id(args.get("session_id")) if keys is not None else ""
        _PROCESS_INPUT.finished(call_id, _input.was_written(result, status), process, keys)
    for process in _input.finished_processes(args, result):
        _PROCESS_INPUT.forget(process)


def _on_post_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    tool_call_id: str = "",
    status: Any = None,
    **_kwargs: Any,
) -> None:
    if tool_name not in WATCHED_TOOLS:
        return None
    try:
        call_id = tool_call_id if isinstance(tool_call_id, str) else ""
        scanned = _SCANNED.pop(call_id) if call_id else None
        if tool_name in PROCESS_TOOLS:
            _process_result(args, result, call_id, status)
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
