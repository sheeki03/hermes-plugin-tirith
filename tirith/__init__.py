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
import math
import os
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any

from . import _cd, _decide, _input, _locate, _scan, _settings, _state
from ._version import PLUGIN_VERSION

__version__ = PLUGIN_VERSION

logger = logging.getLogger(__name__)

TERMINAL_TOOLS = frozenset({"terminal"})
PROCESS_TOOLS = frozenset({"process_manage", "process"})
WATCHED_TOOLS = TERMINAL_TOOLS | PROCESS_TOOLS

# Hermes stops waiting for a pre_tool_call callback after plugins.hook_callback_timeout (30 s by default),
# blocks the call, and then skips this callback for 60 s, which blocks every tool. Each hook call
# therefore finishes its gate and check HOOK_MARGIN seconds (at most half the limit) before that limit;
# a check stopped there asks for approval like any failed check.
HOOK_LIMIT_DEFAULT = 30.0
HOOK_LIMIT_MAX = 600.0  # Hermes clamps plugins.hook_callback_timeout to this
HOOK_MARGIN = 5.0
INCOMPLETE_RULE = "analysis_incomplete"  # tirith could not analyse part of the command

_LOCATOR = _locate.Locator()
# task id -> cwd reported by the last terminal result. No age limit: Hermes reports the cwd only when a
# command changes it and keeps its own record for the whole session, so this must not expire either.
# Every check of a task reads its entry, which keeps it (LRU): only the task idle longest is dropped
# when more than CWD_TASKS tasks have changed directory.
CWD_TASKS = 4096
_CWD_BY_TASK = _state.BoundedStore(max_entries=CWD_TASKS, ttl=math.inf, refresh_on_get=True)
_SCANNED = _state.BoundedStore()  # scoped hook identity -> checked command/data
_WARN_CONTEXT = _state.BoundedStore()  # scoped hook identity -> (warning context, session, session notes)
# (session, rule id) -> True once that session's agent was shown the note for a _decide.SESSION_NOTE_RULES
# warning. Dropping an entry (more than 4096 sessions) only shows the note once more.
_SESSION_NOTES = _state.BoundedStore(max_entries=4096, ttl=math.inf, refresh_on_get=True)
_PROCESS_INPUT = _input.ProcessInput()  # background process -> input typed but not run yet
_PENDING_TERMINAL = _state.BoundedStore()  # scoped hook identity -> (task id, command) from pre to post
_FAIL_OPEN_LIMIT = _state.RateLimiter(60.0)
_TIMEOUT_LIMIT = _state.RateLimiter(60.0)


def _session_cwd(ctx: Any) -> Any:
    """The calling session's directory as Hermes reports it (``ctx.session_cwd()``), or None.

    From Hermes 0.22.3 the CLI, TUI and Desktop are clients of the gateway, and plugin hooks run in
    the gateway process: its own cwd is not the session's, and the session's ``TERMINAL_CWD`` is kept
    per turn, outside ``os.environ``. Hermes 0.22.2 and earlier have no such method. Never raises.
    """
    try:
        method = getattr(ctx, "session_cwd", None)
        return method() if callable(method) else None
    except Exception:
        return None


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", functools.partial(_on_pre_tool_call, ctx))
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)


def _reset_for_tests() -> None:
    _LOCATOR.clear()
    _CWD_BY_TASK.clear()
    _SCANNED.clear()
    _WARN_CONTEXT.clear()
    _SESSION_NOTES.clear()
    _PROCESS_INPUT.clear()
    _PENDING_TERMINAL.clear()
    _FAIL_OPEN_LIMIT.clear()
    _TIMEOUT_LIMIT.clear()
    _settings._reset_warnings_for_tests()


def _configured_hook_limit() -> float:
    """``plugins.hook_callback_timeout`` from Hermes's config, read and clamped as Hermes does.

    For a plugin host process (``plugins.isolation: host``), where Hermes's package runs but its plugin
    manager need not be loaded (it is not on 0.22.5), while the Hermes process that started the host
    enforces this setting. Hermes's config module is imported only when Hermes's package is already
    loaded; otherwise Hermes's default.
    """
    if "hermes_cli" not in sys.modules:
        return HOOK_LIMIT_DEFAULT
    plugins = (importlib.import_module("hermes_cli.config").load_config_readonly() or {}).get("plugins")
    if not isinstance(plugins, Mapping) or plugins.get("hook_callback_timeout") is None:
        return HOOK_LIMIT_DEFAULT
    limit = float(plugins["hook_callback_timeout"])
    if limit < 0:
        return HOOK_LIMIT_DEFAULT
    return min(limit, HOOK_LIMIT_MAX)


def _hook_limit() -> float:
    """Hermes's ``plugins.hook_callback_timeout`` in seconds (``inf`` when Hermes sets none).

    Read through Hermes's own resolver when Hermes has loaded it, else from Hermes's config in a
    plugin host process (``_configured_hook_limit``); nothing is imported outside Hermes. Otherwise,
    or if that fails, Hermes's default.
    """
    resolve = getattr(sys.modules.get("hermes_cli.plugins"), "_resolve_hook_callback_timeout", None)
    try:
        limit = float(resolve()) if callable(resolve) else _configured_hook_limit()
    except Exception:
        return HOOK_LIMIT_DEFAULT
    if math.isnan(limit):
        return HOOK_LIMIT_DEFAULT
    return limit if limit > 0 else math.inf  # 0 or less: Hermes runs the callback without a time limit


def _hook_budget(limit: float) -> float:
    """How long one hook call may spend on the gate and the check."""
    return limit - min(HOOK_MARGIN, limit / 2)


def _warn_timeout_budget(timeout: int, limit: float) -> None:
    longest = _hook_budget(limit) - _scan.KILL_GRACE
    if timeout > longest:
        _settings.warn_once(
            f"tirith plugin: timeout={timeout} s does not fit Hermes's hook time limit "
            f"(plugins.hook_callback_timeout={limit:g} s): checks are stopped after about {max(longest, 0):.0f} s "
            "and then ask for approval"
        )


def terminal_command(args: Any) -> str | None:
    """The command a ``terminal`` call runs, or ``None`` when there is nothing to check."""
    if not isinstance(args, Mapping):
        return None
    command = args.get("command")
    return command if isinstance(command, str) and command.strip() else None


@functools.lru_cache(maxsize=256)
def _moves_directory(command: str) -> bool:
    """Whether ``command`` may change the shell's directory (a heuristic; see ``_cd``).

    Hermes Desktop checks every pending earlier command again for each later one: cached.
    """
    return _cd.moves_directory(command)


_CWD_PENDING = (
    "cwd_pending",
    "an earlier terminal command that can change directory has not run yet, so the directory this "
    "command will run in is not known",
)


def _absolute_workdir(args: Any) -> bool:
    workdir = args.get("workdir") if isinstance(args, Mapping) else None
    return isinstance(workdir, str) and bool(workdir.strip()) and os.path.isabs(os.path.expanduser(workdir.strip()))


def _directory_in_doubt(args: Any, task_id: str) -> bool:
    """Whether an earlier terminal command of this task may move the directory before this one runs.

    Hermes runs terminal commands one at a time, but Hermes Desktop's terminal-approval batching
    runs ``pre_tool_call`` for adjacent terminal calls before the earlier ones run, so the
    directory a ``cd`` in an earlier call moves to is not known yet.
    """
    if _absolute_workdir(args):
        return False
    return any(task == task_id and _moves_directory(command) for task, command in _PENDING_TERMINAL.values())


def _ask_while_directory_unknown(
    decision: _decide.Decision,
    outcome: _scan.ScanOutcome,
    settings: _settings.Settings,
    *,
    command: str,
    cwd: str,
    task_id: str,
    session_id: str,
) -> tuple[_decide.Decision, _scan.ScanOutcome]:
    """tirith checked the command in ``cwd``, but an earlier batched command may change directory first.

    A refusal stands, and a failed check already asks with its own reason. Otherwise ask, showing
    tirith's verdict in ``cwd``. With ``fail_closed`` off, the check is all there is.
    """
    if decision.action == "block" or outcome.kind == "error" or not settings.fail_closed:
        return decision, outcome
    pending = _scan.error_outcome(
        *_CWD_PENDING,
        findings=outcome.findings,
        notes=outcome.notes,
        deferred=outcome.deferred,
        rc=outcome.rc,
        binary=outcome.binary,
        version=outcome.version,
        duration_ms=outcome.duration_ms,
    )
    asked = _decide.cwd_pending(
        outcome, decision, settings, command=command, cwd=cwd, session_id=session_id, task_id=task_id
    )
    return asked, pending


def _double_scan_check() -> None:
    # Hermes 0.21.5 still runs its built-in tirith check. Only look when Hermes's
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
                logger.warning("tirith plugin: %s", outcome.reason)
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
    deadline: float | None = None,
    session_cwd: Callable[[], Any] | None = None,
) -> tuple[_decide.Decision, _scan.ScanOutcome, str]:
    """Locate and gate tirith, then check ``command``; both end by ``deadline`` (``time.monotonic()``).

    ``session_cwd`` asks Hermes for the session's directory (see ``_scan.resolve_cwd``).
    """
    cwd = _scan.resolve_cwd(args, _CWD_BY_TASK.get(task_id), session_cwd=session_cwd)
    env = _scan.child_env(settings, session_id=session_id, task_id=task_id)
    located = _LOCATOR.resolve(settings.path, env, settings.timeout, deadline)
    if not located.ok:
        outcome = _scan.error_outcome(located.status, located.reason, binary=located.path, version=located.version)
    else:
        if located.reason:
            _settings.warn_once(f"tirith plugin: using tirith {located.version} at {located.path}: {located.reason}")
        outcome = _scan.scan(
            command,
            binary=located.path,
            version=located.version,
            cwd=cwd,
            env=env,
            timeout=settings.timeout,
            deadline=deadline,
        )
    scope = session_id or task_id
    noted = frozenset(rule for rule in _decide.SESSION_NOTE_RULES if _SESSION_NOTES.get((scope, rule)))
    decision = _decide.decide(
        outcome, settings, command=command, cwd=cwd, session_id=session_id, task_id=task_id, noted=noted
    )
    return decision, outcome, cwd


def _fail_closed_after_check(
    checked: tuple[_decide.Decision, _scan.ScanOutcome] | None,
    error: tuple[str, str],
    settings: _settings.Settings,
    *,
    command: str,
    args: Mapping[str, Any] | None,
    task_id: str,
    session_id: str,
    scope: str = "",
    session_cwd: Callable[[], Any] | None = None,
) -> tuple[_decide.Decision, _scan.ScanOutcome]:
    """Something the check depends on is unknown (``error``), but the text was checked as well.

    A refusal stands; otherwise this is a failed check whose prompt lists the findings. With
    ``fail_closed`` off, the check is all there is, and a check that tirith marked as needing
    approval (exit code 3 without a usable verdict) still asks.
    """
    findings: tuple[_scan.Finding, ...] = ()
    requires_approval = False
    if checked is not None:
        decision, outcome = checked
        if decision.action == "block" or (not settings.fail_closed and outcome.kind != "error"):
            return decision, outcome
        findings = outcome.findings
        requires_approval = outcome.requires_approval or outcome.kind == "warn_ack"
    failed = _scan.error_outcome(*error, findings=findings, requires_approval=requires_approval)
    cwd = _scan.resolve_cwd(args, _CWD_BY_TASK.get(task_id), session_cwd=session_cwd)
    decision = _decide.decide(
        failed, settings, command=command, cwd=cwd, session_id=session_id, task_id=task_id, scope=scope
    )
    return decision, failed


def check_process_input(
    plan: _input.Plan,
    settings: _settings.Settings,
    *,
    args: Mapping[str, Any],
    task_id: str,
    session_id: str,
    deadline: float | None = None,
    session_cwd: Callable[[], Any] | None = None,
) -> tuple[_decide.Decision, _scan.ScanOutcome, str]:
    """Check what a ``process_manage`` write/submit/close completes (``plan.scan``), or fail closed.

    When the plan cannot be checked as text (``plan.error``), the best-known text is still checked:
    a refusal stands, and its findings join the failed-check prompt, whose approval key is tied to
    this process and this text. With ``fail_closed`` off, that check is all there is.
    """
    ids = {"args": args, "task_id": task_id, "session_id": session_id, "deadline": deadline, "session_cwd": session_cwd}
    if plan.error is None:
        if plan.scan is None:
            return _decide.Decision("none", "allow"), _scan.ScanOutcome(kind="allow"), plan.text  # nothing runs yet
        decision, outcome, _cwd = check_command(plan.scan, settings, **ids)
        return decision, outcome, plan.scan
    checked = None
    if plan.scan is not None:
        decision, outcome, _cwd = check_command(plan.scan, settings, **ids)
        checked = (decision, outcome)
    decision, outcome = _fail_closed_after_check(
        checked,
        plan.error,
        settings,
        command=plan.text,
        args=args,
        task_id=task_id,
        session_id=session_id,
        scope=plan.process,
        session_cwd=session_cwd,
    )
    return decision, outcome, plan.scan if outcome.kind != "error" and plan.scan is not None else plan.text


def _track_process_input(
    plan: _input.Plan, input_call_id: object, directive: dict | None, outcome: _scan.ScanOutcome | None = None
) -> None:
    """Finish the pre reservation; an early terminal post must not be overwritten by it.

    When tirith could not analyse the text (``analysis_incomplete``) and the call runs, the next line
    of that process is checked together with it.
    """
    permitted = directive is None or directive.get("action") != "block"
    incomplete = outcome is not None and any(f.rule_id == INCOMPLETE_RULE for f in outcome.findings)
    _PROCESS_INPUT.started(input_call_id, plan.process, plan.keys, permitted=permitted, incomplete=incomplete)


def _internal_error(command: str, settings: _settings.Settings, task_id: str, session_id: str) -> dict | None:
    outcome = _scan.error_outcome("internal", "the tirith plugin hit an internal error")
    decision = _decide.decide(outcome, settings, command=command, cwd="", session_id=session_id, task_id=task_id)
    return decision.directive()


def _hook_call_id(call_id: Any, task_id: Any, session_id: Any, metadata: Mapping[str, Any]) -> tuple[str, ...] | None:
    if not isinstance(call_id, str) or not call_id:
        return None
    # Providers may reuse a tool-call id in later responses or delegated tasks.
    # Hermes carries these same scope fields through pre, post and transform.
    return tuple(
        value if isinstance(value, str) else ""
        for value in (session_id, task_id, metadata.get("turn_id"), metadata.get("api_request_id"), call_id)
    )


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
    started = time.monotonic()
    settings = _settings.Settings()  # defaults (fail closed) until the user's settings are read
    command = ""
    plan: _input.Plan | None = None
    call_id = _hook_call_id(tool_call_id, task_id, session_id, _kwargs)
    input_call_id = call_id if call_id is not None else object()
    task_id = task_id if isinstance(task_id, str) else ""
    session_id = session_id if isinstance(session_id, str) else ""
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
        in_doubt = False
        if tool_name in TERMINAL_TOOLS:
            in_doubt = _directory_in_doubt(args, task_id)
            if call_id and not args.get("workdir"):
                _PENDING_TERMINAL.set(call_id, (task_id, found))  # until its post_tool_call
        if tool_name in PROCESS_TOOLS:
            process = _input.canonical_id(args.get("session_id"))
            if not process:
                return None  # Hermes refuses a write without a process id
            plan = _input.Plan(process, found, found)  # tracked even if a later step fails
        settings = _settings.load(ctx.get_config)
        if plan is not None:
            if not settings.scan_process_input:
                return None
            plan = _PROCESS_INPUT.plan(plan.process, found, eof=_input.ends_input(args), call_id=input_call_id) or plan
            command = plan.text
        _double_scan_check()
        limit = _hook_limit()
        _warn_timeout_budget(settings.timeout, limit)
        budget = _hook_budget(limit)
        deadline = None if math.isinf(budget) else started + budget
        ids = {
            "args": args,
            "task_id": task_id,
            "session_id": session_id,
            "deadline": deadline,
            "session_cwd": functools.partial(_session_cwd, ctx),
        }
        if plan is None:
            decision, outcome, cwd = check_command(command, settings, **ids)
            if in_doubt:
                decision, outcome = _ask_while_directory_unknown(
                    decision, outcome, settings, command=command, cwd=cwd, task_id=task_id, session_id=session_id
                )
        else:
            decision, outcome, command = check_process_input(plan, settings, **ids)
        if call_id:
            _SCANNED.set(call_id, checked)
            if decision.context:
                _WARN_CONTEXT.set(call_id, (decision.context, session_id or task_id, decision.notes))
        _log_decision(decision, outcome, command)
        directive = decision.directive()
        if plan is not None:
            _track_process_input(plan, input_call_id, directive, outcome)
        return directive
    except Exception:
        logger.exception("tirith plugin: internal error while checking a %s call", tool_name)
        try:
            directive = _internal_error(command, settings, task_id, session_id)
            if plan is not None:
                _track_process_input(plan, input_call_id, directive)
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


def _process_result(args: Any, result: Any, call_id: object | None, status: Any) -> None:
    keys = _input.keystrokes(args)
    if call_id and keys is not None:
        process = _input.canonical_id(args.get("session_id"))
        _PROCESS_INPUT.finished(call_id, _input.was_written(result, status), process, keys)
    for process in _input.finished_processes(args, result):
        _PROCESS_INPUT.forget(process)


def _on_post_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    status: Any = None,
    **_kwargs: Any,
) -> None:
    if tool_name not in WATCHED_TOOLS:
        return None
    try:
        call_id = _hook_call_id(tool_call_id, task_id, session_id, _kwargs)
        scanned = _SCANNED.pop(call_id) if call_id else None
        if call_id and tool_name in TERMINAL_TOOLS:
            _PENDING_TERMINAL.pop(call_id)
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
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_kwargs: Any,
) -> str | None:
    call_id = _hook_call_id(tool_call_id, task_id, session_id, _kwargs)
    if tool_name not in WATCHED_TOOLS or call_id is None:
        return None
    try:
        entry = _WARN_CONTEXT.pop(call_id)
        if entry and isinstance(result, str):
            context, scope, notes = entry
            for rule in notes:  # the agent has now seen the explanation; later repeats are left out
                _SESSION_NOTES.set((scope, rule), True)
            return result + context
    except Exception:
        logger.debug("tirith plugin: transform_tool_result failed", exc_info=True)
    return None
