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
import re
import sys
import time
from collections.abc import Mapping
from typing import Any

from . import _decide, _input, _locate, _scan, _settings, _state
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
HOOK_MARGIN = 5.0

_LOCATOR = _locate.Locator()
# task id -> cwd reported by the last terminal result. No age limit: Hermes reports the cwd only when a
# command changes it and keeps its own record for the whole session, so this must not expire either.
# Every check of a task reads its entry, which keeps it (LRU): only the task idle longest is dropped
# when more than CWD_TASKS tasks have changed directory.
CWD_TASKS = 4096
_CWD_BY_TASK = _state.BoundedStore(max_entries=CWD_TASKS, ttl=math.inf, refresh_on_get=True)
_SCANNED = _state.BoundedStore()  # scoped hook identity -> checked command/data
_WARN_CONTEXT = _state.BoundedStore()  # scoped hook identity -> warning context
_PROCESS_INPUT = _input.ProcessInput()  # background process -> input typed but not run yet
_PENDING_TERMINAL = _state.BoundedStore()  # scoped hook identity -> (task id, command) from pre to post
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
    _PENDING_TERMINAL.clear()
    _FAIL_OPEN_LIMIT.clear()
    _TIMEOUT_LIMIT.clear()
    _settings._reset_warnings_for_tests()


def _hook_limit() -> float:
    """Hermes's ``plugins.hook_callback_timeout`` in seconds (``inf`` when Hermes sets none).

    Read through Hermes only when Hermes has already loaded it, so nothing is imported on our
    behalf; otherwise, or if that fails, Hermes's default.
    """
    resolve = getattr(sys.modules.get("hermes_cli.plugins"), "_resolve_hook_callback_timeout", None)
    if not callable(resolve):
        return HOOK_LIMIT_DEFAULT
    try:
        limit = float(resolve())
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


# A command word that can move the shell to another directory: cd, pushd, popd, or a sourced script,
# also after NAME=value assignments and the builtin, command [-p] and eval prefixes. It is matched in
# the text with quotes and backslashes removed, since bash runs 'cd', "cd", \cd, c\d, $'cd' and
# eval "cd x" as cd too. A function, alias or variable that changes directory under another name is
# not recognised (README, Limits).
_DIRECTORY_CHANGE = re.compile(
    r"(?:^|[;&|(){}`!\n]|\b(?:then|do|else|elif|if|while|until|time)\s)"
    r"\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    r"(?:(?:builtin|command|eval)(?:\s+-\S*)*\s+)*"
    r"(?:cd|pushd|popd|source|\.)(?=$|[\s;&|)`])"
)
_QUOTED_ASSIGNMENT = re.compile(r"""([A-Za-z_][A-Za-z0-9_]*=)(?:'[^']*'|"(?:[^"\\]|\\.)*")+""")
_DOLLAR_QUOTE = re.compile(r"""\$(?=['"])""")
_UNQUOTE = str.maketrans("", "", "\\'\"")


def _moves_directory(command: str) -> bool:
    """Whether ``command`` may change the shell's directory (a heuristic; see ``_DIRECTORY_CHANGE``)."""
    text = _QUOTED_ASSIGNMENT.sub(r"\1x", command)  # ``X="a b" cd``: one assignment
    return bool(_DIRECTORY_CHANGE.search(_DOLLAR_QUOTE.sub("", text).translate(_UNQUOTE)))


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
) -> tuple[_decide.Decision, _scan.ScanOutcome, str]:
    """Locate and gate tirith, then check ``command``; both end by ``deadline`` (``time.monotonic()``)."""
    cwd = _scan.resolve_cwd(args, _CWD_BY_TASK.get(task_id))
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
    decision = _decide.decide(outcome, settings, command=command, cwd=cwd, session_id=session_id, task_id=task_id)
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
) -> tuple[_decide.Decision, _scan.ScanOutcome]:
    """Something the check depends on is unknown (``error``), but the text was checked as well.

    A refusal stands; otherwise this is a failed check whose prompt lists the findings. With
    ``fail_closed`` off, the check is all there is.
    """
    findings: tuple[_scan.Finding, ...] = ()
    if checked is not None:
        decision, outcome = checked
        if decision.action == "block" or (not settings.fail_closed and outcome.kind != "error"):
            return decision, outcome
        findings = outcome.findings
    failed = _scan.error_outcome(*error, findings=findings)
    cwd = _scan.resolve_cwd(args, _CWD_BY_TASK.get(task_id))
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
) -> tuple[_decide.Decision, _scan.ScanOutcome, str]:
    """Check what a ``process_manage`` write/submit/close completes (``plan.scan``), or fail closed.

    When the plan cannot be checked as text (``plan.error``), the best-known text is still checked:
    a refusal stands, and its findings join the failed-check prompt, whose approval key is tied to
    this process and this text. With ``fail_closed`` off, that check is all there is.
    """
    ids = {"args": args, "task_id": task_id, "session_id": session_id, "deadline": deadline}
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
    )
    return decision, outcome, plan.scan if outcome.kind != "error" and plan.scan is not None else plan.text


def _track_process_input(plan: _input.Plan, input_call_id: object, directive: dict | None) -> None:
    """Finish the pre reservation; an early terminal post must not be overwritten by it."""
    permitted = directive is None or directive.get("action") != "block"
    _PROCESS_INPUT.started(input_call_id, plan.process, plan.keys, permitted=permitted)


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
        ids = {"args": args, "task_id": task_id, "session_id": session_id, "deadline": deadline}
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
                _WARN_CONTEXT.set(call_id, decision.context)
        _log_decision(decision, outcome, command)
        directive = decision.directive()
        if plan is not None:
            _track_process_input(plan, input_call_id, directive)
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
        context = _WARN_CONTEXT.pop(call_id)
        if context and isinstance(result, str):
            return result + context
    except Exception:
        logger.debug("tirith plugin: transform_tool_result failed", exc_info=True)
    return None
