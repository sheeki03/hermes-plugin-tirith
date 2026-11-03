"""Turn a ``ScanOutcome`` into a Hermes ``pre_tool_call`` directive.

Defaults: allow runs; warn runs with tirith's warning appended to the result; a block asks
a person through Hermes's approval prompt; a CRITICAL finding is refused; a failed check
asks a person (fail closed). The plugin itself never approves anything.
"""

from __future__ import annotations

import hashlib
import json
import os
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from . import _settings
from ._scan import Finding, ScanOutcome
from ._version import PROCESS_NONCE

MAX_MESSAGE = 700
MAX_EXCERPT = 200
MAX_TITLE = 120
MAX_LISTED = 5
SALTED_KINDS = frozenset({"approval", "block", "bypass", "error"})
# Warnings about tirith's own coverage rather than the command, which would otherwise be appended to the
# result of many package installs (tirith's short lookup time budget ran out, a lookup service returned
# an error or is out of reach, tirith's offline mode, and no cached answer).
# With warn_action allow the first one in a session is shown with an explanation; later ones in that
# session are left out of the appended warning. They still count everywhere else (prompts, blocks).
SESSION_NOTE_RULES = frozenset({"package_lookup_incomplete"})
# The TIRITH_OFFLINE values tirith reads as on (offline_env_active in its CLI). child_env passes a
# TIRITH_OFFLINE from Hermes's environment on to tirith when the offline setting is off.
_OFFLINE_ON = frozenset({"1", "true", "yes", "on"})

_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})


@dataclass(frozen=True)
class Decision:
    action: str  # none | approve | block
    kind: str
    message: str = ""
    rule_key: str = ""
    context: str = ""  # appended to the tool result (warn with warn_action allow)
    notes: tuple[str, ...] = ()  # SESSION_NOTE_RULES explained in ``context``: shown once it is appended

    def directive(self) -> dict[str, Any] | None:
        if self.action == "block":
            return {"action": "block", "message": self.message}
        if self.action == "approve":
            return {"action": "approve", "message": self.message, "rule_key": self.rule_key}
        return None


def sanitize(text: str, limit: int) -> str:
    """Make ``text`` safe to show in an approval prompt.

    Newlines become `` ⏎ ``; controls, bidi and zero-width marks, tags, private-use,
    unassigned and surrogate code points become ``\\u{XXXX}``, so the command being judged
    cannot rewrite the prompt that asks about it.
    """
    out: list[str] = []
    length = 0
    text = text.replace("\r\n", "\n")
    for char in text:
        if char == "\n":
            piece = " ⏎ "
        elif unicodedata.category(char) in _ESCAPED_CATEGORIES:
            piece = f"\\u{{{ord(char):04X}}}"
        else:
            piece = char
        if length + len(piece) > limit:
            out.append("…")
            break
        out.append(piece)
        length += len(piece)
    return "".join(out)


def _safe_id(rule_id: str) -> str:
    cleaned = "".join(c if (c.isascii() and (c.isalnum() or c in "_:.-")) else "?" for c in rule_id)
    return cleaned[:80] or "unknown"


def _ordered(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.key, finding.severity, finding.title), finding)
    return sorted(unique.values(), key=lambda f: -_settings.SEVERITY_RANK.get(f.severity, 3))


def format_findings(findings: Iterable[Finding]) -> str:
    ordered = _ordered(findings)
    if not ordered:
        return "no details"
    shown = [
        f"[{finding.severity}] {sanitize(finding.title, MAX_TITLE)} ({_safe_id(finding.key)})"
        for finding in ordered[:MAX_LISTED]
    ]
    if len(ordered) > MAX_LISTED:
        shown.append(f"+{len(ordered) - MAX_LISTED} more")
    return "; ".join(shown)


def _display_cwd(cwd: str) -> str:
    home = os.path.expanduser("~")
    if home and home != "~" and (cwd == home or cwd.startswith(home + os.sep)):
        cwd = "~" + cwd[len(home) :]
    return sanitize(cwd, 120)


def _cap(message: str) -> str:
    return message if len(message) <= MAX_MESSAGE else message[: MAX_MESSAGE - 1] + "…"


def _approval_message(
    prefix: str, excerpt: str, where: str, details: str, suffix: str = "", *, place: str = "in"
) -> str:
    """Keep the operation visible; only optional details consume the remaining space."""
    heading = f"{prefix} Command: {excerpt} ({place} {where})."
    ending = f" {suffix}" if suffix else ""
    available = MAX_MESSAGE - len(heading) - len(ending) - 1
    if len(details) > available:
        details = details[: available - 1] + "…"
    return f"{heading} {details}{ending}"


def _digest(kind: str, command: str, cwd: str, findings: Iterable[Finding], scope: str = "") -> str:
    parts: list[Any] = [
        "tirith/1",
        kind,
        command,
        cwd,
        sorted([f.rule_id, f.custom_rule_id, f.severity] for f in findings),
    ]
    if scope:
        parts.append(scope)
    material = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("ascii")).hexdigest()[:24]


def _salt(session_id: str, task_id: str) -> str:
    seed = PROCESS_NONCE + "\0" + (session_id or task_id or "")
    return hashlib.sha256(seed.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def rule_key(
    kind: str,
    command: str,
    cwd: str,
    findings: Iterable[Finding] = (),
    *,
    session_id: str = "",
    task_id: str = "",
    reason_class: str = "",
    scope: str = "",
) -> str:
    """The Hermes approval grain: one command, in one directory, with one finding set.

    Keys for policy approvals, blocks, bypass requests and failed checks carry a salt from
    this Hermes process and session, so "Always" for them never outlives the session.
    ``scope`` narrows a key further (the background process whose input could not be checked).
    """
    if kind == "error":
        digest = _digest(f"error:{reason_class}", command, cwd, findings, scope)
        return f"tirith:error:{reason_class or 'unknown'}:{digest}:s{_salt(session_id, task_id)}"
    digest = _digest(kind, command, cwd, findings, scope)
    if kind in SALTED_KINDS:
        return f"tirith:{kind}:{digest}:s{_salt(session_id, task_id)}"
    return f"tirith:{kind}:{digest}"


def filter_findings(findings: Iterable[Finding], settings: _settings.Settings) -> tuple[Finding, ...]:
    """Apply ``min_severity`` and ``ignore_rules`` (used for warn verdicts only)."""
    floor = _settings.SEVERITY_RANK[settings.min_severity]
    kept = []
    for finding in findings:
        rank = _settings.SEVERITY_RANK.get(finding.severity, 3)
        protected = finding.severity == "CRITICAL" or finding.rule_id in _settings.GUARDED_RULES
        if protected:
            kept.append(finding)
            continue
        if rank < floor:
            continue
        if finding.key.lower() in settings.ignore_rules or finding.rule_id.lower() in settings.ignore_rules:
            continue
        kept.append(finding)
    return tuple(kept)


def _block_message(findings: tuple[Finding, ...]) -> str:
    ordered = _ordered(findings)
    explain = f" (tirith explain --rule {_safe_id(ordered[0].rule_id)})" if ordered else ""
    return _cap(
        f"BLOCKED by tirith: {format_findings(findings)}. This cannot be approved from Hermes. "
        "Do not retry this command or a variant; tell the user what tirith reported. "
        f"A false positive is handled in tirith's own policy{explain}."
    )


def _session_note(finding: Finding) -> bool:
    return finding.rule_id in SESSION_NOTE_RULES and not finding.custom_rule_id and finding.severity != "CRITICAL"


def _note_text(rule_id: str, settings: _settings.Settings) -> str:
    if settings.offline or os.environ.get("TIRITH_OFFLINE", "").strip().lower() in _OFFLINE_ON:
        what = "were skipped because tirith's offline mode is on, and no cached answer was available"
    else:
        what = (
            "did not all finish during the check and no cached answer was available; usually tirith's short "
            "time budget for these lookups ran out or a service returned an error, which does not mean that "
            "the machine is offline"
        )
    return (
        f"Note: {rule_id} means tirith's live package lookups (OSV.dev, deps.dev, ecosyste.ms, the CISA KEV "
        f"feed) {what}. That is incomplete verification, not evidence that a package is malicious. "
        f"Later {rule_id} warnings in this session are not repeated; other warnings still are."
    )


def _warning_context(findings: tuple[Finding, ...], settings: _settings.Settings, noted: frozenset[str]) -> Decision:
    """The warning appended to the result: a session note is explained once, then left out."""
    shown = tuple(f for f in findings if not (_session_note(f) and f.rule_id in noted))
    if not shown:
        return Decision("none", "warn")
    notes = tuple(sorted({f.rule_id for f in shown if _session_note(f)}))
    context = f"\n\n[tirith] Warning about this command (it was allowed): {format_findings(shown)}."
    for rule_id in notes:
        context += " " + _note_text(rule_id, settings)
    return Decision("none", "warn", context=context, notes=notes)


def decide(
    outcome: ScanOutcome,
    settings: _settings.Settings,
    *,
    command: str,
    cwd: str,
    session_id: str = "",
    task_id: str = "",
    scope: str = "",
    noted: frozenset[str] = frozenset(),
) -> Decision:
    """``noted``: the ``SESSION_NOTE_RULES`` already explained to this session's agent."""
    kind = outcome.kind
    if (outcome.requires_approval or kind == "warn_ack") and kind not in ("block", "error"):
        kind = "approval"
    excerpt = sanitize(command, MAX_EXCERPT)
    where = _display_cwd(cwd)

    def key(findings: tuple[Finding, ...] = ()) -> str:
        return rule_key(
            kind, command, cwd, findings, session_id=session_id, task_id=task_id, reason_class=outcome.reason_class
        )

    if kind == "approval":
        if settings.warn_action == "block":
            return Decision("block", kind, _block_message(outcome.findings))
        details = format_findings(outcome.findings)
        if outcome.approval_rule:
            details = f"Policy rule: {_safe_id(outcome.approval_rule)}. {details}"
        return Decision(
            "approve",
            kind,
            _approval_message(
                "tirith policy requires approval.",
                excerpt,
                where,
                details,
                "Approving applies to this exact command for this session only.",
            ),
            key(outcome.findings),
        )

    if kind == "allow":
        return Decision("none", kind)

    if kind == "bypass":
        return Decision(
            "approve",
            kind,
            _approval_message(
                "This command asks tirith to skip its check.",
                excerpt,
                where,
                "TIRITH=0 is allowed by your policy; a command written by the agent cannot waive the check on its own.",
            ),
            key(outcome.findings),
        )

    if kind == "warn":
        findings = filter_findings(outcome.findings, settings)
        if not findings:
            return Decision("none", kind)
        text = format_findings(findings)
        action = settings.warn_action
        if action == "block":
            return Decision("block", kind, _block_message(findings))
        if action == "approve":
            return Decision(
                "approve",
                kind,
                _approval_message("tirith warns about this command.", excerpt, where, text),
                key(findings),
            )
        if not settings.warn_context:
            return Decision("none", kind)
        return _warning_context(findings, settings, noted)

    if kind == "block":
        critical = any(f.severity == "CRITICAL" for f in outcome.findings)
        action = settings.critical_action if critical else settings.block_action
        if action == "block":
            return Decision("block", kind, _block_message(outcome.findings))
        return Decision(
            "approve",
            kind,
            _approval_message(
                "tirith flagged this command.",
                excerpt,
                where,
                format_findings(outcome.findings),
                "Approving applies to this exact command for this session only.",
            ),
            key(outcome.findings),
        )

    # error (and anything unexpected): fail closed unless the user turned that off. A failed check
    # that tirith marked as needing approval (exit code 3 without a usable verdict) always asks.
    if not settings.fail_closed and not outcome.requires_approval:
        return Decision("none", "error")
    reason = sanitize(outcome.reason or "unknown error", 300)
    details = f"Reason: {reason}."
    if outcome.requires_approval:
        details += " tirith also signalled that this command needs approval."
    if outcome.findings:
        details += f" tirith flagged the text it could check: {format_findings(outcome.findings)}."
    return Decision(
        "approve",
        "error",
        _approval_message(
            "tirith could not check this command.",
            excerpt,
            where,
            details,
            "Approve only if you want it to run without a tirith check.",
        ),
        rule_key(
            "error",
            command,
            cwd,
            outcome.findings,
            session_id=session_id,
            task_id=task_id,
            reason_class=outcome.reason_class or "unknown",
            scope=scope,
        ),
    )


def _verdict_there(outcome: ScanOutcome, settings: _settings.Settings) -> str:
    """tirith's verdict for a command it checked, as one sentence for a prompt."""
    if outcome.kind == "block":
        return f"tirith flagged it there: {format_findings(outcome.findings)}."
    if outcome.requires_approval or outcome.kind == "warn_ack":
        rule = f" (policy rule {_safe_id(outcome.approval_rule)})" if outcome.approval_rule else ""
        return f"Your tirith policy requires approval for it there{rule}: {format_findings(outcome.findings)}."
    if outcome.kind == "bypass":
        return "It asks tirith to skip its check (TIRITH=0), which your tirith policy allows."
    findings = filter_findings(outcome.findings, settings) if outcome.kind == "warn" else ()
    if findings:
        return f"tirith warned there: {format_findings(findings)}."
    return "tirith found nothing there."


def cwd_pending(
    outcome: ScanOutcome,
    checked: Decision,
    settings: _settings.Settings,
    *,
    command: str,
    cwd: str,
    session_id: str = "",
    task_id: str = "",
) -> Decision:
    """Ask about a command tirith checked in ``cwd`` while an earlier batched command may still change it.

    ``outcome`` and ``checked`` are tirith's verdict in ``cwd`` (not a refusal, not a failed check). The
    prompt says why it asks and shows that verdict; a warning stays attached to the result.
    """
    return Decision(
        "approve",
        "error",
        _approval_message(
            "The directory this command will run in is not known yet.",
            sanitize(command, MAX_EXCERPT),
            _display_cwd(cwd),
            "An earlier terminal command that can change directory has not run yet, and another "
            f"directory can have another tirith policy. {_verdict_there(outcome, settings)}",
            "Approve only if it may run in whichever directory the earlier command leaves.",
            place="checked in",
        ),
        rule_key(
            "error",
            command,
            cwd,
            outcome.findings,
            session_id=session_id,
            task_id=task_id,
            reason_class="cwd_pending",
        ),
        context=checked.context,
        notes=checked.notes,
    )
