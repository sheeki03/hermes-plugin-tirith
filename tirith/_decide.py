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
SALTED_KINDS = frozenset({"block", "bypass", "error"})

_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})


@dataclass(frozen=True)
class Decision:
    action: str  # none | approve | block
    kind: str
    message: str = ""
    rule_key: str = ""
    context: str = ""  # appended to the tool result (warn with warn_action allow)

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


def _digest(kind: str, command: str, cwd: str, findings: Iterable[Finding]) -> str:
    material = json.dumps(
        ["tirith/1", kind, command, cwd, sorted([f.rule_id, f.custom_rule_id, f.severity] for f in findings)],
        ensure_ascii=True,
        separators=(",", ":"),
    )
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
) -> str:
    """The Hermes approval grain: one command, in one directory, with one finding set.

    Keys for blocks, bypass requests and failed checks carry a salt from this Hermes process
    and session, so "Always" for them never outlives the session.
    """
    if kind == "error":
        digest = _digest(f"error:{reason_class}", command, cwd, ())
        return f"tirith:error:{reason_class or 'unknown'}:{digest}:s{_salt(session_id, task_id)}"
    digest = _digest(kind, command, cwd, findings)
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


def decide(
    outcome: ScanOutcome,
    settings: _settings.Settings,
    *,
    command: str,
    cwd: str,
    session_id: str = "",
    task_id: str = "",
) -> Decision:
    kind = outcome.kind
    excerpt = sanitize(command, MAX_EXCERPT)
    where = _display_cwd(cwd)

    def key(findings: tuple[Finding, ...] = ()) -> str:
        return rule_key(
            kind, command, cwd, findings, session_id=session_id, task_id=task_id, reason_class=outcome.reason_class
        )

    if kind == "allow":
        return Decision("none", kind)

    if kind == "bypass":
        return Decision(
            "approve",
            kind,
            _cap(
                "This command asks tirith to skip its check (TIRITH=0) and your tirith policy allows that. "
                "A command written by the agent cannot waive the check on its own. "
                f"Command: {excerpt} (in {where})."
            ),
            key(outcome.findings),
        )

    if kind in ("warn", "warn_ack"):
        findings = filter_findings(outcome.findings, settings)
        if not findings:
            return Decision("none", kind)
        text = format_findings(findings)
        action = "approve" if kind == "warn_ack" else settings.warn_action
        if action == "block":
            return Decision("block", kind, _block_message(findings))
        if action == "approve":
            return Decision(
                "approve",
                kind,
                _cap(f"tirith warns about this command: {text}. Command: {excerpt} (in {where})."),
                key(findings),
            )
        context = f"\n\n[tirith] Warning about this command (it was allowed): {text}." if settings.warn_context else ""
        return Decision("none", kind, context=context)

    if kind == "block":
        critical = any(f.severity == "CRITICAL" for f in outcome.findings)
        action = settings.critical_action if critical else settings.block_action
        if action == "block":
            return Decision("block", kind, _block_message(outcome.findings))
        return Decision(
            "approve",
            kind,
            _cap(
                f"tirith flagged this command: {format_findings(outcome.findings)}. "
                f"Command: {excerpt} (in {where}). "
                "Approving applies to this exact command for this session only."
            ),
            key(outcome.findings),
        )

    # error (and anything unexpected): fail closed unless the user turned that off
    if not settings.fail_closed:
        return Decision("none", "error")
    reason = sanitize(outcome.reason or "unknown error", 300)
    return Decision(
        "approve",
        "error",
        _cap(
            f"tirith could not check this command ({reason}). Approve only if you want it to run without a "
            f"tirith check. Command: {excerpt}."
        ),
        rule_key(
            "error",
            command,
            cwd,
            session_id=session_id,
            task_id=task_id,
            reason_class=outcome.reason_class or "unknown",
        ),
    )
