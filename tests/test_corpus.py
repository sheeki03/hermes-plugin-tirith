"""Run the reconstructed command corpus through the plugin with a real tirith.

This measures check coverage and proposed gate decisions, never command execution.
Warning-only attack rows would be permitted with an advisory; they are not prevented.
Benign results are reported, not asserted: the benign target is set by the tirith release.

The test runs offline in an empty home, so tirith has no threat database. Rows that tirith can
only catch with its database are asserted only when TIRITH_CORPUS_DATA_HOME points at an
XDG data directory that holds one. TIRITH_CORPUS_REPORT=<path> writes the table as Markdown.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import tirith as plugin

pytestmark = [
    pytest.mark.realtirith,
    pytest.mark.skipif(not os.environ.get("TIRITH_TEST_BIN"), reason="set TIRITH_TEST_BIN"),
]

CORPUS = json.loads((Path(__file__).parent / "data" / "corpus.json").read_text(encoding="utf-8"))
# Caught through the threat database only (typosquatted package, known exfiltration endpoint).
NEEDS_THREAT_DB = frozenset({"A06", "A07"})
ATTEMPTS = 3  # a row whose check timed out is checked again; one that keeps failing fails the test


def _timed_out(outcome) -> bool:
    """tirith, or its gate, did not answer in time: a slow machine, not a broken contract."""
    return outcome.kind == "error" and (outcome.reason_class == "timeout" or "in time" in outcome.reason)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def test_corpus(ctx_factory, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    for key in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(key, str(home / key.lower()))
    data_home = os.environ.get("TIRITH_CORPUS_DATA_HOME", "")
    if data_home:
        monkeypatch.setenv("XDG_DATA_HOME", data_home)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _ctx, registered = ctx_factory(path=os.environ["TIRITH_TEST_BIN"], offline=True, timeout=60)

    captured = []
    check_command = plugin.check_command

    def observe_check(*args, **kwargs):
        result = check_command(*args, **kwargs)
        captured.append(result[1])
        return result

    monkeypatch.setattr(plugin, "check_command", observe_check)
    rows, lost, errors, retried = [], [], [], []
    for row in CORPUS:
        for attempt in range(1, ATTEMPTS + 1):
            call_id = f"corpus-{row['id']}-{attempt}"
            directive = registered["pre_tool_call"](
                tool_name="terminal",
                args={"command": row["cmd"]},
                task_id="corpus",
                session_id="corpus",
                tool_call_id=call_id,
            )
            context = registered["transform_tool_result"](
                tool_name="terminal", result="", task_id="corpus", session_id="corpus", tool_call_id=call_id
            )
            outcome = captured[-1]
            if not _timed_out(outcome):
                break
        if attempt > 1:
            retried.append(f"{row['id']} ({attempt} attempts)")
        action = directive["action"] if directive else ("allow+warning" if context else "allow")
        message = (directive or {}).get("message", "") or (context or "")
        coverage = (
            "check failed"
            if outcome.kind == "error"
            else ("intelligence not asserted" if not data_home and row["id"] in NEEDS_THREAT_DB else "asserted")
        )
        rows.append((row["id"], row["expected"], row["set"], action, coverage, message))
        if outcome.kind == "error":
            errors.append(row["id"])
        elif row["expected"] == "attack" and action == "allow" and coverage == "asserted":
            lost.append(row["id"])

    report = os.environ.get("TIRITH_CORPUS_REPORT")
    if report:
        lines = [
            "| id | expected | set | Proposed Hermes decision | Coverage | Findings |",
            "|---|---|---|---|---|---|",
        ]
        lines += [f"| {i} | {e} | {s} | {a} | {c} | {_cell(m)[:300]} |" for i, e, s, a, c, m in rows]
        benign = [r for r in rows if r[1] == "benign"]
        attacks = [r for r in rows if r[1] == "attack"]
        warned = [r[0] for r in attacks if r[3] == "allow+warning"]
        unasserted = [r[0] for r in attacks if r[4] == "intelligence not asserted"]
        lines += [
            "",
            "No corpus command was executed. These are scanner and hook decisions, not prevention measurements.",
            f"Benign decisions: {sum(r[3] == 'block' for r in benign)} refusals, "
            f"{sum(r[3] == 'approve' for r in benign)} approval requests, "
            f"{sum(r[3].startswith('allow') for r in benign)} permissions.",
            f"Attack decisions: {sum(r[3] == 'block' for r in attacks)} refusals, "
            f"{sum(r[3] == 'approve' for r in attacks)} approval requests, "
            f"{sum(r[3] == 'allow+warning' for r in attacks)} warning-only permissions, "
            f"{sum(r[3] == 'allow' for r in attacks)} no-signal permissions.",
            f"Warning-only attack rows (not prevented): {warned or 'none'}.",
            f"Asserted attack rows with no signal: {lost or 'none'}. Failed checks: {errors or 'none'}.",
            f"Database-dependent rows not asserted: {unasserted or 'none'}.",
            f"Checked again after a timeout: {retried or 'none'}.",
        ]
        Path(report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not errors, f"valid corpus inputs did not receive a completed check: {errors}"
    assert not lost, f"asserted attacks received no prompt, refusal or warning: {lost}"
