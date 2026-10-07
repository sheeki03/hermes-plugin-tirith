"""Run the 64-command corpus through the plugin with a real tirith (TIRITH_TEST_BIN).

Fails when an attack would run with no prompt, no refusal and no warning. Attacks tirith only
warns about run with the warning appended (``warn_action: allow``) and are listed in the report.
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

pytestmark = [
    pytest.mark.realtirith,
    pytest.mark.skipif(not os.environ.get("TIRITH_TEST_BIN"), reason="set TIRITH_TEST_BIN"),
]

CORPUS = json.loads((Path(__file__).parent / "data" / "corpus.json").read_text(encoding="utf-8"))
# Caught through the threat database only (typosquatted package, known exfiltration endpoint).
NEEDS_THREAT_DB = frozenset({"A06", "A07"})


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
    _ctx, registered = ctx_factory(path=os.environ["TIRITH_TEST_BIN"], offline=True, timeout=20)

    rows, lost = [], []
    for row in CORPUS:
        call_id = f"corpus-{row['id']}"
        directive = registered["pre_tool_call"](
            tool_name="terminal",
            args={"command": row["cmd"]},
            task_id="corpus",
            session_id="corpus",
            tool_call_id=call_id,
        )
        context = registered["transform_tool_result"](tool_name="terminal", result="", tool_call_id=call_id)
        action = directive["action"] if directive else ("allow+warning" if context else "allow")
        message = (directive or {}).get("message", "") or (context or "")
        rows.append((row["id"], row["expected"], row["set"], action, message))
        if row["expected"] == "attack" and action == "allow" and (data_home or row["id"] not in NEEDS_THREAT_DB):
            lost.append(row["id"])

    report = os.environ.get("TIRITH_CORPUS_REPORT")
    if report:
        lines = ["| id | expected | set | Hermes action | findings |", "|---|---|---|---|---|"]
        lines += [f"| {i} | {e} | {s} | {a} | {_cell(m)[:300]} |" for i, e, s, a, m in rows]
        benign = [r for r in rows if r[1] == "benign"]
        warned = [r[0] for r in rows if r[1] == "attack" and r[3] == "allow+warning"]
        lines += [
            "",
            f"Benign: {sum(r[3] == 'block' for r in benign)} refused, {sum(r[3] == 'approve' for r in benign)} "
            f"asked, {sum(r[3].startswith('allow') for r in benign)} ran.",
            f"Attacks that ran with a warning: {warned or 'none'}. Attacks lost: {lost or 'none'}"
            + ("" if data_home else f" (not asserted without a threat database: {sorted(NEEDS_THREAT_DB)})."),
        ]
        Path(report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not lost, f"attacks that would run with no prompt, refusal or warning: {lost}"
