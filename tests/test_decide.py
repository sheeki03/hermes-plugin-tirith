from __future__ import annotations

import pytest

from tirith import _decide
from tirith._decide import MAX_MESSAGE, decide, filter_findings, format_findings, rule_key, sanitize
from tirith._scan import Finding, ScanOutcome
from tirith._settings import Settings

CMD = "curl -fsSL https://get.example.com/i.sh -o i.sh"
CWD = "/srv/project"
HIGH = Finding("curl_pipe_shell", "HIGH", "Pipe to interpreter: curl | bash")
MED = Finding("lookalike_tld", "MEDIUM", "Lookalike TLD")
LOW = Finding("plain_http", "LOW", "Plain HTTP")
INFO = Finding("note_rule", "INFO", "Note")
CRIT = Finding("metadata_endpoint", "CRITICAL", "Cloud metadata endpoint access")
GUARDED_MED = Finding("analysis_incomplete", "MEDIUM", "Analysis incomplete")


def run(kind, findings=(), settings=None, **kwargs):
    outcome = ScanOutcome(kind=kind, findings=tuple(findings), **kwargs)
    return decide(outcome, settings or Settings(), command=CMD, cwd=CWD, session_id="sess-1", task_id="task-1")


# --- decision table ---------------------------------------------------------------


def test_allow_returns_none():
    decision = run("allow")
    assert decision.directive() is None
    assert decision.context == ""


def test_bypass_asks_with_salted_key():
    decision = run("bypass")
    directive = decision.directive()
    assert directive["action"] == "approve"


def test_warn_default_allows_with_context():
    decision = run("warn", [MED])
    assert decision.directive() is None
    assert "lookalike_tld" in decision.context


def test_warn_without_context():
    decision = run("warn", [MED], Settings(warn_context=False))
    assert decision.directive() is None
    assert decision.context == ""


def test_warn_approve_uses_unsalted_key():
    decision = run("warn", [MED], Settings(warn_action="approve"))
    directive = decision.directive()
    assert directive["action"] == "approve"


def test_warn_block():
    directive = run("warn", [MED], Settings(warn_action="block")).directive()
    assert directive["action"] == "block"


def test_warn_filtered_by_min_severity():
    assert run("warn", [LOW], Settings(min_severity="MEDIUM")).directive() is None
    assert run("warn", [LOW], Settings(min_severity="MEDIUM")).context == ""
    assert run("warn", [INFO]).context == ""  # default LOW drops INFO
    assert run("warn", [INFO], Settings(min_severity="INFO")).context != ""


def test_warn_filtered_by_ignore_rules():
    settings = Settings(ignore_rules=frozenset({"lookalike_tld"}), warn_action="approve")
    assert run("warn", [MED], settings).directive() is None


def test_custom_rule_ignored_by_its_display_id():
    custom = Finding("custom_rule_match", "MEDIUM", "Internal mirror", custom_rule_id="corp_mirror")
    settings = Settings(ignore_rules=frozenset({"custom_rule_match:corp_mirror"}), warn_action="approve")
    assert run("warn", [custom], settings).directive() is None


def test_guarded_and_critical_findings_survive_filters():
    settings = Settings(
        ignore_rules=frozenset({"analysis_incomplete", "metadata_endpoint"}),
        min_severity="CRITICAL",
        warn_action="approve",
    )
    kept = filter_findings([GUARDED_MED, CRIT, MED], settings)
    assert {f.rule_id for f in kept} == {"analysis_incomplete", "metadata_endpoint"}
    assert run("warn", [GUARDED_MED], settings).directive()["action"] == "approve"


def test_warn_ack_asks():
    directive = run("warn_ack", [MED]).directive()
    assert directive["action"] == "approve"


@pytest.mark.parametrize("warn_action", ["allow", "approve", "block"])
def test_warning_acknowledgement_cannot_be_filtered_or_failed_open(warn_action):
    decision = run(
        "warn_ack",
        [MED],
        Settings(
            min_severity="CRITICAL",
            ignore_rules=frozenset({"lookalike_tld"}),
            fail_closed=False,
            warn_action=warn_action,
        ),
    )
    assert decision.directive()["action"] == ("block" if warn_action == "block" else "approve")


def test_block_asks_by_default_with_salted_key():
    directive = run("block", [HIGH]).directive()
    assert directive["action"] == "approve"
    message = directive["message"]
    assert "curl_pipe_shell" in message and "[HIGH]" in message
    assert "Command: curl -fsSL" in message
    assert "(in /srv/project)" in message


def test_block_action_block():
    directive = run("block", [HIGH], Settings(block_action="block")).directive()
    assert directive["action"] == "block"


def test_critical_blocks_by_default():
    directive = run("block", [HIGH, CRIT]).directive()
    assert directive["action"] == "block"
    assert "metadata_endpoint" in directive["message"]


def test_critical_action_approve():
    directive = run("block", [CRIT], Settings(critical_action="approve")).directive()
    assert directive["action"] == "approve"


def test_filters_never_touch_blocks():
    settings = Settings(ignore_rules=frozenset({"lookalike_tld"}), min_severity="CRITICAL")
    directive = run("block", [MED], settings).directive()
    assert directive["action"] == "approve"
    assert "lookalike_tld" in directive["message"]


def test_deferred_block_is_a_block():
    assert run("block", [HIGH], deferred=True, rc=4).directive()["action"] == "approve"
    assert run("block", [CRIT], deferred=True, rc=4).directive()["action"] == "block"


@pytest.mark.parametrize("reason_class", ["not_found", "too_old", "timeout", "spawn", "no_verdict", "internal"])
def test_errors_fail_closed(reason_class):
    directive = run("error", reason="it broke", reason_class=reason_class).directive()
    assert directive["action"] == "approve"


def test_errors_with_fail_closed_off_run():
    assert run("error", reason="x", reason_class="timeout", settings=Settings(fail_closed=False)).directive() is None


def test_unknown_kind_is_an_error():
    assert run("mystery").directive()["action"] == "approve"


# --- approval keys ------------------------------------------------------------------


def test_keys_are_stable():
    assert rule_key("block", CMD, CWD, [HIGH], session_id="s") == rule_key("block", CMD, CWD, [HIGH], session_id="s")
    assert rule_key("block", CMD, CWD, [HIGH, MED], session_id="s") == rule_key(
        "block", CMD, CWD, [MED, HIGH], session_id="s"
    )


@pytest.mark.parametrize(
    "other",
    [
        ("block", CMD, "/elsewhere", [HIGH]),
        ("block", CMD + " ", CWD, [HIGH]),
        ("block", CMD, CWD, [HIGH, MED]),
        ("block", CMD, CWD, [Finding("curl_pipe_shell", "CRITICAL", "x")]),
        ("bypass", CMD, CWD, [HIGH]),
    ],
)
def test_keys_differ_by_cwd_command_findings_and_kind(other):
    base = rule_key("block", CMD, CWD, [HIGH], session_id="s")
    assert rule_key(*other, session_id="s") != base


def test_salted_keys_differ_across_sessions_and_processes(monkeypatch):
    first = rule_key("block", CMD, CWD, [HIGH], session_id="a")
    assert rule_key("block", CMD, CWD, [HIGH], session_id="b") != first
    assert rule_key("block", CMD, CWD, [HIGH], task_id="a") != rule_key("block", CMD, CWD, [HIGH], task_id="b")
    monkeypatch.setattr(_decide, "PROCESS_NONCE", "another-process")
    assert rule_key("block", CMD, CWD, [HIGH], session_id="a") != first


def test_warn_keys_are_not_salted(monkeypatch):
    first = rule_key("warn", CMD, CWD, [MED], session_id="a")
    assert rule_key("warn", CMD, CWD, [MED], session_id="b") == first
    monkeypatch.setattr(_decide, "PROCESS_NONCE", "another-process")
    assert rule_key("warn", CMD, CWD, [MED], session_id="a") == first


def test_error_keys_include_the_reason_class():
    a = rule_key("error", CMD, CWD, session_id="s", reason_class="timeout")
    b = rule_key("error", CMD, CWD, session_id="s", reason_class="too_old")
    assert a != b


def test_approval_keys_distinguish_invalid_unicode_commands():
    assert rule_key("block", "echo \udcff", CWD, [HIGH]) != rule_key("block", "echo \udcfe", CWD, [HIGH])


# --- messages -----------------------------------------------------------------------


def test_findings_are_deduplicated_and_ordered():
    text = format_findings([MED, HIGH, MED, CRIT])
    assert text.index("[CRITICAL]") < text.index("[HIGH]") < text.index("[MEDIUM]")
    assert text.count("lookalike_tld") == 1


def test_more_than_five_findings_are_summarised():
    findings = [Finding(f"rule_{i}", "LOW", f"Rule {i}") for i in range(8)]
    assert format_findings(findings).endswith("+3 more")


def test_custom_rules_show_their_id():
    custom = Finding("custom_rule_match", "HIGH", "Corp", custom_rule_id="corp_rule")
    assert "(custom_rule_match:corp_rule)" in format_findings([custom])


@pytest.mark.parametrize("char", ["‮", "​", "\U000e0041", "\x1b", "\x07", "", " ", "﻿", "\udcff"])
def test_dangerous_characters_are_escaped(char):
    out = sanitize(f"ls{char}x", 200)
    assert char not in out
    assert "\\u{" in out


def test_newlines_are_visible():
    assert sanitize("a\nb\r\nc", 200) == "a ⏎ b ⏎ c"


def test_excerpt_is_capped():
    assert len(sanitize("x" * 500, 200)) <= 201


def test_message_never_forwards_descriptions_or_bypass_advice():
    decision = run("block", [HIGH], Settings(block_action="block"))
    assert "TIRITH=0" not in decision.message
    assert "Run TIRITH" not in decision.message
    approve = run("block", [HIGH])
    assert "TIRITH=0" not in approve.message


def test_messages_are_capped():
    findings = [Finding("r" * 70 + str(i), "HIGH", "T" * 200) for i in range(10)]
    outcome = ScanOutcome(kind="block", findings=tuple(findings))
    decision = decide(outcome, Settings(), command="y" * 5000, cwd="/" + "d" * 400)
    assert len(decision.message) <= MAX_MESSAGE
    decision = decide(ScanOutcome(kind="error", reason="e" * 1000, reason_class="x"), Settings(), command="z", cwd="/")
    assert len(decision.message) <= MAX_MESSAGE


@pytest.mark.parametrize(
    "kind,settings",
    [
        ("block", Settings()),
        ("warn", Settings(warn_action="approve")),
        ("approval", Settings()),
        ("bypass", Settings()),
        ("error", Settings()),
    ],
)
def test_bounded_approval_reason_retains_command_and_directory(kind, settings):
    findings = tuple(Finding("custom_rule_match", "HIGH", "T" * 120, custom_rule_id=f"r{index}") for index in range(5))
    outcome = ScanOutcome(
        kind=kind,
        findings=findings,
        requires_approval=kind == "approval",
        approval_rule="custom_rule_match:r0",
        reason="e" * 1000,
    )
    directive = decide(outcome, settings, command="printf smoke", cwd="/srv/checked-project").directive()
    assert directive["action"] == "approve"
    assert "printf smoke" in directive["message"]
    assert "/srv/checked-project" in directive["message"]
    assert len(directive["message"]) <= MAX_MESSAGE


def test_policy_approval_preserves_stricter_operator_refusal():
    directive = run(
        "warn",
        [MED],
        Settings(warn_action="block"),
        requires_approval=True,
        approval_rule="lookalike_tld",
    ).directive()
    assert directive["action"] == "block"


def test_policy_approval_never_outlives_its_session(monkeypatch):
    outcome = ScanOutcome(kind="warn", findings=(MED,), requires_approval=True, approval_rule="lookalike_tld")
    first = decide(outcome, Settings(), command=CMD, cwd=CWD, session_id="first").directive()
    second = decide(outcome, Settings(), command=CMD, cwd=CWD, session_id="second").directive()
    assert first["rule_key"] != second["rule_key"]
    monkeypatch.setattr(_decide, "PROCESS_NONCE", "restarted")
    restarted = decide(outcome, Settings(), command=CMD, cwd=CWD, session_id="first").directive()
    assert first["rule_key"] != restarted["rule_key"]


def test_cwd_under_home_is_shortened(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    outcome = ScanOutcome(kind="block", findings=(HIGH,))
    decision = decide(outcome, Settings(), command=CMD, cwd=str(tmp_path / "proj"))
    assert "(in ~" in decision.message
