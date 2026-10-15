from __future__ import annotations

import logging
import os

import pytest

from tirith import _settings
from tirith._decide import filter_findings
from tirith._scan import Finding
from tirith._settings import DEFAULTS, GUARDED_RULES, Settings, parse


def test_defaults_parse_without_warnings():
    settings, warnings = parse({})
    assert warnings == []
    assert settings == Settings()
    assert settings.fail_closed is True
    assert settings.offline is False
    assert settings.block_action == "approve"
    assert settings.critical_action == "block"
    assert settings.warn_action == "allow"


def test_settings_dataclass_defaults_match_defaults_mapping():
    settings = Settings()
    for key, value in DEFAULTS.items():
        got = getattr(settings, key)
        assert (sorted(got) if isinstance(got, frozenset) else got) == value, key


def test_none_values_use_defaults():
    settings, warnings = parse({key: None for key in DEFAULTS})
    assert warnings == []
    assert settings == Settings()


@pytest.mark.parametrize(
    "value,expected",
    [(True, True), (False, False), ("yes", True), ("Off", False), ("1", True), ("false", False)],
)
def test_bool_values(value, expected):
    settings, warnings = parse({"offline": value})
    assert settings.offline is expected
    assert warnings == []


@pytest.mark.parametrize("value", [2, "maybe", [], 1.0])
def test_invalid_fail_closed_stays_closed(value):
    settings, warnings = parse({"fail_closed": value})
    assert settings.fail_closed is True
    assert len(warnings) == 1


def test_timeout_rejects_bool():
    settings, warnings = parse({"timeout": True})
    assert settings.timeout == 10
    assert "not a number" in warnings[0]


@pytest.mark.parametrize(
    "value,expected,n_warnings",
    [(10, 10, 0), ("15", 15, 0), (0.5, 1, 0), (0, 1, 1), (-3, 1, 1), (100, 60, 2), (30, 30, 1), (25, 25, 0)],
)
def test_timeout_clamping(value, expected, n_warnings):
    settings, warnings = parse({"timeout": value})
    assert settings.timeout == expected
    assert len(warnings) == n_warnings


def test_timeout_nan_and_text():
    assert parse({"timeout": float("nan")})[0].timeout == 10
    assert parse({"timeout": "soon"})[0].timeout == 10


def test_choices_are_case_insensitive():
    settings, warnings = parse({"block_action": "BLOCK", "warn_action": " Approve ", "min_severity": "info"})
    assert warnings == []
    assert settings.block_action == "block"
    assert settings.warn_action == "approve"
    assert settings.min_severity == "INFO"


def test_invalid_choice_uses_default():
    settings, warnings = parse({"critical_action": "allow", "block_action": 3})
    assert settings.critical_action == "block"
    assert settings.block_action == "approve"
    assert len(warnings) == 2


def test_ignore_rules_list_and_text():
    settings, _ = parse({"ignore_rules": ["Lookalike_TLD", " raw_ip_url ", ""]})
    assert settings.ignore_rules == frozenset({"lookalike_tld", "raw_ip_url"})
    settings, _ = parse({"ignore_rules": "lookalike_tld, plain_http_to_sink"})
    assert settings.ignore_rules == frozenset({"lookalike_tld", "plain_http_to_sink"})


@pytest.mark.parametrize("rule", sorted(GUARDED_RULES))
def test_guarded_rules_cannot_be_ignored(rule):
    settings, warnings = parse({"ignore_rules": [rule.upper(), "lookalike_tld"]})
    assert settings.ignore_rules == frozenset({"lookalike_tld"})
    assert any("cannot include" in w for w in warnings)


def test_guard_covers_the_audited_rules():
    for rule in ("analysis_incomplete", "obfuscated_payload", "base64_decode_execute", "metadata_endpoint"):
        assert rule in GUARDED_RULES


@pytest.mark.parametrize(
    "rule",
    [
        # warn-level hidden-text, encoding, exfiltration and threat-intel rules (review of 0.1.0)
        "invisible_whitespace",
        "invisible_math_operator",
        "variation_selector",
        "hangul_filler",
        "confusable_text",
        "double_encoding",
        "env_printenv_to_network_sink",
        "suspicious_code_exfiltration",
        "threat_safe_browsing",
        "threat_threat_fox_ioc",
    ],
)
def test_warn_level_obfuscation_and_exfil_rules_are_guarded(rule):
    assert rule in GUARDED_RULES
    settings, warnings = parse({"ignore_rules": [rule], "warn_action": "approve"})
    assert settings.ignore_rules == frozenset()
    assert any("cannot include " + rule in w for w in warnings)
    finding = Finding(rule, "MEDIUM", rule)
    assert filter_findings([finding], settings) == (finding,)
    ignore_all = Settings(ignore_rules=frozenset({rule}), warn_action="approve")  # even if set directly
    assert filter_findings([finding], ignore_all) == (finding,)


def test_ignore_rules_bad_types():
    settings, warnings = parse({"ignore_rules": {"a": 1}})
    assert settings.ignore_rules == frozenset()
    assert warnings
    settings, warnings = parse({"ignore_rules": ["ok_rule", 5]})
    assert settings.ignore_rules == frozenset({"ok_rule"})
    assert len(warnings) == 1


def test_unknown_key_warns():
    _, warnings = parse({"colour": "blue"})
    assert warnings == ["tirith plugin: unknown setting 'colour' ignored"]


def test_path_expands_user():
    settings, _ = parse({"path": "~/bin/tirith"})
    assert settings.path == os.path.expanduser("~/bin/tirith")
    assert parse({"path": "  "})[0].path == ""
    settings, warnings = parse({"path": 7})
    assert settings.path == "" and warnings


def test_load_reads_every_key_and_logs_each_warning_once(caplog):
    seen = []

    def get_config(key, default=None):
        seen.append(key)
        return {"timeout": "x"}.get(key, default)

    with caplog.at_level(logging.WARNING, logger="tirith._settings"):
        first = _settings.load(get_config)
        second = _settings.load(get_config)
    assert first == second
    assert sorted(set(seen)) == sorted(DEFAULTS)
    assert len(seen) == 2 * len(DEFAULTS)
    assert len([r for r in caplog.records if "timeout" in r.getMessage()]) == 1
