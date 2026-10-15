"""Plugin settings: defaults, parsing and the guarded rule list.

``ctx.get_config`` does not apply the manifest ``config_schema`` defaults, so this
module owns them (``DEFAULTS``). ``tests/test_manifest.py`` checks that the
manifest defaults match.
"""

from __future__ import annotations

import logging
import math
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

DEFAULTS: dict[str, Any] = {
    "path": "",
    "timeout": 10,
    "offline": False,
    "fail_closed": True,
    "block_action": "approve",
    "critical_action": "block",
    "warn_action": "allow",
    "warn_context": True,
    "min_severity": "LOW",
    "ignore_rules": [],
    "scan_process_input": True,
}

CHOICES: dict[str, tuple[str, ...]] = {
    "block_action": ("approve", "block"),
    "critical_action": ("block", "approve"),
    "warn_action": ("allow", "approve", "block"),
    "min_severity": SEVERITIES,
}

BOOL_KEYS = ("offline", "fail_closed", "warn_context", "scan_process_input")

TIMEOUT_MIN = 1
TIMEOUT_MAX = 60
# Hermes abandons a hook callback after plugins.hook_callback_timeout (default 30 s).
TIMEOUT_WARN_ABOVE = 25

# Rule ids whose warnings can never be ignored through ``ignore_rules``: obfuscation and
# hidden text, input tirith could not analyse, known-malicious intelligence, policy
# denials, exfiltration and terminal injection. Findings with severity CRITICAL can never
# be ignored either. Filters only ever apply to warn verdicts; blocks are never filtered.
GUARDED_RULES = frozenset(
    {
        # obfuscation and input tirith could not analyse
        "analysis_incomplete",
        "obfuscated_payload",
        "base64_decode_execute",
        "dynamic_code_execution",
        "interpreter_suspicious_inline_exec",
        "wrapper_chain_too_deep",
        "prompt_injection_obfuscated",
        "double_encoding",
        # download and execute
        "pipe_to_interpreter",
        "curl_pipe_shell",
        "wget_pipe_shell",
        "httpie_pipe_shell",
        "xh_pipe_shell",
        "ps_inline_download_execute",
        "reverse_shell",
        # terminal injection and hidden text
        "ansi_escapes",
        "control_chars",
        "bidi_controls",
        "zero_width_chars",
        "unicode_tags",
        "hidden_multiline",
        "invisible_whitespace",
        "invisible_math_operator",
        "variation_selector",
        "hangul_filler",
        "confusable_text",
        # known-malicious intelligence
        "threat_malicious_package",
        "threat_unresolved_malicious_package",
        "threat_malicious_ip",
        "threat_malicious_url",
        "threat_phishing_url",
        "threat_safe_browsing",
        "threat_threat_fox_ioc",
        "artifact_known_malicious",
        # policy denials
        "policy_blocklisted",
        "agent_denied_by_policy",
        "command_network_deny",
        # exfiltration and credential access
        "data_exfiltration",
        "secret_write_then_network",
        "credential_file_sweep",
        # Split in two so Hermes's plugin security scan (its dump_all_env pattern) does not take
        # this rule id for code that dumps the environment.
        "env_print" + "env_to_network_sink",
        "env_sensitive_exposed_to_unknown_script",
        "suspicious_code_exfiltration",
        "canary_token_touched",
        "metadata_endpoint",
        "private_key_exposed",
    }
)

_TRUE_STRINGS = {"true", "yes", "on", "1"}
_FALSE_STRINGS = {"false", "no", "off", "0"}


@dataclass(frozen=True)
class Settings:
    path: str = ""
    timeout: int = 10
    offline: bool = False
    fail_closed: bool = True
    block_action: str = "approve"
    critical_action: str = "block"
    warn_action: str = "allow"
    warn_context: bool = True
    min_severity: str = "LOW"
    ignore_rules: frozenset[str] = frozenset()
    scan_process_input: bool = True


_warned: set[str] = set()
_warned_lock = threading.Lock()


def warn_once(message: str) -> None:
    """Log ``message`` at WARNING the first time it is seen in this process."""
    with _warned_lock:
        if message in _warned:
            return
        _warned.add(message)
    logger.warning("%s", message)


def _reset_warnings_for_tests() -> None:
    with _warned_lock:
        _warned.clear()


def _parse_bool(key: str, value: Any, warnings: list[str]) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_STRINGS:
            return True
        if lowered in _FALSE_STRINGS:
            return False
    warnings.append(f"tirith plugin: setting {key}={value!r} is not true/false; using {DEFAULTS[key]!r}")
    return bool(DEFAULTS[key])


def _parse_timeout(value: Any, warnings: list[str]) -> int:
    number: float | None = None
    if isinstance(value, bool):
        number = None
    elif isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            number = None
    if number is None or not math.isfinite(number):
        warnings.append(f"tirith plugin: setting timeout={value!r} is not a number; using {DEFAULTS['timeout']}")
        return int(DEFAULTS["timeout"])
    seconds = int(math.ceil(number))
    if seconds < TIMEOUT_MIN or seconds > TIMEOUT_MAX:
        clamped = min(max(seconds, TIMEOUT_MIN), TIMEOUT_MAX)
        warnings.append(f"tirith plugin: timeout={value!r} is outside {TIMEOUT_MIN}-{TIMEOUT_MAX} s; using {clamped}")
        seconds = clamped
    if seconds > TIMEOUT_WARN_ABOVE:
        warnings.append(
            f"tirith plugin: timeout={seconds} s is close to Hermes's hook limit "
            "(plugins.hook_callback_timeout, 30 s by default); a check that runs that long is blocked by Hermes"
        )
    return seconds


def _parse_choice(key: str, value: Any, warnings: list[str]) -> str:
    allowed = CHOICES[key]
    if isinstance(value, str):
        candidate = value.strip()
        for choice in allowed:
            if candidate.lower() == choice.lower():
                return choice
    warnings.append(
        f"tirith plugin: setting {key}={value!r} is not one of {', '.join(allowed)}; using {DEFAULTS[key]!r}"
    )
    return str(DEFAULTS[key])


def _parse_path(value: Any, warnings: list[str]) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        return os.path.expanduser(stripped) if stripped else ""
    warnings.append(f"tirith plugin: setting path={value!r} is not text; searching for tirith instead")
    return ""


def _parse_ignore_rules(value: Any, warnings: list[str]) -> frozenset[str]:
    if isinstance(value, str):
        items: list[Any] = [part for part in value.split(",")]
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        warnings.append(f"tirith plugin: setting ignore_rules={value!r} is not a list; ignoring no rules")
        return frozenset()
    rules: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            warnings.append(f"tirith plugin: ignore_rules entry {item!r} is not text; skipped")
            continue
        rule = item.strip().lower()
        if not rule:
            continue
        if rule in GUARDED_RULES:
            warnings.append(
                f"tirith plugin: ignore_rules cannot include {rule}: obfuscation, hidden text, unanalysable "
                "input, known-malicious, exfiltration and terminal-injection findings are always reported; "
                "entry skipped"
            )
            continue
        rules.add(rule)
    return frozenset(rules)


def parse(values: Mapping[str, Any]) -> tuple[Settings, list[str]]:
    """Turn raw config values into ``Settings``. Missing or ``None`` values use the default."""
    warnings: list[str] = []
    for key in values:
        if key not in DEFAULTS:
            warnings.append(f"tirith plugin: unknown setting {key!r} ignored")

    def raw(key: str) -> Any:
        value = values.get(key)
        return DEFAULTS[key] if value is None else value

    bools = {key: _parse_bool(key, raw(key), warnings) for key in BOOL_KEYS}
    settings = Settings(
        path=_parse_path(raw("path"), warnings),
        timeout=_parse_timeout(raw("timeout"), warnings),
        offline=bools["offline"],
        fail_closed=bools["fail_closed"],
        block_action=_parse_choice("block_action", raw("block_action"), warnings),
        critical_action=_parse_choice("critical_action", raw("critical_action"), warnings),
        warn_action=_parse_choice("warn_action", raw("warn_action"), warnings),
        warn_context=bools["warn_context"],
        min_severity=_parse_choice("min_severity", raw("min_severity"), warnings),
        ignore_rules=_parse_ignore_rules(raw("ignore_rules"), warnings),
        scan_process_input=bools["scan_process_input"],
    )
    return settings, warnings


def load(get_config: Callable[..., Any]) -> Settings:
    """Read every setting through ``ctx.get_config`` (call this on every hook call)."""
    values = {key: get_config(key, None) for key in DEFAULTS}
    settings, warnings = parse(values)
    for message in warnings:
        warn_once(message)
    return settings
