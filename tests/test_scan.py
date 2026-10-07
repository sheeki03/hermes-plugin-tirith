from __future__ import annotations

import json
import os
import re
import time

import pytest

from tirith import _scan
from tirith._scan import RunResult, ScanOutcome, child_env, classify, parse_verdict, resolve_cwd, scan
from tirith._settings import Settings

from fake_tirith import calls, make_fake, verdict


def _out(v) -> bytes:
    return (json.dumps(v) + "\n").encode()


BLOCK = verdict("block", [("curl_pipe_shell", "HIGH", "Pipe to interpreter")])
WARN = verdict("warn", [("lookalike_tld", "MEDIUM", "Lookalike TLD")])
ALLOW = verdict("allow")
BYPASS = verdict("allow", bypass_honored=True)


# --- classification (decision table input side) -------------------------------------


@pytest.mark.parametrize(
    "rc,stdout,kind,reason_class",
    [
        (0, _out(ALLOW), "allow", ""),
        (0, _out(BYPASS), "bypass", ""),
        (1, _out(BLOCK), "block", ""),
        (2, _out(WARN), "warn", ""),
        (3, _out(verdict("warn_ack", [("x", "LOW", "x")])), "warn_ack", ""),
        (4, _out(BLOCK), "block", ""),
        # no verdict: usage error, stdin over cap, crash
        (0, b"", "error", "no_verdict"),
        (1, b"", "error", "no_verdict"),
        (2, b"error: unexpected argument\n", "error", "no_verdict"),
        (3, b"", "error", "no_verdict"),
        (4, b"", "error", "no_verdict"),
        (5, b"", "error", "exit_code"),
        (101, b"thread main panicked\n", "error", "exit_code"),
        (-9, b"", "error", "exit_code"),
        # malformed JSON
        (1, b'{"action": "block", "findings": [', "error", "no_verdict"),
        (0, b'{"something": "else"}\n', "error", "no_verdict"),
        # exit code and verdict disagree: the stricter wins
        (0, _out(BLOCK), "block", ""),
        (1, _out(ALLOW), "block", ""),
        (2, _out(ALLOW), "warn", ""),
        (0, _out(WARN), "warn", ""),
        (1, _out(BYPASS), "block", ""),
        (5, _out(ALLOW), "error", "exit_code"),
        (101, _out(BLOCK), "block", ""),
        (0, _out(verdict("ask")), "error", "verdict"),
        (1, _out(verdict("ask")), "block", ""),
    ],
)
def test_classify(rc, stdout, kind, reason_class):
    outcome = classify(RunResult(rc=rc, stdout=stdout))
    assert outcome.kind == kind
    assert outcome.reason_class == reason_class


def test_classify_deferred_flag():
    assert classify(RunResult(rc=4, stdout=_out(BLOCK))).deferred is True
    assert classify(RunResult(rc=1, stdout=_out(BLOCK))).deferred is False


def test_classify_disagreement_is_noted():
    outcome = classify(RunResult(rc=0, stdout=_out(BLOCK)))
    assert outcome.notes and "disagree" in outcome.notes[0]


def test_classify_spawn_and_timeout():
    assert classify(RunResult(rc=None, error="could not start")).reason_class == "spawn"
    assert classify(RunResult(rc=None, timed_out=True)).reason_class == "timeout"


def test_findings_are_normalised():
    raw = verdict("block", [("r1", "high", "T1"), ("r2", "weird", ""), ("r3", "LOW", "T3", "my_rule")])
    raw["findings"].append("junk")
    outcome = classify(RunResult(rc=1, stdout=_out(raw)))
    assert [(f.rule_id, f.severity, f.title) for f in outcome.findings] == [
        ("r1", "HIGH", "T1"),
        ("r2", "HIGH", "r2"),
        ("r3", "LOW", "T3"),
    ]
    assert outcome.findings[2].key == "custom_rule_match:my_rule"


def test_parse_verdict_takes_the_last_verdict_line():
    text = "noise\n" + json.dumps({"x": 1}) + "\n" + json.dumps(WARN) + "\n" + json.dumps(BLOCK) + "\ntrailing\n"
    assert parse_verdict(text)["action"] == "block"
    assert parse_verdict(json.dumps(ALLOW, indent=2))["action"] == "allow"
    assert parse_verdict("") is None


# --- environment ----------------------------------------------------------------------


def test_child_env_strips_and_adds():
    base = {"PATH": "/bin", "TIRITH": "0", "TIRITH_DEFER": "1", "TIRITH_INTERACTIVE": "1", "TIRITH_OFFLINE": "0"}
    env = child_env(Settings(), session_id="abc", base=base)
    assert "TIRITH" not in env and "TIRITH_DEFER" not in env and "TIRITH_INTERACTIVE" not in env
    assert env["TIRITH_INTEGRATION"] == "hermes"
    assert env["TIRITH_INTEGRATION_VERSION"] == "0.1.0"
    assert env["TIRITH_OFFLINE"] == "0"  # offline off: the user's own value is left alone
    assert env["PATH"] == "/bin"
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,128}", env["TIRITH_SESSION_ID"])


def test_child_env_strips_case_insensitively():
    env = child_env(Settings(), base={"tirith": "0", "Tirith_Defer": "1"})
    assert not any(k.upper() in ("TIRITH", "TIRITH_DEFER") for k in env)


def test_offline_forces_tirith_offline():
    env = child_env(Settings(offline=True), base={"TIRITH_OFFLINE": "0"})
    assert env["TIRITH_OFFLINE"] == "1"


def test_session_ids():
    a = child_env(Settings(), session_id="s1", base={})["TIRITH_SESSION_ID"]
    b = child_env(Settings(), session_id="s2", base={})["TIRITH_SESSION_ID"]
    c = child_env(Settings(), task_id="s1", base={})["TIRITH_SESSION_ID"]
    assert a != b and a == c
    assert child_env(Settings(), session_id="\udcff\n../x", base={})["TIRITH_SESSION_ID"].startswith("hermes-")
    assert len(child_env(Settings(), base={})["TIRITH_SESSION_ID"]) == 39


# --- working directory ------------------------------------------------------------------


def test_cwd_order(tmp_path, monkeypatch):
    work, tracked, terminal = (tmp_path / n for n in ("work", "tracked", "terminal"))
    for d in (work, tracked, terminal):
        d.mkdir()
    env = {"TERMINAL_CWD": str(terminal)}
    monkeypatch.chdir(tmp_path)
    assert resolve_cwd({"workdir": str(work)}, str(tracked), env) == str(work)
    assert resolve_cwd({}, str(tracked), env) == str(tracked)
    assert resolve_cwd({}, None, env) == str(terminal)
    assert os.path.samefile(resolve_cwd({}, None, {}), tmp_path)
    # missing directories fall through
    assert resolve_cwd({"workdir": str(tmp_path / "gone")}, str(tmp_path / "gone2"), env) == str(terminal)
    # a relative workdir is taken relative to the session directory
    (tracked / "sub").mkdir()
    assert resolve_cwd({"workdir": "sub"}, str(tracked), env) == str(tracked / "sub")


def test_cwd_expands_user(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / "p").mkdir()
    assert resolve_cwd({"workdir": "~/p"}, None, {}) == str(tmp_path / "p")


# --- running the fake -----------------------------------------------------------------------


def do_scan(fake, command, tmp_path, timeout=10, env=None):
    return scan(
        command,
        binary=fake,
        version="0.5.0",
        cwd=str(tmp_path),
        env=env if env is not None else child_env(Settings()),
        timeout=timeout,
    )


def test_exact_argv_and_stdin(tmp_path):
    fake = make_fake(str(tmp_path / "bin"))
    outcome = do_scan(fake, "echo hi", tmp_path)
    assert outcome.kind == "allow"
    (call,) = calls(fake)
    assert call["args"] == ["check", "--json", "--non-interactive", "--shell", "posix"]
    assert call["stdin"] == b"echo hi"
    assert os.path.samefile(call["cwd"], tmp_path)
    assert call["env"]["TIRITH_INTEGRATION"] == "hermes"


@pytest.mark.parametrize(
    "command",
    ["a\nb\r\nc", "nul\x00byte", "emoji \U0001f600", "rtl ‮ text אב", "-n --json", "--version"],
)
def test_stdin_round_trip(tmp_path, command):
    fake = make_fake(str(tmp_path / "bin"))
    do_scan(fake, command, tmp_path)
    (call,) = calls(fake)
    assert call["stdin"] == command.encode("utf-8")
    assert call["args"] == ["check", "--json", "--non-interactive", "--shell", "posix"]


def test_oversized_command_is_refused_without_spawning(tmp_path):
    fake = make_fake(str(tmp_path / "bin"))
    outcome = do_scan(fake, "x" * (1024 * 1024 + 1), tmp_path)
    assert outcome.kind == "error" and outcome.reason_class == "too_large"
    assert calls(fake) == []
    assert do_scan(fake, "x" * (1024 * 1024), tmp_path).kind == "allow"


def test_lone_surrogate_is_refused_without_spawning(tmp_path):
    fake = make_fake(str(tmp_path / "bin"))
    outcome = do_scan(fake, "echo \udcff", tmp_path)
    assert outcome.kind == "error" and outcome.reason_class == "encoding"
    assert calls(fake) == []


def test_environment_reaches_the_child(tmp_path):
    fake = make_fake(str(tmp_path / "bin"), {"default": {"rc": 1, "verdict": BLOCK}})
    base = dict(os.environ, TIRITH="0", TIRITH_DEFER="1", TIRITH_INTERACTIVE="1")
    env = child_env(Settings(offline=True), session_id="s", base=base)
    outcome = do_scan(fake, "curl x", tmp_path, env=env)
    # without stripping, the fake would honour TIRITH=0 (allow) or TIRITH_DEFER=1 (exit 4)
    assert outcome.kind == "block" and outcome.rc == 1
    (call,) = calls(fake)
    seen = call["env"]
    assert "TIRITH" not in seen and "TIRITH_DEFER" not in seen and "TIRITH_INTERACTIVE" not in seen
    assert seen["TIRITH_OFFLINE"] == "1"
    assert seen["TIRITH_SESSION_ID"] == env["TIRITH_SESSION_ID"]


def test_timeout_kills_the_child_quickly(tmp_path):
    fake = make_fake(str(tmp_path / "bin"), {"default": {"rc": 0, "verdict": ALLOW, "sleep": 30}})
    started = time.monotonic()
    outcome = do_scan(fake, "sleep", tmp_path, timeout=1)
    elapsed = time.monotonic() - started
    assert outcome.kind == "error" and outcome.reason_class == "timeout"
    assert elapsed < 8


def test_missing_binary_is_a_spawn_error(tmp_path):
    outcome = do_scan(str(tmp_path / "nope"), "ls", tmp_path)
    assert outcome.kind == "error" and outcome.reason_class == "spawn"


def test_scan_outcome_defaults():
    assert ScanOutcome(kind="allow").findings == ()
    assert _scan.error_outcome("x", "y").kind == "error"
