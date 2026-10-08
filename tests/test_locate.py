from __future__ import annotations

import os
import subprocess

import pytest

import tirith as plugin
from tirith import _locate
from tirith._locate import PROBE_FLAG, Locator, candidates, gate
from tirith._scan import child_env
from tirith._settings import Settings

from fake_tirith import calls, make_fake

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX install folders")
WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows install folders")


@pytest.fixture
def env():
    return child_env(Settings())


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Empty PATH and home, so only the fakes a test installs can be found."""
    home = tmp_path / "home"
    home.mkdir()
    empty = tmp_path / "empty-path"
    empty.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    for key in ("LOCALAPPDATA", "APPDATA"):
        monkeypatch.setenv(key, str(home / key))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(_locate.os.path, "isfile", _only_under(tmp_path, os.path.isfile))
    return home


def _only_under(root, real_isfile):
    """Hide system-wide tirith installs (/opt/homebrew/bin/tirith and friends) from the tests."""
    root = os.path.realpath(str(root))

    def isfile(path):
        return os.path.normcase(os.path.realpath(path)).startswith(os.path.normcase(root)) and real_isfile(path)

    return isfile


def test_explicit_path_is_the_only_candidate(tmp_path, isolated):
    fake = make_fake(str(tmp_path / "custom"))
    other = make_fake(str(isolated / ".local" / "bin"))
    assert candidates(fake, os.environ) == [fake]
    assert other not in candidates(fake, os.environ)


def test_explicit_missing_path_is_not_found(tmp_path, isolated, env):
    result = Locator().resolve(str(tmp_path / "missing" / "tirith"), env, 5)
    assert result.status == "not_found"
    assert "not found" in result.reason


def test_nothing_installed(isolated, env):
    result = Locator().resolve("", env, 5)
    assert result.status == "not_found"
    assert "0.5.0" in result.reason


def test_found_on_path(tmp_path, isolated, monkeypatch, env):
    fake = make_fake(str(tmp_path / "on-path"))
    monkeypatch.setenv("PATH", str(tmp_path / "on-path"))
    found = candidates("", os.environ)
    assert len(found) == 1 and os.path.samefile(found[0], fake)
    assert Locator().resolve("", child_env(Settings()), 5).ok


@POSIX_ONLY
def test_fallback_install_folders(isolated, env):
    fake = make_fake(str(isolated / ".local" / "bin"))
    hermes_copy = make_fake(str(isolated / ".hermes" / "bin"))
    assert candidates("", os.environ) == [fake, hermes_copy]


@WINDOWS_ONLY
def test_windows_install_folders(isolated):
    local = make_fake(str(isolated / "LOCALAPPDATA" / "tirith" / "bin"))
    os.replace(local, local[:-4] + ".exe")  # the folder entry is tirith.exe
    npm = make_fake(str(isolated / "APPDATA" / "npm"))
    found = candidates("", os.environ)
    assert found[0].endswith("tirith.exe") and found[-1] == npm


def test_old_tirith_is_refused(tmp_path, env):
    fake = make_fake(str(tmp_path / "old"), {"mode": "old", "version_output": "tirith 0.4.2\n"})
    result = gate(fake, env, 5)
    assert result.status == "too_old"
    assert result.version == "0.4.2"
    assert "tirith 0.4.2" in result.reason and "older than 0.5.0" in result.reason and fake in result.reason
    probe = [c for c in calls(fake) if PROBE_FLAG in c["args"]]
    assert probe and probe[0]["args"] == ["check", "--json", "--non-interactive", "--shell", "posix", PROBE_FLAG]


def test_new_tirith_passes(tmp_path, env):
    fake = make_fake(str(tmp_path / "new"))
    result = gate(fake, env, 5)
    assert result.ok and result.version == "0.5.0" and result.reason == ""


def test_prerelease_build_with_the_new_contract_passes(tmp_path, env):
    fake = make_fake(str(tmp_path / "pre"), {"version_output": "tirith 0.4.2\n"})
    result = gate(fake, env, 5)
    assert result.ok and "pre-release" in result.reason


def test_probe_that_exits_zero_is_refused(tmp_path, env):
    # exit 0 without a verdict still means the option was accepted
    fake = make_fake(str(tmp_path / "odd"), {"mode": "old", "probe_response": {"rc": 0, "stdout": "ok\n"}})
    assert gate(fake, env, 5).status == "too_old"


@pytest.mark.parametrize(
    "reject",
    [
        {"rc": 1, "stderr": ""},  # a crash or a policy failure, not a usage error
        {"rc": 101, "stderr": "thread 'main' panicked\n"},
        {"rc": 2, "stderr": "error: invalid value 'posix' for '--shell <SHELL>'\n"},  # some other usage error
        {"rc": 2, "stderr": ""},
    ],
)
def test_probe_rejection_must_be_a_usage_error_for_the_probe(tmp_path, env, reject):
    fake = make_fake(str(tmp_path / "odd"), {"reject_response": reject})
    locator = Locator()
    result = locator.check(fake, env, 5)
    assert result.status == "error" and "unexpected answer" in result.reason and PROBE_FLAG in result.reason
    locator.check(fake, env, 5)
    assert len(calls(fake)) == 4  # an unexpected answer is not cached


def test_probe_timeout_is_an_error_and_not_cached(tmp_path, env):
    fake = make_fake(str(tmp_path / "slow"), {"probe_sleep": 30})
    locator = Locator()
    result = locator.check(fake, env, 1)
    assert result.status == "error" and "in time" in result.reason
    make_fake(str(tmp_path / "slow"))  # same path, now fast (new config)
    assert locator.check(fake, env, 5).ok


def test_first_passing_candidate_wins(tmp_path, isolated, monkeypatch, env):
    stale = make_fake(str(tmp_path / "stale"), {"mode": "old", "version_output": "tirith 0.4.1\n"})
    monkeypatch.setenv("PATH", str(tmp_path / "stale"))
    if os.name == "nt":
        fresh = make_fake(str(isolated / "APPDATA" / "npm"))
    else:
        fresh = make_fake(str(isolated / ".local" / "bin"))
    result = Locator().resolve("", child_env(Settings()), 5)
    assert result.ok and os.path.samefile(result.path, fresh)
    assert not os.path.samefile(stale, fresh)


def test_first_failure_is_reported_when_none_pass(tmp_path, isolated, monkeypatch):
    make_fake(str(tmp_path / "stale"), {"mode": "old", "version_output": "tirith 0.4.1\n"})
    monkeypatch.setenv("PATH", str(tmp_path / "stale"))
    result = Locator().resolve("", child_env(Settings()), 5)
    assert result.status == "too_old" and "0.4.1" in result.reason


def test_results_are_cached_until_the_binary_changes(tmp_path, env):
    fake = make_fake(str(tmp_path / "c"))
    locator = Locator()
    assert locator.check(fake, env, 5).ok
    assert locator.check(fake, env, 5).ok
    assert len(calls(fake)) == 2  # one --version, one probe
    with open(fake, "a", encoding="utf-8") as handle:
        handle.write("\n")  # size and mtime change, as after an upgrade
    assert locator.check(fake, env, 5).ok
    assert len(calls(fake)) == 4


def test_negative_results_expire(tmp_path, env):
    now = [1000.0]
    fake = make_fake(str(tmp_path / "n"), {"mode": "old"})
    locator = Locator(clock=lambda: now[0])
    assert locator.check(fake, env, 5).status == "too_old"
    assert locator.check(fake, env, 5).status == "too_old"
    assert len(calls(fake)) == 2
    now[0] += 61
    assert locator.check(fake, env, 5).status == "too_old"
    assert len(calls(fake)) == 4


def test_register_never_runs_tirith(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("register() must not start processes")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    from conftest import RecordingCtx

    ctx = RecordingCtx()
    plugin.register(ctx)
    assert sorted(ctx.hooks) == ["post_tool_call", "pre_tool_call", "transform_tool_result"]
    assert ctx.get_config_calls == 0


def test_current_directory_is_never_searched(tmp_path, isolated, monkeypatch):
    project = tmp_path / "project"
    make_fake(str(project))  # a tirith planted in the project the agent works in
    monkeypatch.chdir(project)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "bin", str(tmp_path / "empty-path")]))
    assert candidates("", os.environ) == []
    assert candidates("tirith", os.environ) == []
    assert candidates(os.path.join(".", "tirith"), os.environ) == []
    result = Locator().resolve("tirith", child_env(Settings()), 5)
    assert result.status == "not_found" and "configured path" in result.reason


def test_program_name_setting_is_looked_up_on_path(tmp_path, isolated, monkeypatch):
    fake = make_fake(str(tmp_path / "tools"), name="tirith-next")
    monkeypatch.setenv("PATH", str(tmp_path / "tools"))
    (found,) = candidates("tirith-next", os.environ)
    assert os.path.samefile(found, fake)


@WINDOWS_ONLY
def test_windows_child_env_disables_current_directory_lookup():
    assert child_env(Settings(), base={})["NoDefaultCurrentDirectoryInExePath"] == "1"
