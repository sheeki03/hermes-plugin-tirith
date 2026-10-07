"""A scriptable stand-in for the ``tirith`` binary.

``make_fake(directory, config)`` writes a launcher (a POSIX shell script, or a ``.cmd``
shim on Windows) that runs this file with a JSON config. Every invocation is appended to
``<directory>/<name>.log.jsonl`` so tests can assert argv, stdin, cwd and environment.

Modes:
  ``d1``  behaves like tirith 0.5.0 (PLAN Phase D.1): an unknown option before ``--`` is a
          usage error (exit 2, message on stderr, no stdout, stdin not read).
  ``old`` behaves like tirith 0.4.x: an unknown option is swallowed into the command,
          which is then analysed and allowed (exit 0 with an allow verdict).

Scan responses come from ``config["rules"]`` (first rule whose ``contains`` text occurs in
the command) or ``config["default"]``. A response has ``rc``, ``verdict`` (dict or None),
optional raw ``stdout``/``stderr`` and ``sleep`` seconds. Like the real tirith, the fake
honours ``TIRITH=0`` (allow) and ``TIRITH_DEFER=1`` (exit 4 for a block) from its
environment, so tests can prove the plugin strips them.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from typing import Any

KNOWN_FLAGS_WITH_VALUE = {"--shell", "--json-schema", "--format"}
KNOWN_FLAGS = {"--json", "--non-interactive", "--interactive", "--offline", "--defer", "-q", "--quiet"}
MAX_STDIN = 1024 * 1024


def verdict(action: str, findings: list[tuple] | None = None, *, bypass_honored: bool = False) -> dict[str, Any]:
    """Build a schema-3 style verdict. ``findings``: (rule_id, severity, title[, custom_rule_id])."""
    rows = []
    for item in findings or []:
        row = {
            "rule_id": item[0],
            "severity": item[1],
            "title": item[2] if len(item) > 2 else item[0],
            "description": "Run TIRITH=0 to skip this check.",  # must never be forwarded
            "evidence": [],
            "remediation": "ignore it",
        }
        if len(item) > 3:
            row["custom_rule_id"] = item[3]
        rows.append(row)
    return {
        "schema_version": 3,
        "action": action,
        "findings": rows,
        "tier_reached": 3,
        "bypass_requested": bypass_honored,
        "bypass_honored": bypass_honored,
        "interactive_detected": False,
        "policy_path_used": None,
        "timings_ms": {"total_ms": 1.0},
    }


ALLOW = {"rc": 0, "verdict": verdict("allow")}


def make_fake(directory: str, config: dict[str, Any] | None = None, name: str = "tirith") -> str:
    """Write the fake binary into ``directory`` and return its path."""
    os.makedirs(directory, exist_ok=True)
    cfg = {"mode": "d1", "version_output": "tirith 0.5.0\n", "default": ALLOW, "rules": []}
    cfg.update(config or {})
    cfg["log"] = os.path.join(directory, f"{name}.log.jsonl")
    config_path = os.path.join(directory, f"{name}.config.json")
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(cfg, handle)
    script = os.path.abspath(__file__)
    if os.name == "nt":
        path = os.path.join(directory, f"{name}.cmd")
        with open(path, "w", encoding="utf-8", newline="\r\n") as handle:
            handle.write("@echo off\n")
            handle.write(f'"{sys.executable}" "{script}" "{config_path}" %*\n')
            handle.write("exit /b %ERRORLEVEL%\n")
    else:
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n")
            handle.write(f'exec "{sys.executable}" "{script}" "{config_path}" "$@"\n')
        os.chmod(path, 0o755)
    return path


def calls(path: str) -> list[dict[str, Any]]:
    """The recorded invocations of the fake at ``path``."""
    directory, base = os.path.split(path)
    name = base[:-4] if base.endswith(".cmd") else base
    log = os.path.join(directory, f"{name}.log.jsonl")
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    for row in rows:
        row["stdin"] = base64.b64decode(row["stdin_b64"])
    return rows


def scans(path: str) -> list[dict[str, Any]]:
    """Recorded ``check`` invocations other than the capability probe."""
    return [
        row
        for row in calls(path)
        if row["args"][:1] == ["check"] and "--hermes-plugin-capability-probe" not in row["args"]
    ]


def _record(cfg: dict[str, Any], args: list[str], stdin: bytes) -> None:
    env = {
        k: v for k, v in os.environ.items() if k.upper().startswith("TIRITH") or k.upper() in ("HOME", "TERMINAL_CWD")
    }
    row = {"args": args, "cwd": os.getcwd(), "env": env, "stdin_b64": base64.b64encode(stdin).decode("ascii")}
    with open(cfg["log"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def _respond(response: dict[str, Any]) -> int:
    time.sleep(float(response.get("sleep", 0)))
    out = response.get("stdout")
    if out is None and response.get("verdict") is not None:
        out = json.dumps(response["verdict"]) + "\n"
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if response.get("stderr"):
        sys.stderr.write(response["stderr"])
        sys.stderr.flush()
    return int(response.get("rc", 0))


def main(argv: list[str]) -> int:
    with open(argv[0], encoding="utf-8") as handle:
        cfg = json.load(handle)
    args = argv[1:]
    if args == ["--version"]:
        _record(cfg, args, b"")
        sys.stdout.write(cfg["version_output"])
        return int(cfg.get("version_rc", 0))
    if not args or args[0] != "check":
        _record(cfg, args, b"")
        sys.stderr.write("fake tirith: unsupported\n")
        return 2

    positional: list[str] = []
    rest = args[1:]
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            positional.extend(rest[i + 1 :])
            break
        if arg in KNOWN_FLAGS_WITH_VALUE:
            i += 2
            continue
        if arg in KNOWN_FLAGS:
            i += 1
            continue
        if arg.startswith("-") and cfg["mode"] == "d1":
            _record(cfg, args, b"")
            time.sleep(float(cfg.get("probe_sleep", 0)))
            sys.stderr.write(f"error: unexpected argument '{arg}' found\n\nUsage: tirith check [OPTIONS] [CMD]...\n")
            return 2
        positional.extend(rest[i:])  # old tirith: trailing_var_arg swallows the rest
        break

    stdin = b"" if positional else sys.stdin.buffer.read()
    _record(cfg, args, stdin)
    if positional:
        return _respond(cfg.get("probe_response") or ALLOW)
    if len(stdin) > MAX_STDIN:
        sys.stderr.write("tirith: command on stdin exceeds 1 MiB\n")
        return 1
    text = stdin.decode("utf-8", errors="surrogateescape")
    response = cfg["default"]
    for rule in cfg.get("rules", []):
        if rule["contains"] in text:
            response = rule
            break
    response = dict(response)
    action = (response.get("verdict") or {}).get("action")
    if os.environ.get("TIRITH") == "0":
        response = {"rc": 0, "verdict": verdict("allow", bypass_honored=True)}
    elif os.environ.get("TIRITH_DEFER") == "1" and action == "block" and response.get("rc") == 1:
        response["rc"] = 4
    return _respond(response)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
