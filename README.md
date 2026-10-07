# hermes-plugin-tirith

[tirith](https://github.com/sheeki03/tirith) command checking for
[Hermes Agent](https://github.com/NousResearch/hermes-agent), as an opt-in plugin: before Hermes runs a
terminal command, the plugin runs your installed `tirith check` on it and sends any finding to Hermes's
normal approval prompt. Critical findings are refused.

**Status: 0.1.0, not released yet.** It needs tirith 0.5.0, which is not released yet.

The plugin itself is in [`tirith/`](tirith/); its [README](tirith/README.md) covers what it does,
settings, unattended runs, limits and the network and data disclosure. Short version:

```
# 1. install tirith 0.5.0 or later yourself (the plugin never downloads it)
brew install tirith
# 2. install and enable the plugin
hermes plugins install sheeki03/hermes-plugin-tirith/tirith
hermes plugins enable tirith
# 3. Hermes 0.21.5 and earlier: turn off the built-in check so commands are not checked twice
hermes config set security.tirith_enabled false
```

## Repository layout

| Path | What |
|---|---|
| `tirith/` | The plugin, exactly what Hermes installs (`plugin.yaml`, Python modules, README, LICENSE, CHANGELOG). Standard library only. |
| `tests/` | pytest suite. `fake_tirith.py` is a scriptable stand-in for the tirith binary. |
| `.github/workflows/ci.yml` | Lint, unit tests on Linux/macOS/Windows, Hermes loader tests, real-tirith tests. |
| `pyproject.toml` | Development settings only (pytest markers, ruff). Hermes ignores it: it is not next to `plugin.yaml`. |

## Development

```
uv venv -p 3.14 .venv
uv pip install -p .venv pytest pyyaml ruff
.venv/bin/python -m pytest -m "not realtirith and not hermes"
```

Test groups:

- **Unit tests** (default): settings, the decision table, approval keys, messages, binary discovery and the
  version gate, the subprocess contract (argv, stdin, environment, working directory, timeouts) and the
  hooks, all against the fake tirith.
- **`realtirith`**: run only when a tirith binary is provided. `TIRITH_TEST_BIN` is a tirith with the
  0.5.0 check contract (scans, policy, corpus); `TIRITH_OLD_BIN` is an older release that the version gate
  must refuse. `TIRITH_CORPUS_REPORT=<file>` writes the corpus table.
- **`hermes`**: loads the plugin through a real Hermes (`hermes_cli` importable, for example
  `uv pip install -p .venv -e <hermes-agent checkout>`), runs Hermes's own approval gate end to end, and
  runs `hermes plugins validate` and `hermes plugins doctor`.

```
.venv/bin/python -m pytest -m hermes
TIRITH_TEST_BIN=/path/to/tirith TIRITH_OLD_BIN=/path/to/tirith-0.4.2 .venv/bin/python -m pytest -m realtirith
.venv/bin/hermes plugins validate --install-deps tirith
```

## Licence

MIT, see [LICENSE](LICENSE). tirith itself is AGPL-3.0 or commercial; this plugin only runs it as a
separate program.
