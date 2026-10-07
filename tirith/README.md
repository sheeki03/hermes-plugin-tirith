# tirith for Hermes

Checks every command Hermes is about to run in a terminal with [tirith](https://github.com/sheeki03/tirith),
the terminal security tool you install yourself. tirith looks for lookalike and homograph URLs,
pipe-to-shell downloads, obfuscated execution, credential exfiltration, malicious packages and terminal
injection. What it finds goes to Hermes's normal approval prompt; critical findings are refused.

## Requirements

- tirith **0.5.0 or later**, installed by you. The plugin never downloads, installs or updates tirith.
- Hermes **0.21.5 or later**.
- Linux, macOS or Windows. Python standard library only; nothing to `pip install`.

## Install

1. Install tirith 0.5.0 or later (this plugin never downloads or updates it):

   ```
   brew install tirith      # or: npm install -g tirith / cargo install tirith / scoop install tirith
   tirith --version
   ```

   The signed release installers are listed at <https://github.com/sheeki03/tirith#install>.

2. Install and enable the plugin:

   ```
   hermes plugins install tirith                                  # from the catalog, once listed
   hermes plugins install sheeki03/hermes-plugin-tirith/tirith    # directly from GitHub
   hermes plugins enable tirith
   ```

3. Hermes 0.21.5 and earlier also run a built-in tirith check. Turn it off so commands are not checked
   twice:

   ```
   hermes config set security.tirith_enabled false
   ```

## What happens to a command

Before each `terminal` command, and before each line the agent finishes in a background terminal
(`process_manage` submit, or a write that ends the line), the plugin runs
`tirith check --json --non-interactive --shell posix` with the command on standard input, in the
command's working directory. Then:

| tirith says | With the default settings |
|---|---|
| allow | The command runs. |
| warn | The command runs; tirith's warning is added to the command result so the agent sees it. |
| block | Hermes asks you. The prompt shows the findings, the command and its directory. |
| block with a CRITICAL finding | Refused. Hermes cannot approve it; change your tirith policy if it is a false positive. |
| the command asks tirith to skip the check (`TIRITH=0`) and your tirith policy allows that | Hermes asks you: a prefix the agent wrote is not your consent. |
| no answer: tirith missing, older than 0.5.0, timed out, crashed, no verdict | Hermes asks you (fail closed). |

**Background terminals.** `process_manage` sends keystrokes: `write` types text, `submit` types text
and Enter. The plugin keeps what was typed into each background process and checks the whole line when
a call ends it, so a line typed over several calls (even by another task) is checked as one. A shell
command that goes on over several lines (a trailing `\`, `|`, `&&` or `||`, an open quote, a heredoc)
is checked as a whole each time a line of it is sent. Typed text counts once Hermes reports that the
call ran, so a refused line stays typed and is checked again when the line is ended again. Input with
control keys (Tab, Esc, Ctrl-A and other Ctrl keys, a lone carriage return, NUL, DEL) counts as a
failed check: a terminal can treat them as editing keys (completion, moving the cursor, recalling
history) and run a different line than the text tirith would see. Ctrl-C or Ctrl-D on its own, with
nothing typed, goes through.

The agent never sees tirith's long descriptions or fix-it advice, only the finding titles and rule ids,
so it cannot be steered by them. The command excerpt in the prompt shows control, bidi and zero-width
characters as `\u{XXXX}`, so a command cannot disguise itself in the prompt that asks about it.

## Settings

Set them in `config.yaml` under `plugins.entries.tirith.settings`, or in the Hermes Desktop plugin
settings. They are read on every command, so changes apply at once.

| Setting | Default | Meaning |
|---|---|---|
| `path` | `""` | Empty: look for tirith on `PATH`, then in the usual install folders (Homebrew, `~/.local/bin`, `~/.cargo/bin`, Nix, npm, Scoop, `%LOCALAPPDATA%\tirith\bin`). Or an absolute path. |
| `timeout` | `10` | Seconds per check, 1-60. Keep it below `plugins.hook_callback_timeout` (30 s by default). |
| `offline` | `false` | Run checks with `TIRITH_OFFLINE=1` (see Disclosure). |
| `fail_closed` | `true` | When tirith cannot give an answer, ask (and block in unattended runs). Off: the command runs unchecked and a warning is logged. |
| `block_action` | `approve` | tirith blocks: `approve` asks you, `block` refuses. |
| `critical_action` | `block` | A CRITICAL finding: `block` refuses, `approve` asks you. |
| `warn_action` | `allow` | tirith warns: `allow` runs it, `approve` asks you, `block` refuses. |
| `warn_context` | `true` | With `warn_action: allow`, add tirith's warning to the command result. |
| `min_severity` | `LOW` | Warnings below this severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) are ignored. Never applies to blocks. |
| `ignore_rules` | `[]` | Rule ids whose warnings are ignored. Never applies to blocks. Obfuscation, hidden-text, unanalysable-input, known-malicious, exfiltration and terminal-injection rules (the list is `GUARDED_RULES` in `_settings.py`), and every CRITICAL finding, cannot be ignored. |
| `scan_process_input` | `true` | Also check input sent to background terminals (`process_manage` write/submit). |

Filters never relax a block. To stop tirith from blocking something, use tirith's own policy
(`tirith explain --rule <rule_id>` shows what a rule does; `tirith policy` manages the policy), where your
organisation's and team's policy still apply.

## Unattended runs

No check waits for a person. tirith runs non-interactively with a timeout, and every "ask" goes through
Hermes's approval gate, which handles cron jobs, `hermes chat -q` and messaging platforms with
`approvals.cron_mode`, `approvals.single_query_mode` and `approvals.unattended_mode` (all `deny` by
default). With the default settings, unattended runs execute allowed and warned commands, and refuse
blocked commands, failed checks and critical findings. Keep `warn_action: allow` for cron jobs.
`--yolo` and `approvals.mode: off` approve every "ask", but never a refusal.

## Approvals and "Always"

An approval covers one exact command, in one directory, with one set of findings. A different directory,
a changed command or a new finding (for example after a threat database update) asks again.

For blocks, bypass requests and failed checks, "Session" and "Always" both last only until the Hermes
session ends or Hermes restarts: the approval key includes a random value from the running process. Hermes
still saves an "Always" answer to `command_allowlist` in `config.yaml`; such entries
(`plugin_rule:tirith:...:s...`) never match again and can be deleted. For warnings with
`warn_action: approve`, "Always" is permanent for that exact command, directory and finding set.

## Hermes 0.21.5 and earlier

These versions still ship a built-in tirith check that runs before plugins, so a command can be checked
(and prompted) twice. Run `hermes config set security.tirith_enabled false`; the plugin logs a warning
once while the built-in check is present. Hermes 0.21.4 and earlier are not supported: there a crashing
or slow plugin let the command run.

## Limits

- Hermes does not tell plugins which backend (local, Docker, SSH, ...) runs the command or its exact
  directory. The plugin uses the call's `workdir`, else the directory reported by the last command, else
  `TERMINAL_CWD`, else Hermes's own directory. For remote and container backends this is approximate, and
  their commands are checked too.
- Another plugin can change a command after tirith checked it (a `modify` directive). The plugin notices
  afterwards and logs a warning; it cannot check the changed command.
- `execute_code` (Python) and file-writing tools are not checked; tirith checks shell commands.
- The plugin checks the text of each line. A background shell can still run something else for it:
  an alias, function or history entry set up earlier, or a script written with a file tool.
- A Hermes approval cannot be limited to one session by a plugin, hence the salted keys above.

## Disclosure

**What this plugin does on your machine.** Before every `terminal` command, and every line the agent
finishes in a background terminal, the plugin runs the `tirith` program you installed
(`tirith check`), in the command's working directory, with the command on standard input. This adds
roughly 0.1-0.5 s per command. It reads its own settings only, stores nothing outside memory, makes no
network requests itself, sends no telemetry, and never downloads, installs or updates tirith or anything
else.

**What tirith does when the plugin runs it** (the same as in your shell): it records each check in its
local audit log (tagged `hermes`). Unless `offline: true`, it may refresh its signed threat database in
the background and look up package and URL reputation with OSV.dev, deps.dev, ecosyste.ms, and Google Safe
Browsing (only if you configured a key), plus any feeds, a running tirith daemon, policy webhooks or a team
policy server you set up. `offline: true` sets `TIRITH_OFFLINE=1`: checks use only the cached threat
database, and lookups that need the network are reported as incomplete. Policy webhooks you configured
still fire.

**Licences.** This plugin is MIT. tirith itself is AGPL-3.0 or commercial; the plugin only runs it as a
separate program and grants no rights to tirith.

## Logs

The plugin logs to Hermes's `agent.log` under `hermes_plugins.tirith`: one INFO line per command that was
not simply allowed (kind, rule ids, a hash of the command, never the command itself), and a WARNING once
per problem (tirith missing or too old, invalid settings, double checking).

## Licence

MIT. See [LICENSE](LICENSE).

## Development

Tests, CI and development notes live in the repository root:
<https://github.com/sheeki03/hermes-plugin-tirith>.
