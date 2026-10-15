# tirith for Hermes

Checks every command Hermes is about to run in a terminal with [tirith](https://github.com/sheeki03/tirith),
the terminal security tool you install yourself. tirith looks for lookalike and homograph URLs,
pipe-to-shell downloads, obfuscated execution, credential exfiltration, malicious packages and terminal
injection. Blocks and required policy confirmations go to Hermes's approval prompt.
Ordinary warnings run with an advisory; critical blocks are refused by default.

## Requirements

- tirith **0.5.0 or later**, installed by you. The plugin never downloads, installs or updates tirith.
- Hermes **0.21.5 or later**.
- Linux, macOS or Windows. Python standard library only; nothing to `pip install`.

## Install

**Unreleased candidate.** Tirith 0.5.0 and the plugin are not published yet.
Use these installation commands only after publication and merge of the reviewed
plugin tree; the current placeholder default branch is not installable.
Catalog discovery requires a separate reviewed submission. Hermes does not
promise an automatic migration pointer.

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

3. If your older Hermes build still contains the built-in tirith check, turn
   it off to avoid checking commands twice:

   ```
   hermes config set security.tirith_enabled false
   ```

## What happens to a command

Before each `terminal` command, and before each line the agent finishes in a background terminal
(`process_manage` submit, a write that ends the line, or a close), the plugin runs
`tirith check --json --non-interactive --shell posix` with the command on standard input, in the
command's working directory. Then:

| tirith says | With the default settings |
|---|---|
| allow | The command runs. |
| warn | The command runs; tirith's warning is added to the command result so the agent sees it. |
| allow/warn with `requires_approval: true`, or mandatory warning acknowledgement | Hermes asks you before execution, even if warning filters would ignore the findings. `warn_action: block` can refuse instead. |
| block | Hermes asks you. The prompt shows the findings, the command and its directory. |
| block with a CRITICAL finding | Refused. Hermes cannot approve it; change your tirith policy if it is a false positive. |
| the command asks tirith to skip the check (`TIRITH=0`) and your tirith policy allows that | Hermes asks you: a prefix the agent wrote is not your consent. tirith 0.5.0 reports the honoured bypass in its verdict (`bypass_honored`); a build that exits 0 with no verdict counts as a failed check, which asks too. |
| no answer: tirith missing, older than 0.5.0, timed out, crashed, no verdict | Hermes asks you (fail closed). |

The first check runs three quick tirith commands to make sure the binary speaks the 0.5.0 check contract:
`tirith --version`, `tirith check` with an option no tirith knows (0.5.0 must reject it), and
`tirith check` on `echo tirith-hermes-plugin-contract-check` (the verdict must say whether the command
needs approval). A tirith that fails this, including a pre-release build without the approval field,
counts as older than 0.5.0. The result is kept until the binary changes.

**Background terminals.** `process_manage` sends keystrokes: `write` types text, `submit` types text
and Enter. The plugin keeps what was typed into each background process and checks the whole line when
a call ends it, so a line typed over several calls (even by another task) is checked as one. A shell
command that goes on over several lines (a trailing `\`, `|`, `&&` or `||`, an open quote, a heredoc)
is checked as a whole each time a line of it is sent. Typed text counts once Hermes reports that the
call ran, so a refused line stays typed and is checked again when the line is ended again. Input with
control keys (Tab, Esc, Ctrl-A and other Ctrl keys, a lone carriage return, NUL, DEL) counts as a
failed check: a terminal can treat them as editing keys (completion, moving the cursor, recalling
history) and run a different line than the text tirith would see. Ctrl-C or Ctrl-D on its own, with
nothing typed, goes through. `close` sends end of input, and a shell runs the text it holds at end of
input even without Enter, so a `close` checks everything typed so far as a whole command (with nothing
typed it goes through).

Overlapping calls are not ordered by callback completion. Multiple delivered
writes, an IO error that may follow partial delivery, or an unanswered call leave
explicit uncertainty; with `fail_closed: true`, later submit/close requests ask
rather than scan an invented line. Elapsed time never confirms delivery or erases
pending input. A confirmed process exit clears its input state. Turning off
`fail_closed` intentionally permits these unknown calls unchecked.

Tracking is bounded (1024 processes with unfinished input, 4096 unfinished calls). When it is
full, input that would need a new entry fails closed for that call only; nothing tracked is
evicted, and tracking recovers as calls finish and processes exit. Provider call IDs are scoped by session, task,
turn and API request so a later response can reuse an ID without consuming an
earlier call's pending input. Long finding text is clipped after reserving space
for the sanitized command excerpt and directory in approval prompts.

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
| `min_severity` | `LOW` | Ordinary warnings below this severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) are ignored. Never applies to blocks or required policy confirmation. |
| `ignore_rules` | `[]` | Rule ids whose ordinary warnings are ignored. Never applies to blocks or required policy confirmation. Obfuscation, hidden-text, unanalysable-input, known-malicious, exfiltration and terminal-injection rules (the list is `GUARDED_RULES` in `_settings.py`), and every CRITICAL finding, cannot be ignored. |
| `scan_process_input` | `true` | Also check input sent to background terminals (`process_manage` write/submit/close). |

Filters never relax a block or required policy confirmation. To stop tirith from blocking something, use tirith's own policy
(`tirith explain --rule <rule_id>` shows what a rule does; `tirith policy` manages the policy), where your
organisation's and team's policy still apply.

## Unattended runs

No check waits for a person. tirith runs non-interactively with a timeout, and every "ask" goes through
Hermes's approval gate, which handles cron jobs, `hermes chat -q` and messaging platforms with
`approvals.cron_mode`, `approvals.single_query_mode` and `approvals.unattended_mode` (all `deny` by
default). With the default settings, unattended runs execute ordinary allowed and warned
commands, and refuse blocks, required policy confirmations, failed/unknown checks and
critical findings. `warn_action: allow` never waives a policy confirmation.
`--yolo` and `approvals.mode: off` approve every "ask", but never a refusal.

## Approvals and "Always"

An approval covers one exact command, in one directory, with one set of findings. A different directory,
a changed command or a new finding (for example after a threat database update) asks again.

For policy approval/acknowledgement, blocks, bypass requests and failed checks, "Session" and "Always" both last only until the Hermes
session ends or Hermes restarts: the approval key includes a random value from the running process. Hermes
still saves an "Always" answer to `command_allowlist` in `config.yaml`; such entries
(`plugin_rule:tirith:...:s...`) never match again and can be deleted. For warnings with
`warn_action: approve`, "Always" is permanent for that exact command, directory and finding set.

## Older Hermes builds

Some older installations retain a built-in tirith check before plugins. The
plugin detects its actual presence and warns once; on those installations run
`hermes config set security.tirith_enabled false` to avoid duplicate checking.
The qualified 0.21.5 canary and current 0.21.7 source trees no longer contain it.
Hermes 0.21.4 and earlier are unsupported: their hook failure behavior could let
a command run after a plugin crash or timeout.

## Limits

- Hermes does not tell plugins which backend (local, Docker, SSH, ...) runs the command or its exact
  directory. The plugin uses the call's `workdir`, else the directory the task's last `cd` moved to (as
  reported in the command result), else `TERMINAL_CWD`, else Hermes's own directory. For remote and
  container backends this is approximate, and their commands are checked too.
- Another plugin can change a command after tirith checked it (a `modify` directive). The plugin notices
  afterwards and logs a warning; it cannot check the changed command.
- `execute_code` (Python) and file-writing tools are not checked; tirith checks shell commands.
- The plugin checks the text of each line. A background shell can still run something else for it:
  an alias, function or history entry set up earlier, or a script written with a file tool.
- A Hermes approval cannot be limited to one session by a plugin, hence the salted keys above.
- A scan requires the 0.5.0 JSON contract, including a boolean approval requirement;
  missing/invalid metadata is a failed check, never implicit permission. Known
  mandatory acknowledgement remains required even when its JSON is damaged.
- Warnings run by default and reputation-dependent cases need threat data.
  Corpus coverage is not a "zero attacks execute" guarantee.

## Disclosure

**What this plugin does on your machine.** Before every `terminal` command, and every line the agent
finishes in a background terminal, the plugin runs the `tirith` program you installed
(`tirith check`), in the command's working directory, with the command on standard input.
Each check adds subprocess/scanner latency; there is no universal latency guarantee.
The plugin reads its settings, stores tracking only in memory, makes no network
requests itself, sends no telemetry, and never installs or updates tirith or anything else.

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
