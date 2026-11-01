# Changelog

## 0.1.1

Released: TODO(owner): the date 0.1.1 is published (after tirith 0.5.0 is published).

Fixes from the review of 0.1.0. Needs tirith 0.5.0 or later and Hermes 0.21.5 or later, like 0.1.0.

- Background terminal input is read the way an interactive bash reads it. A command left open by an
  unclosed `$(`, `<(`, `(`, `{`, `${`, `$[` or `[[`, a quote inside `"$(...)"`, a heredoc with any
  delimiter, or an unfinished `if`, `case`, loop or function definition (also after `time -p` or
  `coproc`) is kept together. After a person approved an opening line such as `bash -c $(` or
  `eval $(time -p case x in x)`, the lines that complete it used to be checked one at a time (each
  harmless on its own) while the shell ran them as one command; each is now checked together with the
  lines before it. This narrows the gap rather than closing it: README Limits lists what remains.
- Input for a program that is not a shell (a Python or Node REPL, `cat > file`) is still checked line
  by line, as in 0.1.0, except that the line after one tirith cannot analyse (a Node template literal
  with `${}`) is checked together with it and so asks too (see below). A line bash rejects as a syntax
  error (`print(x)`, a stray `done`) ends the command, as bash drops it, and a command held open only by
  reserved words (`if x:`) or by a heredoc whose delimiter does not start with a letter (`x << 4`) is
  followed for at most 32 lines (64 KiB). Each new line costs only its own reading, not the whole held
  text again, also in a long heredoc body or a long word of `{` or `[` (a minified JSON line).
- Ctrl-C or Ctrl-D on its own clears what was typed once it runs; it used to stay in the text, so every
  later line failed as input with control keys. It asks where 0.1.0 asked (an open quote, heredoc,
  final `\` or trailing `|`, or text typed on the line) and goes through otherwise.
- When tirith reports `analysis_incomplete` for a background line that runs, the next line is checked
  together with it, in case the shell still reads the two as one command for a reason the plugin misses
  (bash 5.3's `${ command; }`, which README Limits lists). That next line then usually asks as well,
  after any line tirith cannot analyse (`source <(...)`, `eval "$X"`, or a Node template literal
  `` `${a}-${b}` `` typed into a REPL).
- Hermes Desktop batches: the plugin now finds each command's command word the way bash does. An
  earlier, not yet run command spelled `\cd`, `'cd'`, `"cd"`, `c\d`, `$'cd'` or `$'\x63d'`, run through
  `eval`, `command [-p]`, `builtin` or `time -p`, or written after `NAME=value` assignments or
  redirections (`>/dev/null cd`, `cd>/dev/null`), now counts as a possible directory change, like `cd`
  and `builtin cd` already did, so the later command asks instead of being checked silently under the
  old directory's policy. `echo 'a|cd'`, `echo "; cd x"` and `command -v cd` do not count.
- On Hermes 0.22.3 and later, commands are checked in the session's directory. Since 0.22.3 the
  CLI, TUI and Desktop are clients of Hermes's gateway and plugin hooks run in the gateway process,
  whose own directory is not the session's, and the session's `TERMINAL_CWD` is kept per turn, not in
  the process environment. A command without `workdir` that followed no `cd` was checked in the
  gateway's directory or the gateway's `TERMINAL_CWD`: a project's `.tirith/policy.yaml` (its blocklist
  among others) did not apply, relative paths and the repository root were looked up in the wrong
  tree, the prompt named the wrong directory, and a warning approved "Always" with
  `warn_action: approve` in one project was approved in every other. The plugin now asks Hermes for
  the session's directory (`ctx.session_cwd()`) after the call's `workdir` and the task's last `cd`,
  before `TERMINAL_CWD`; Hermes 0.22.2 and earlier, which have no such call, work as before.
- The directory a task moved to is kept while the task is in use. It was dropped once 512 other tasks
  had reported a directory change, even if the task was still running commands, which were then checked
  in `TERMINAL_CWD` or Hermes's own directory under the wrong repository policy. Each check now counts as
  a use (least recently used goes first) and up to 4096 tasks are remembered.
- The Hermes Desktop batch prompt for a command whose directory is not known yet no longer says "tirith
  could not check this command" (tirith did check it). It says that an earlier command that can change
  directory has not run yet, and shows tirith's verdict in the directory known so far (nothing found, a
  warning, a required policy approval or a finding). A warning stays attached to the result once
  approved. A failed check asks with its own reason, and a refusal still stands.
- Each hook call now finishes inside Hermes's `plugins.hook_callback_timeout` (read from Hermes; 30 s by
  default). A slow or hung binary on the first call (startup check plus check, up to about 27 s at the
  default timeout and 42 s at 25 s) could run past it; Hermes then blocked the call and skipped the
  plugin for 60 s, which blocked every tool. The startup check of every candidate binary and the check
  now share one deadline 5 s before the limit, including the time spent waiting for another call's
  startup check; a check stopped there asks, like any failed check. A failed startup check is kept for
  5 s, so calls queued behind a broken binary get the answer at once; one that only ran out of the hook
  call's time is not kept, and the next call gives the binary its full time again. With
  `plugins.isolation: host` the plugin runs in a separate host process, where Hermes's plugin manager
  is not loaded, while Hermes still enforces the limit on the call; there the plugin reads
  `plugins.hook_callback_timeout` from Hermes's configuration and clamps it as Hermes does (a negative
  or invalid value is 30 s, 0 is no limit, more than 600 s is 600 s) instead of assuming 30 s.
- With `fail_closed: false`, input to a background process whose delivery is not known (overlapping
  calls, a write error) ran when tirith exited with code 3 without a usable verdict, because the failed
  check built for it dropped tirith's approval signal. It now asks, as a terminal command does in that
  case; the prompt says that tirith signalled that the input needs approval.
- The `timeout` setting warns above 12 s (it warned above 25 s), and also when it does not fit the hook
  limit Hermes is configured with.
- tirith 0.5.0 reports `package_lookup_incomplete` (MEDIUM) when its live package lookups (OSV.dev,
  deps.dev, ecosyste.ms, the CISA KEV feed) do not all finish and nothing is cached: online usually
  because tirith's short lookup time budget during a check ran out (500 ms per check, shared by the
  packages in it) or a service returned an error, and always with `offline: true` (the plugin sets
  `TIRITH_OFFLINE=1` only then). That made many a `pip install`, `npm install`, `npx`, `cargo add` or
  `go get` append the same warning to its result. With `warn_action: allow`, the first one in a session
  is now appended with a note on what it means (incomplete verification, not evidence about the
  package, and not a sign that the machine is offline unless the offline setting is on), and later ones
  in that session are left out; every other finding is still appended, and with `warn_action: approve`
  or `block` it still asks or refuses each time.
- README, Limits: commands tirith allows can switch the guard off (uninstall or replace the binary,
  `hermes plugins disable tirith`, `hermes config set ...`); the plugin runs whichever program is at the
  resolved path, and the contract check does not prove it is tirith, so hardened setups should point
  `path` at a binary the agent cannot write. Another plugin's tool-execution middleware can replace a
  command after the check without the plugin noticing.
- README, Disclosure: during a check tirith also downloads CISA's Known Exploited Vulnerabilities feed
  when OSV.dev reports advisories for a package (the whole catalogue, so no package names are sent;
  cached for 24 hours). Package lookups get 500 ms per check, 5 s with a running tirith daemon, which
  matters for the `timeout` setting. On a fresh install the first checks can run before tirith's threat
  database has downloaded. `offline: true` needs a database tirith has already downloaded: without one,
  known-malicious-package and typosquat detection is unavailable, so run `tirith threat-db update` once
  while online (also in the setting's description in `plugin.yaml`).
- Install instructions (README and `plugin.yaml`): Scoop needs tirith's bucket first
  (`scoop bucket add tirith https://github.com/sheeki03/scoop-tirith`), and while Homebrew's main
  repository has not picked up a new tirith release yet, `brew install sheeki03/tap/tirith` installs it
  from the tap tirith's release updates. The "older than 0.5.0" message no longer suggests
  `brew upgrade tirith` to everyone: it says to upgrade with the package manager tirith came from.

## 0.1.0

Released: TODO(owner): the date tirith 0.5.0 is published.

First release. Needs tirith 0.5.0 or later and Hermes 0.21.5 or later; tested with the Hermes releases
0.21.5, 0.21.6, 0.21.7, 0.22.0, 0.22.1 and 0.22.2 (on 0.21.5, turn off Hermes's own built-in tirith
check). The plugin never downloads, installs or updates tirith.

What is checked:

- Runs your installed `tirith check` on every Hermes `terminal` command, and on every line the agent
  finishes in a background terminal (`process_manage` write/submit), before they run. The command goes
  to tirith on standard input, in the command's working directory. A `close` (end of input, which makes
  a shell run a line typed without Enter) checks everything typed so far.
- The working directory reported after a `cd` is kept for the whole session (Hermes reports it only when
  it changes), so later commands are checked in the directory Hermes runs them in.
- Hermes Desktop checks adjacent terminal commands before the earlier ones run. A later command whose
  directory an earlier, not yet run `cd` (or `pushd`, `popd`, `source`, `.`) may change is checked and
  then asks, since its directory, and so its repository policy, is not known yet.
- Background terminal input is checked as the terminal will run it: text typed over several calls, or a
  command continued over several lines, is checked as a whole, and input with control keys (Tab, Esc,
  Ctrl keys, NUL), which a terminal can treat as editing keys, fails closed.
- Typed text counts only once Hermes confirms the call ran, and neither callback order nor elapsed time
  counts as proof of delivery. When it is not known whether, or in what order, input reached a process
  (overlapping calls, a write error, a timeout), every later input to that process asks until Hermes
  reports that the process exited. The prompt shows the plugin's best guess of the typed text (the calls
  in the order they were checked), tirith still checks it (a refusal stands, findings are listed), and
  the approval covers only that process and that text.
- Background input tracking is bounded (1024 processes, 4096 unfinished calls). When it is full, only
  input that would need a new entry fails closed, and tracking recovers as calls finish and processes
  exit.
- Calls are matched across Hermes's hooks by the provider's call id together with the session, task,
  turn and API request ids, so a call id reused in a later response cannot take over an earlier call's
  checked command, warning or typed input.

What happens:

- tirith blocks go to Hermes's approval prompt; CRITICAL findings are refused; warnings run and are
  appended to the command result. All three are settings.
- When tirith says a command needs approval (`requires_approval: true`, or a warning that must be
  acknowledged, exit code 3), Hermes asks even if `min_severity`, `ignore_rules` or `fail_closed: false`
  would otherwise let it run; `warn_action: block` refuses it instead.
- `ignore_rules` cannot silence obfuscation, hidden-text, unanalysable-input, known-malicious,
  exfiltration or terminal-injection rules, nor any CRITICAL finding.
- A `TIRITH=0` prefix that your tirith policy honours still asks you: a prefix the agent wrote is not
  your consent. tirith 0.5.0 answers it with exit 0 and its normal verdict (`action: allow`,
  `bypass_honored: true`, `requires_approval: false`).
- Fails closed: when tirith is missing, too old, times out, crashes or returns no usable verdict
  (including one that lacks a boolean `requires_approval`; a block stays a block), Hermes asks (refused
  in unattended runs). Exit code 3 without a verdict is shown as a failed check and asks even with
  `fail_closed: false`.
- Before the first check the plugin makes sure the binary speaks the 0.5.0 check contract: tirith must
  reject an unknown option with its usage error (exit code 2, naming the option), and its verdict for a
  harmless command must carry a boolean `requires_approval`. Older releases and pre-release builds
  without that field are refused with "this plugin needs tirith 0.5.0 or newer".

Approvals:

- An approval covers one command, in one directory, with one set of findings. For policy approvals,
  blocks, bypass requests and failed checks, "Session" and "Always" last only until the Hermes session
  ends or Hermes restarts.
- Approval prompts always show the command excerpt and its directory; only long finding lists are
  clipped.
