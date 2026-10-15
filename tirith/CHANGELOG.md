# Changelog

## 0.1.0 (unreleased)

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
