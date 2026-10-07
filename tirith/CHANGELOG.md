# Changelog

## 0.1.0 (unreleased)

First release.

- Runs your installed `tirith check` on every Hermes `terminal` command, and on every line the agent
  finishes in a background terminal (`process_manage` write/submit), before they run. The command goes
  to tirith on standard input, in the command's working directory.
- Background terminal input is checked as the terminal will run it: text typed over several calls, or a
  command continued over several lines, is checked as a whole, and input with control keys (Tab, Esc,
  Ctrl keys, NUL), which a terminal can treat as editing keys, fails closed.
- tirith blocks go to Hermes's approval prompt; CRITICAL findings are refused; warnings run and are
  appended to the command result. All three are settings.
- Fails closed: when tirith is missing, older than 0.5.0, times out or returns no verdict, Hermes asks for
  approval (and blocks in unattended runs).
- Approvals cover one command, in one directory, with one set of findings. For blocks and failed checks,
  "Always" lasts only for the current session.
- Needs tirith 0.5.0 or later and Hermes 0.21.5 or later. Never downloads or updates tirith.
