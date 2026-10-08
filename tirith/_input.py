"""What the agent has typed into each background terminal, so a line is checked when it can run.

Hermes's ``process_manage`` tool sends keystrokes to a background process: ``write`` sends
``data`` as it is and ``submit`` sends ``data`` plus Enter. A line can therefore be typed in one
call and run by a later one (``write`` the command, then ``submit("")``), and a shell command can
go on over several lines (a trailing ``\\`` or ``|``, an open quote, a heredoc). ``close`` sends
end of input (Ctrl-D on a PTY, a closed pipe otherwise), and a shell runs a line it holds at end of
input even without Enter (any shell on a pipe; dash on a PTY after a second Ctrl-D), so ``close``
completes whatever was typed. This module keeps the unfinished input of every process and hands the
plugin the whole text that a call completes.

Input is recorded only once Hermes reports that the call ran (``post_tool_call``): a refused call
never reaches the process, so its text must not replace what the process really holds. Calls that
were let through but have not reported back yet count as typed.

Keys that a terminal treats as editing keys (Tab completion, Ctrl-A, Esc sequences, history recall)
or that a shell drops (NUL) make the line that runs differ from the text, so such input is reported
as uncheckable instead of being analysed as text.
"""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

INPUT_ACTIONS = frozenset({"write", "submit", "close"})
EOF_ACTIONS = frozenset({"close"})  # end of input: the typed text runs as it is
INTERRUPT_KEYS = frozenset("\x03\x04")  # Ctrl-C and Ctrl-D on their own
MAX_INPUT_BYTES = 1024 * 1024  # the most tirith reads; more fails closed
MAX_PROCESSES = 1024  # processes with unfinished input; more fails closed
INFLIGHT_TTL = 300.0  # a call with no result after this long is taken as written
_GONE = frozenset({"exited", "killed", "already_exited"})
_WORD_BREAKS = " \t\n;&|()<>"


@dataclass(frozen=True)
class Plan:
    """What one ``write`` / ``submit`` / ``close`` means for the process it goes to."""

    process: str  # canonical process id
    keys: str  # what Hermes writes for this call ("" for ``close``)
    text: str  # unfinished input plus ``keys``: shown when the input cannot be checked
    scan: str | None = None  # complete lines to check now, or None when nothing can run yet
    error: tuple[str, str] | None = None  # (reason class, reason): fail closed


def canonical_id(raw: Any) -> str:
    """The id Hermes looks a process up by: ``proc_<hex>``, also for a bare hex prefix."""
    text = str(raw).strip() if raw is not None else ""
    if not text:
        return ""
    return text if text.startswith("proc_") else "proc_" + text


def keystrokes(args: Any) -> str | None:
    """What Hermes writes to the process for this call ("" for ``close``), or None for other actions."""
    if not isinstance(args, Mapping):
        return None
    action = args.get("action")
    if not isinstance(action, str) or action not in INPUT_ACTIONS:
        return None
    if action in EOF_ACTIONS:
        return ""  # Hermes sends end of input and ignores ``data``
    data = str(args.get("data", ""))  # Hermes: str(a.get("data", ""))
    return data + "\n" if action == "submit" else data


def ends_input(args: Any) -> bool:
    """Whether the call sends end of input (``close``), which runs whatever is typed."""
    return isinstance(args, Mapping) and args.get("action") in EOF_ACTIONS


def has_text(value: str) -> bool:
    return any(not (char.isspace() or ord(char) < 32 or ord(char) == 127) for char in value)


def control_keys(text: str) -> bool:
    """C0 controls and DEL, except Enter (LF, or CR right before LF)."""
    for index, char in enumerate(text):
        if char == "\n" or (char == "\r" and text.startswith("\n", index + 1)):
            continue
        code = ord(char)
        if code < 32 or code == 127:
            return True
    return False


def interrupt_only(keys: str) -> bool:
    body = keys[:-1] if keys.endswith("\n") else keys
    return bool(body) and set(body) <= INTERRUPT_KEYS


def _heredoc_word(text: str, index: int) -> tuple[str, bool, int] | None:
    """The delimiter of a heredoc whose ``<<`` ends just before ``index``."""
    strip_tabs = text.startswith("-", index)
    index += 1 if strip_tabs else 0
    while index < len(text) and text[index] in " \t":
        index += 1
    start = index
    while index < len(text) and text[index] not in _WORD_BREAKS:
        index += 1
    word = text[start:index].replace("'", "").replace('"', "").replace("\\", "")
    # ``$((1<<2))`` is a shift, not a heredoc: only take words that start like a name.
    if not word or not (word[0].isalpha() or word[0] == "_"):
        return None
    return word, strip_tabs, index


def continues(text: str) -> bool:
    """Whether a POSIX shell that read ``text`` (whole lines) still waits for more of the same command.

    True for an open quote or backtick, an escaped final newline, an unfinished heredoc, or a last
    non-blank line ending in ``|``, ``||``, ``&&`` or ``|&``. Other open constructs (``$(``, ``{``)
    are reported by tirith itself. Used only to keep such a command together for the next check;
    every complete line is checked either way.
    """
    quote = ""
    prev = "\n"
    line: list[str] = []
    last_line = ""
    heredocs: list[tuple[str, bool]] = []
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if quote:
            if char == "\\" and quote != "'":
                index += 2
                continue
            if char == quote[-1]:
                quote = ""
                prev = char
                line.append("q")
            index += 1
            continue
        if char == "\\":
            if text.startswith("\n", index + 1):
                if index + 2 >= size:
                    return True
                index += 2
                continue
            line.append("x")
            prev = "x"
            index += 2
            continue
        if char in "'\"`":
            quote = "$'" if char == "'" and prev == "$" else char
            index += 1
            continue
        if char == "#" and prev in _WORD_BREAKS:
            while index < size and text[index] != "\n":
                index += 1
            continue
        if char == "<" and text.startswith("<", index + 1):
            if text.startswith("<", index + 2):  # here-string
                line.append("<<<")
                prev = "<"
                index += 3
                continue
            found = _heredoc_word(text, index + 2)
            line.append("<<")
            if found is None:
                prev = "<"
                index += 2
                continue
            heredocs.append(found[:2])
            prev = "x"
            index = found[2]
            continue
        if char == "\n":
            significant = "".join(line).strip()
            if significant:
                last_line = significant
            line = []
            prev = char
            index += 1
            for word, strip_tabs in heredocs:
                while True:
                    if index >= size:
                        return True
                    end = text.find("\n", index)
                    if end < 0:
                        return True
                    body = text[index:end]
                    index = end + 1
                    if (body.lstrip("\t") if strip_tabs else body) == word:
                        break
            heredocs = []
            continue
        line.append(char)
        prev = char
        index += 1
    if quote or heredocs:
        return True
    significant = "".join(line).strip()
    if significant:
        last_line = significant
    return last_line.endswith(("|", "&&", "|&"))


def advance(prior: str, keys: str) -> str:
    """The unfinished input of a process that held ``prior`` once ``keys`` reach it."""
    if not prior and interrupt_only(keys):
        return ""
    text = prior + keys
    end = text.rfind("\n")
    if end < 0:
        return text
    if continues(text[: end + 1].replace("\r\n", "\n")):
        return text
    return text[end + 1 :]


def was_written(result: Any, status: Any = None) -> bool:
    """Whether a finished ``write`` / ``submit`` reached the process (unknown counts as yes)."""
    if status == "blocked":
        return False
    try:
        parsed = json.loads(result) if isinstance(result, str) else result
    except ValueError:
        return True
    if isinstance(parsed, dict):
        if parsed.get("status") == "ok":
            return True
        if "error" in parsed or parsed.get("status") in ("error", "not_found", "already_exited"):
            return False
    return True


def finished_processes(args: Any, result: Any) -> list[str]:
    """Canonical ids of processes a ``process_manage`` result reports as finished."""
    try:
        parsed = json.loads(result) if isinstance(result, str) else result
    except ValueError:
        return []
    if not isinstance(parsed, dict) or parsed.get("status") not in _GONE:
        return []
    ids = []
    if isinstance(parsed.get("session_id"), str):
        ids.append(canonical_id(parsed["session_id"]))
    if isinstance(args, Mapping):
        ids.append(canonical_id(args.get("session_id")))
    return [found for found in ids if found]


def _related(a: str, b: str) -> bool:
    return a != b and (a.startswith(b) or b.startswith(a))


class ProcessInput:
    """Unfinished input per background process, guarded by one lock (hooks run on worker threads)."""

    def __init__(
        self,
        max_processes: int = MAX_PROCESSES,
        max_bytes: int = MAX_INPUT_BYTES,
        inflight_ttl: float = INFLIGHT_TTL,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._max_processes = max_processes
        self._max_bytes = max_bytes
        self._inflight_ttl = inflight_ttl
        self._clock = clock
        self._pending: OrderedDict[str, str] = OrderedDict()
        self._inflight: OrderedDict[str, tuple[str, str, float]] = OrderedDict()
        self._lock = threading.Lock()

    # -- internals (lock held) --

    def _settle_stale(self) -> None:
        now = self._clock()
        for call_id, (process, keys, started) in list(self._inflight.items()):
            if now - started > self._inflight_ttl:
                del self._inflight[call_id]
                self._apply(process, keys)

    def _apply(self, process: str, keys: str) -> None:
        names = [name for name in self._pending if name == process or _related(name, process)]
        prior = "".join(self._pending.pop(name) for name in names)
        after = advance(prior, keys)
        if after:
            self._pending[process] = after

    # -- API --

    def plan(self, process: str, keys: str, eof: bool = False) -> Plan | None:
        """What to check before ``keys`` go to ``process`` (None: Hermes will refuse the call).

        ``eof``: the call ends the input (``close``), so all typed text is checked as it is, finished
        line or not. With nothing typed it goes through.
        """
        if not process:
            return None
        with self._lock:
            self._settle_stale()
            others = [name for name in self._pending if _related(name, process)]
            others += [name for name, _keys, _started in self._inflight.values() if _related(name, process)]
            prior = self._pending.get(process, "") + "".join(
                pending_keys for name, pending_keys, _started in self._inflight.values() if name == process
            )
            new_entry = process not in self._pending and len(self._pending) >= self._max_processes
        text = prior + keys
        if others:
            return Plan(
                process,
                keys,
                text,
                error=(
                    "ambiguous",
                    "input for this background process was sent under different ids, so tirith cannot tell "
                    "what it would run",
                ),
            )
        if not prior and interrupt_only(keys):
            return Plan(process, keys, text)
        if control_keys(text):
            return Plan(
                process,
                keys,
                text,
                error=(
                    "control_keys",
                    "the input has control keys (such as Tab, Esc, Ctrl or NUL) that a terminal can treat as "
                    "editing keys, so tirith cannot tell what would run",
                ),
            )
        if len(text.encode("utf-8", "surrogatepass")) > self._max_bytes:
            return Plan(
                process,
                keys,
                text,
                error=("too_large", "the input for this background process is too large to check (over 1 MiB)"),
            )
        if new_entry and advance(prior, keys):
            return Plan(
                process,
                keys,
                text,
                error=("too_many", "too many background processes have unfinished input"),
            )
        normalised = text.replace("\r\n", "\n")
        if eof:
            return Plan(process, keys, text, scan=normalised if has_text(normalised) else None)
        end = normalised.rfind("\n")
        if end < 0:
            return Plan(process, keys, text)
        complete = normalised[:end]
        return Plan(process, keys, text, scan=complete if has_text(complete) else None)

    def started(self, call_id: str, process: str, keys: str) -> None:
        """A call that may run: its keys count as typed until its result arrives."""
        with self._lock:
            self._inflight.pop(call_id, None)
            self._inflight[call_id] = (process, keys, self._clock())

    def finished(self, call_id: str, written: bool, process: str = "", keys: str | None = None) -> None:
        """The call's result: record its keys if they reached the process."""
        with self._lock:
            entry = self._inflight.pop(call_id, None)
            if entry is None or not written:
                return
            self._apply(process or entry[0], entry[1] if keys is None else keys)

    def record(self, process: str, keys: str, confirmed: bool = True) -> None:
        """For a call with no id to pair its result with. Unconfirmed keys are kept whole."""
        with self._lock:
            if confirmed:
                self._apply(process, keys)
            else:
                self._pending[process] = self._pending.pop(process, "") + keys

    def forget(self, process: str) -> None:
        """The process has finished; its unfinished input can no longer run."""
        with self._lock:
            self._pending.pop(process, None)

    def pending(self, process: str) -> str:
        with self._lock:
            return self._pending.get(process, "")

    def clear(self) -> None:
        with self._lock:
            self._pending.clear()
            self._inflight.clear()
