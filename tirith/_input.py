"""What the agent has typed into each background terminal, so a line is checked when it can run.

Hermes's ``process_manage`` tool sends keystrokes to a background process: ``write`` sends
``data`` as it is and ``submit`` sends ``data`` plus Enter. A line can therefore be typed in one
call and run by a later one (``write`` the command, then ``submit("")``), and a shell command can
go on over several lines (a trailing ``\\`` or ``|``, an open quote, a heredoc). ``close`` sends
end of input (Ctrl-D on a PTY, a closed pipe otherwise), and a shell runs a line it holds at end of
input even without Enter (any shell on a pipe; dash on a PTY after a second Ctrl-D), so ``close``
completes whatever was typed. This module keeps the unfinished input of every process and hands the
plugin the whole text that a call completes.

Input is committed only once Hermes confirms that the call ran (``post_tool_call``): a refused
call never reaches the process. An unconfirmed call prevents later input from assuming an order.
Neither callback order nor elapsed time proves the order or delivery of physical PTY/pipe writes.

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
INFLIGHT_TTL = 300.0  # diagnostic age only: never a delivery confirmation
MAX_CALLS = 4096  # outstanding calls and recent/unmatched completion ids
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


def was_written(result: Any, status: Any = None) -> bool | None:
    """True for confirmed delivery, False for definite refusal, None for unknown delivery."""
    if status == "blocked":
        return False
    if status in ("timeout", "cancelled"):
        return None  # Hermes may abandon a worker without knowing whether its physical write happened
    try:
        parsed = json.loads(result) if isinstance(result, str) else result
    except ValueError:
        return None
    if isinstance(parsed, dict):
        if parsed.get("status") == "ok":
            return True
        if parsed.get("status") in ("not_found", "already_exited"):
            return False
        # Hermes wraps PTY/pipe write AND flush exceptions as generic errors.
        # Some bytes may already have reached the process when a flush fails.
    return None


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


@dataclass
class _Call:
    process: str
    keys: str
    started: float
    group: object
    preparing: bool = False  # the pre hook can still return after a synthesized post
    complete: bool = False
    written: bool | None = None
    oversized: bool = False


class ProcessInput:
    """Confirmed unfinished input and unresolved calls, guarded by one worker-thread lock.

    Calls are reserved before scanning. Overlapping calls settle together: only a single confirmed
    delivery has a known order. Multiple deliveries, unknown results, or lost tracking capacity
    leave an explicit fail-closed state, not an invented command. Unconfirmed calls never expire.
    """

    def __init__(
        self,
        max_processes: int = MAX_PROCESSES,
        max_bytes: int = MAX_INPUT_BYTES,
        inflight_ttl: float = INFLIGHT_TTL,
        clock: Callable[[], float] = time.monotonic,
        max_calls: int = MAX_CALLS,
    ):
        self._max_processes = max_processes
        self._max_bytes = max_bytes
        self._inflight_ttl = inflight_ttl
        self._clock = clock
        self._max_calls = max_calls
        self._pending: OrderedDict[str, str] = OrderedDict()
        self._inflight: OrderedDict[object, _Call] = OrderedDict()
        self._unknown: dict[str, tuple[str, str]] = {}
        # True means a post arrived before its pre finished (or before it even registered).
        # These tombstones cannot be evicted into an allow. Ordinary completed pres can.
        self._finished: OrderedDict[object, bool] = OrderedDict()
        self._overflow = False
        self._lock = threading.Lock()

    # -- internals (lock held) --

    @staticmethod
    def _matches(a: str, b: str) -> bool:
        return a == b or _related(a, b)

    def _remember_finished(self, call_id: object, awaiting_pre: bool) -> None:
        previous = self._finished.pop(call_id, False)
        self._finished[call_id] = previous or awaiting_pre
        while len(self._finished) > self._max_calls:
            _old_id, unresolved = self._finished.popitem(last=False)
            if unresolved:
                self._overflow = True

    def _mark_unknown(self, process: str, error: tuple[str, str]) -> None:
        names = self._pending.keys() | self._unknown.keys()
        if process not in names and len(names) >= self._max_processes:
            self._overflow = True
            return
        self._unknown.setdefault(process, error)

    def _reserve(self, call_id: object, process: str, keys: str, *, preparing: bool) -> None:
        if self._overflow or call_id in self._finished or call_id in self._inflight:
            return
        if len(self._inflight) >= self._max_calls:
            self._overflow = True
            return
        overlapping = [entry for entry in self._inflight.values() if self._matches(entry.process, process)]
        group = overlapping[0].group if overlapping else object()
        groups = {entry.group for entry in overlapping}
        for entry in self._inflight.values():
            if entry.group in groups:
                entry.group = group
        oversized = len(keys.encode("utf-8", "surrogatepass")) > self._max_bytes
        self._inflight[call_id] = _Call(
            process, "" if oversized else keys, self._clock(), group, preparing=preparing, oversized=oversized
        )

    def _apply(self, process: str, keys: str) -> None:
        if process in self._unknown:
            return
        if any(_related(name, process) for name in self._pending.keys() | self._unknown.keys()):
            self._mark_unknown(
                process,
                ("ambiguous", "input under different process ids cannot be put in a confirmed physical order"),
            )
            return
        prior = self._pending.get(process, "")
        text = prior + keys
        if len(text.encode("utf-8", "surrogatepass")) > self._max_bytes:
            self._mark_unknown(process, ("too_large", "the input for this background process is too large to check"))
            return
        after = advance(prior, keys)
        if after:
            names = self._pending.keys() | self._unknown.keys()
            if process not in names and len(names) >= self._max_processes:
                self._overflow = True
                return
            self._pending[process] = after
        else:
            self._pending.pop(process, None)

    def _settle(self, group: object) -> None:
        calls = [(call_id, entry) for call_id, entry in self._inflight.items() if entry.group is group]
        if not calls or any(entry.preparing or not entry.complete for _call_id, entry in calls):
            return
        for call_id, _entry in calls:
            del self._inflight[call_id]
        delivered = [entry for _call_id, entry in calls if entry.written is True]
        unknown = [entry for _call_id, entry in calls if entry.written is None]
        if unknown or len(delivered) > 1:
            reason = (
                ("unconfirmed", "Hermes has not confirmed what input reached this background process")
                if unknown
                else (
                    "ambiguous",
                    "overlapping input calls reached this background process; callback order does not prove "
                    "the physical write order, so tirith cannot tell what it would run",
                )
            )
            for entry in delivered + unknown:
                self._mark_unknown(entry.process, reason)
        elif delivered:
            entry = delivered[0]
            if entry.oversized:
                self._mark_unknown(entry.process, ("too_large", "the input for this background process is too large"))
            else:
                self._apply(entry.process, entry.keys)

    # -- API --

    def plan(self, process: str, keys: str, eof: bool = False, *, call_id: object | None = None) -> Plan | None:
        """Check an input call, reserving its id before any slow scanner or approval work.

        ``eof`` checks all typed text. Calls without a host id use a private reservation which
        cannot be confirmed by a post; they remain unconfirmed rather than being assumed written.
        Direct callers can omit ``call_id`` to inspect a plan without reserving it.
        """
        if not process:
            return None
        with self._lock:
            prior = self._pending.get(process, "")
            text = prior + keys
            error = None
            outstanding = [entry for entry in self._inflight.values() if self._matches(entry.process, process)]
            names = self._pending.keys() | self._unknown.keys()
            if self._overflow:
                error = ("too_many", "background input tracking capacity was exhausted; delivery is unknown")
            elif call_id is not None and call_id in self._finished:
                error = (
                    "finished",
                    "Hermes already finished this input call; a late pre hook cannot register it again",
                )
            elif any(_related(name, process) for name in names):
                error = (
                    "ambiguous",
                    "input for this background process was sent under different ids, so tirith cannot tell "
                    "what it would run",
                )
            elif process in self._unknown:
                error = self._unknown[process]
            elif outstanding:
                stale = any(self._clock() - entry.started > self._inflight_ttl for entry in outstanding)
                error = (
                    ("unconfirmed", "an earlier input call is still unconfirmed; elapsed time does not prove delivery")
                    if stale
                    else (
                        "ambiguous",
                        "another input call for this background process has not finished; tirith cannot prove "
                        "the physical write order",
                    )
                )
            elif not prior and interrupt_only(keys):
                pass
            elif control_keys(text):
                error = (
                    "control_keys",
                    "the input has control keys (such as Tab, Esc, Ctrl or NUL) that a terminal can treat as "
                    "editing keys, so tirith cannot tell what would run",
                )
            elif len(text.encode("utf-8", "surrogatepass")) > self._max_bytes:
                error = ("too_large", "the input for this background process is too large to check (over 1 MiB)")
            elif process not in names and len(names) >= self._max_processes and advance(prior, keys):
                error = ("too_many", "too many background processes have unfinished input")
            if call_id is not None:
                self._reserve(call_id, process, keys, preparing=True)
                if self._overflow:
                    error = ("too_many", "background input tracking capacity was exhausted; delivery is unknown")
            if error:
                return Plan(process, keys, text, error=error)
            if not prior and interrupt_only(keys):
                return Plan(process, keys, text)
            normalised = text.replace("\r\n", "\n")
            if eof:
                return Plan(process, keys, text, scan=normalised if has_text(normalised) else None)
            end = normalised.rfind("\n")
            complete = normalised[:end] if end >= 0 else ""
            return Plan(process, keys, text, scan=complete if has_text(complete) else None)

    def started(self, call_id: object, process: str, keys: str, *, permitted: bool = True) -> None:
        """The pre hook returned. An earlier terminal post wins over this late registration."""
        with self._lock:
            if call_id in self._finished:
                self._finished[call_id] = False  # the late pre has now returned; safe to retire this tombstone
            else:
                self._reserve(call_id, process, keys, preparing=False)
            entry = self._inflight.get(call_id)
            if entry is None:
                return
            entry.preparing = False
            if not permitted and not entry.complete:
                entry.complete, entry.written = True, False
                self._remember_finished(call_id, False)
            self._settle(entry.group)

    def finished(self, call_id: object, written: bool | None, process: str = "", keys: str | None = None) -> None:
        """A terminal post: only a confirmed, uniquely ordered delivery advances a line."""
        with self._lock:
            if call_id in self._finished:
                return  # duplicate posts must not change a blocked/finished call into a delivery
            entry = self._inflight.get(call_id)
            self._remember_finished(call_id, entry is None or entry.preparing)
            if entry is None:
                if written is not False and process:
                    self._mark_unknown(process, ("unconfirmed", "input was reported without a matching pre hook"))
                return
            if process and process != entry.process:
                if written is not False:
                    error = ("ambiguous", "the process id changed after this input was checked")
                    self._mark_unknown(entry.process, error)
                    self._mark_unknown(process, error)
            elif keys is not None and keys != entry.keys and not entry.oversized:
                entry.oversized = len(keys.encode("utf-8", "surrogatepass")) > self._max_bytes
                entry.keys = "" if entry.oversized else keys
            entry.complete, entry.written = True, written
            self._settle(entry.group)

    def record(self, process: str, keys: str, confirmed: bool = True) -> None:
        """Record a known serial delivery, or preserve an explicit unknown input state."""
        with self._lock:
            if confirmed and not any(self._matches(entry.process, process) for entry in self._inflight.values()):
                self._apply(process, keys)
            else:
                text = self._pending.get(process, "") + keys
                self._mark_unknown(process, ("unconfirmed", "input delivery or its physical order was not confirmed"))
                if not self._overflow and len(text.encode("utf-8", "surrogatepass")) <= self._max_bytes:
                    self._pending[process] = text

    def forget(self, process: str) -> None:
        """A confirmed process exit retires its input, including outstanding pre hooks."""
        with self._lock:
            self._pending.pop(process, None)
            self._unknown.pop(process, None)
            groups = set()
            for call_id, entry in list(self._inflight.items()):
                if entry.process == process:
                    groups.add(entry.group)
                    del self._inflight[call_id]
                    self._remember_finished(call_id, entry.preparing)
            for group in groups:
                self._settle(group)

    def pending(self, process: str) -> str:
        """Confirmed unfinished text; unresolved delivery is represented by ``plan().error``."""
        with self._lock:
            return self._pending.get(process, "")

    def clear(self) -> None:
        with self._lock:
            self._pending.clear()
            self._inflight.clear()
            self._unknown.clear()
            self._finished.clear()
            self._overflow = False
