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
While delivery or order is unknown, the plugin fails closed but still shows and checks its best
guess of the typed text (the calls in the order they were checked), which can only add findings.

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
MAX_PROCESSES = 1024  # processes with unfinished input; input for one more fails closed
INFLIGHT_TTL = 300.0  # diagnostic age only: never a delivery confirmation
MAX_CALLS = 4096  # outstanding calls, and recent/unmatched completion ids; one more call fails closed
_GONE = frozenset({"exited", "killed", "already_exited"})
# Failed checks where the text is known but not whether (or in what order) it reaches the process:
# the best-known text is still checked. Control keys mean the text is not what runs, so it is not.
_GUESSED = frozenset({"unconfirmed", "ambiguous", "too_many"})
_WORD_BREAKS = " \t\n;&|()<>"
# Reserved words that open a compound command, and the word that closes it.
_OPENERS = {"if": "fi", "case": "esac", "for": "done", "select": "done", "while": "done", "until": "done"}
# Reserved words after which the next word starts a command again (where reserved words count).
_LEAD_INS = frozenset({"if", "then", "else", "elif", "while", "until", "do", "!", "time", "{"})


@dataclass(frozen=True)
class Plan:
    """What one ``write`` / ``submit`` / ``close`` means for the process it goes to."""

    process: str  # canonical process id
    keys: str  # what Hermes writes for this call ("" for ``close``)
    text: str  # best-known unfinished input plus ``keys``: shown and keyed when the input cannot be checked
    scan: str | None = None  # complete lines to check now, or None when nothing can run yet
    error: tuple[str, str] | None = None  # (reason class, reason): fail closed; ``scan`` only adds findings


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


class _Continuation:
    """One pass over complete lines of shell input: does the shell still wait for more of the command?

    Tracks quotes, escaped newlines, heredocs, a trailing ``|``, ``&&`` or ``||``, and the constructs
    a shell keeps reading until they close: ``(`` (a subshell, ``$(``, ``<(``, ``>(``, an array,
    ``((``), ``${``, a ``{ ... }`` group, and ``if``, ``case``, ``for``, ``select``, ``while`` and
    ``until``. Reserved words count only where a command starts, as in the shell. This keeps input
    together; it is not a parser. A construct it wrongly takes for open only means that later lines
    are checked together with the earlier ones.
    """

    def __init__(self, text: str):
        self.text = text
        self.quote = ""
        self.prev = "\n"
        self.line: list[str] = []
        self.last_line = ""
        self.heredocs: list[tuple[str, bool]] = []
        self.stack: list[str] = []  # what closes each open construct: ")", "))", "${", "}", "fi", "esac", "done"
        self.command = True  # the next word starts a command, so reserved words count
        self.word: list[str] = []
        self.word_command = False  # the current word started where a command starts
        self.word_plain = True  # no quotes, escapes or expansions: it can be a reserved word
        self.function_name = False  # after ``function``: its name comes next, then the body
        self.case_words = 0  # after ``case``: 2 = its word comes next, 1 = ``in`` comes next
        self.pattern = False  # in a ``case`` pattern (before its ``)``), where only ``esac`` counts

    def _start_word(self) -> None:
        if not self.word:
            self.word_command = self.command
            self.word_plain = True
            self.command = False

    def _end_word(self) -> None:
        if not self.word:
            return
        token = "".join(self.word) if self.word_plain else ""
        at_command = self.word_command
        self.word = []
        stack = self.stack
        if self.case_words == 2:
            self.case_words = 1
            return
        if self.case_words == 1:
            self.case_words = 0
            if token == "in":
                self.pattern = True
                return
        if self.pattern:
            if token == "esac" and stack and stack[-1] == "esac":
                stack.pop()
                self.pattern = False
            return
        if self.function_name:
            self.function_name = False
            self.command = True  # ``function name { ...``
            return
        if not at_command:
            return
        if token in _OPENERS:
            stack.append(_OPENERS[token])
            self.case_words = 2 if token == "case" else 0
        elif token in ("fi", "esac", "done", "}"):
            if stack and stack[-1] == token:
                stack.pop()
        elif token == "{":
            stack.append("}")
        elif token == "function":
            self.function_name = True
        if token in _LEAD_INS:
            self.command = True

    def _heredoc_bodies(self, index: int) -> int | None:
        """Skip the bodies of the heredocs opened on the line that just ended; None if one is unfinished."""
        text, size = self.text, len(self.text)
        for word, strip_tabs in self.heredocs:
            while True:
                if index >= size:
                    return None
                end = text.find("\n", index)
                if end < 0:
                    return None
                body = text[index:end]
                index = end + 1
                if (body.lstrip("\t") if strip_tabs else body) == word:
                    break
        self.heredocs = []
        return index

    def run(self) -> bool:
        text, size, stack = self.text, len(self.text), self.stack
        index = 0
        while index < size:
            char = text[index]
            if self.quote:
                if char == "\\" and self.quote != "'":
                    index += 2
                    continue
                if char == self.quote[-1]:
                    self.quote = ""
                    self.prev = char
                    self.line.append("q")
                index += 1
                continue
            if char == "\\":
                if text.startswith("\n", index + 1):
                    if index + 2 >= size:
                        return True
                    index += 2
                    continue
                self._start_word()
                self.word_plain = False
                self.word.append("x")
                self.line.append("x")
                self.prev = "x"
                index += 2
                continue
            if char in "'\"`":
                self._start_word()
                self.word_plain = False
                self.word.append(char)
                self.quote = "$'" if char == "'" and self.prev == "$" else char
                index += 1
                continue
            if stack and stack[-1] == "${":  # ``${x:- #(<<}``: literal up to the closing ``}``
                index = self._parameter(char, index)
                self.prev = char
                continue
            if char == "#" and self.prev in _WORD_BREAKS:
                while index < size and text[index] != "\n":
                    index += 1
                continue
            if char == "<" and text.startswith("<", index + 1):
                self._end_word()
                if text.startswith("<", index + 2):  # here-string
                    self.line.append("<<<")
                    self.prev = "<"
                    index += 3
                    continue
                # ``$((1<<2))`` and ``((x<<y))`` are shifts, not heredocs
                found = None if stack and stack[-1] == "))" else _heredoc_word(text, index + 2)
                self.line.append("<<")
                if found is None:
                    self.prev = "<"
                    index += 2
                    continue
                self.heredocs.append(found[:2])
                self.prev = "x"
                index = found[2]
                continue
            if char == "\n":
                self._end_word()
                significant = "".join(self.line).strip()
                if significant:
                    self.last_line = significant
                self.line = []
                self.prev = char
                self.command = True
                skipped = self._heredoc_bodies(index + 1)
                if skipped is None:
                    return True
                index = skipped
                continue
            self.line.append(char)
            index = self._unquoted(char, index)
            self.prev = char
        if self.quote or self.heredocs:
            return True
        self._end_word()
        significant = "".join(self.line).strip()
        if significant:
            self.last_line = significant
        return bool(stack) or self.last_line.endswith(("|", "&&", "|&"))

    def _unquoted(self, char: str, index: int) -> int:
        """One unquoted character other than a newline, quote, escape or ``<<``; returns the next index."""
        text, stack = self.text, self.stack
        following = text[index + 1] if index + 1 < len(text) else ""
        if char in " \t":
            self._end_word()
        elif char in ";&|":
            self._end_word()
            if char == ";" and following in ";&":  # ``;;``, ``;&``, ``;;&``: the next case pattern
                self.pattern = bool(stack) and stack[-1] == "esac"
                self.command = not self.pattern
                self.line.append(following)
                return index + 2
            if not self.pattern:  # ``a|b)`` is still the pattern
                self.command = not (char in "&|" and self.prev in "<>")  # ``>&2`` and ``>|`` redirect
        elif char in "<>":
            self._end_word()
        elif char == "(":
            self._end_word()
            if self.pattern:  # ``(a)``: the optional parenthesis before a case pattern
                return index + 1
            if following == "(":  # ``((`` and ``$((``: arithmetic
                stack.append("))")
                self.line.append(following)
                self.command = False
                return index + 2
            stack.append(")")
            self.command = True
        elif char == ")":
            self._end_word()
            if self.pattern:  # the end of a case pattern: a command follows
                self.pattern = False
                self.command = True
            elif stack and stack[-1] == "))":
                if following == ")":
                    stack.pop()
                    self.line.append(following)
                    self.command = False
                    return index + 2
                stack[-1] = ")"  # ``((a); b)`` was two subshells: the inner one ends here
                self.command = False
            elif stack and stack[-1] == ")":
                stack.pop()
                self.command = self.prev == "("  # ``name()``: the function body follows
            else:
                self.command = True
        elif char == "{" and self._expansion_opens():
            self.word_plain = False
            self.word.append(char)
            stack.append("${")
        else:
            self._start_word()
            self.word.append(char)
        return index + 1

    def _expansion_opens(self) -> bool:
        """Whether a ``{`` here opens ``${``: the word ends in an odd run of ``$`` (``$${`` is ``$$`` then ``{``)."""
        count = 0
        for char in reversed(self.word):
            if char != "$":
                break
            count += 1
        return count % 2 == 1

    def _parameter(self, char: str, index: int) -> int:
        """One unquoted character inside ``${...}``: literal, except ``}`` and nested ``$(``, ``$((``, ``${``."""
        stack = self.stack
        self._start_word()
        self.word_plain = False
        if char == "}":
            stack.pop()
        elif char == "(" and self.word[-1:] == ["$"]:
            if self.text.startswith("(", index + 1):
                stack.append("))")
                self.word.append("((")
                return index + 2
            stack.append(")")
            self.word = []  # a command starts inside ``$(``
            self.command = True
            return index + 1
        elif char == "{" and self._expansion_opens():
            stack.append("${")
        self.word.append(char)
        return index + 1


def continues(text: str) -> bool:
    """Whether a POSIX shell that read ``text`` (whole lines) still waits for more of the same command.

    True for an open quote or backtick, an escaped final newline, an unfinished heredoc, a last
    non-blank line ending in ``|``, ``||``, ``&&`` or ``|&``, or an open ``(`` (``$(``, ``<(``, ``>(``,
    a subshell, an array), ``${``, ``{`` group, ``if``, ``case`` or loop. Such a command is kept
    together for the next check, so lines a person approved one at a time (an unfinished
    ``bash -c $(``) are checked again together with the lines that complete them. Every complete
    line is checked either way.
    """
    return _Continuation(text).run()


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


def _ready(text: str, eof: bool) -> str | None:
    """What a shell would run from ``text`` now: complete lines, or everything at end of input."""
    normalised = text.replace("\r\n", "\n")
    if not eof:
        end = normalised.rfind("\n")
        normalised = normalised[:end] if end >= 0 else ""
    return normalised if has_text(normalised) else None


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
    delivery has a known order. Multiple deliveries or unknown results leave an explicit fail-closed
    state for that process, not an invented command. Unconfirmed calls never expire.

    Capacity limits apply to the call or process that would need a new entry: its input fails
    closed, and tracking recovers as calls finish and processes exit. Input that ran anyway (an
    approved failed check, or ``fail_closed: false``) is still recorded, so the limits are soft.
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
        self._guess: dict[str, str] = {}  # unknown process -> best guess of its unfinished text
        # Completed call ids. The value is the process when the post arrived before its pre returned
        # (or before it even registered): that late pre must not register the call again.
        self._finished: OrderedDict[object, str | None] = OrderedDict()
        self._lock = threading.Lock()

    # -- internals (lock held) --

    @staticmethod
    def _matches(a: str, b: str) -> bool:
        return a == b or _related(a, b)

    def _remember_finished(self, call_id: object, awaiting_pre: str | None) -> None:
        """``awaiting_pre``: the process of a call whose post came before its pre returned."""
        previous = self._finished.pop(call_id, None)
        self._finished[call_id] = previous or awaiting_pre
        while len(self._finished) > self._max_calls:
            _old_id, process = self._finished.popitem(last=False)
            if process and process in self._pending:
                # Its late pre could now register the call again, and a stray post could then
                # count it as delivered. Only this process's typed text is at stake.
                self._mark_unknown(process, ("unconfirmed", "tracking for an earlier input call was dropped"))

    def _mark_unknown(self, process: str, error: tuple[str, str], keys: str = "") -> None:
        """Delivery or order is unknown: fail closed, guessing that ``keys`` arrived after the rest."""
        self._unknown.setdefault(process, error)
        guess = self._guess.get(process, self._pending.get(process, ""))
        guess = advance(guess, keys) if keys else guess
        self._guess[process] = guess if len(guess.encode("utf-8", "surrogatepass")) <= self._max_bytes else ""

    def _reserve(self, call_id: object, process: str, keys: str, *, preparing: bool) -> bool:
        """Track a call from its pre hook. False when the call table is full: the call is not tracked."""
        if call_id in self._inflight:
            return True
        if len(self._inflight) >= self._max_calls:
            return False
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
        return True

    def _apply(self, process: str, keys: str) -> None:
        if process in self._unknown:
            self._mark_unknown(process, self._unknown[process], keys)
            return
        if any(_related(name, process) for name in self._pending.keys() | self._unknown.keys()):
            self._mark_unknown(
                process,
                ("ambiguous", "input under different process ids cannot be put in a confirmed physical order"),
                keys,
            )
            return
        prior = self._pending.get(process, "")
        text = prior + keys
        if len(text.encode("utf-8", "surrogatepass")) > self._max_bytes:
            self._mark_unknown(process, ("too_large", "the input for this background process is too large to check"))
            return
        after = advance(prior, keys)
        if after:
            self._pending[process] = after  # plan() refuses a new process when full; this ran anyway
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
            for _call_id, entry in calls:  # the order the calls were checked in
                if entry.written is not False:
                    self._mark_unknown(entry.process, reason, entry.keys)
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
            outstanding = [entry for entry in self._inflight.values() if self._matches(entry.process, process)]
            if process in self._unknown:
                known = self._guess.get(process, prior)
            else:
                known = prior + "".join(entry.keys for entry in outstanding if entry.process == process)
            text = known + keys
            error = None
            names = self._pending.keys() | self._unknown.keys()
            if call_id is not None and call_id in self._finished:
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
            if call_id is not None and call_id not in self._finished:
                if not self._reserve(call_id, process, keys, preparing=True) and error is None:
                    error = ("too_many", "too many background input calls are unfinished; this one cannot be tracked")
            if error:
                scannable = error[0] in _GUESSED and len(text.encode("utf-8", "surrogatepass")) <= self._max_bytes
                return Plan(process, keys, text, scan=_ready(text, eof) if scannable else None, error=error)
            if not prior and interrupt_only(keys):
                return Plan(process, keys, text)
            return Plan(process, keys, text, scan=_ready(text, eof))

    def started(self, call_id: object, process: str, keys: str, *, permitted: bool = True) -> None:
        """The pre hook returned. An earlier terminal post wins over this late registration."""
        with self._lock:
            if call_id in self._finished:
                self._finished[call_id] = None  # the late pre has now returned; safe to retire this tombstone
            else:
                self._reserve(call_id, process, keys, preparing=False)
            entry = self._inflight.get(call_id)
            if entry is None:
                return  # finished already, or not tracked (its post marks the process unknown)
            entry.preparing = False
            if not permitted and not entry.complete:
                entry.complete, entry.written = True, False
                self._remember_finished(call_id, None)
            self._settle(entry.group)

    def finished(self, call_id: object, written: bool | None, process: str = "", keys: str | None = None) -> None:
        """A terminal post: only a confirmed, uniquely ordered delivery advances a line."""
        with self._lock:
            if call_id in self._finished:
                return  # duplicate posts must not change a blocked/finished call into a delivery
            entry = self._inflight.get(call_id)
            awaiting = entry is None or entry.preparing
            self._remember_finished(call_id, (entry.process if entry else process) if awaiting else None)
            if entry is None:
                if written is not False and process:
                    error = ("unconfirmed", "input was reported without a matching pre hook")
                    self._mark_unknown(process, error, keys or "")
                return
            if process and process != entry.process:
                if written is not False:
                    error = ("ambiguous", "the process id changed after this input was checked")
                    self._mark_unknown(entry.process, error)  # settling below adds its keys
                    self._mark_unknown(process, error, keys or "")
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
                error = ("unconfirmed", "input delivery or its physical order was not confirmed")
                self._mark_unknown(process, error, keys)
                if len(text.encode("utf-8", "surrogatepass")) <= self._max_bytes:
                    self._pending[process] = text

    def forget(self, process: str) -> None:
        """A confirmed process exit retires its input, including outstanding pre hooks."""
        with self._lock:
            self._pending.pop(process, None)
            self._unknown.pop(process, None)
            self._guess.pop(process, None)
            groups = set()
            for call_id, entry in list(self._inflight.items()):
                if entry.process == process:
                    groups.add(entry.group)
                    del self._inflight[call_id]
                    self._remember_finished(call_id, entry.process if entry.preparing else None)
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
            self._guess.clear()
            self._finished.clear()
