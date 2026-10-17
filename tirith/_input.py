"""What the agent has typed into each background terminal, so a line is checked when it can run.

Hermes's ``process_manage`` tool sends keystrokes to a background process: ``write`` sends
``data`` as it is and ``submit`` sends ``data`` plus Enter. A line can therefore be typed in one
call and run by a later one (``write`` the command, then ``submit("")``), and a shell command can
go on over several lines (a trailing ``\\`` or ``|``, an open quote, a heredoc). ``close`` sends
end of input (Ctrl-D on a PTY, a closed pipe otherwise), and a shell runs a line it holds at end of
input even without Enter (any shell on a pipe; dash on a PTY after a second Ctrl-D), so ``close``
completes whatever was typed. This module keeps the unfinished input of every process and hands the
plugin the whole text that a call completes.

The input is read as an interactive bash on a terminal reads it: a command stays together while a
quote, ``$(``, heredoc, ``if`` or other construct is open, and a syntax error (``print(x)``, a stray
``done``) drops the command, as bash does. Ctrl-C or Ctrl-D on its own cancels what was typed. The
process may not be a shell at all (a Python or Node REPL, ``cat > file``), so a command held open only
by reserved words, which such input opens easily (``if x:``), is followed for at most
``MAX_HELD_LINES`` lines; after that, lines are checked one at a time again.

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
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
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
_QUOTES = frozenset({'"', "'", "$'", "`"})
_ARITHMETIC = frozenset({"))", "]", "a)"})  # ((, $((, $[ and the parentheses inside them
_CONDITION = frozenset({"]]", "c)"})  # [[ and the parentheses inside it
# Reserved words that open a compound command, and the word that closes it.
_OPENERS = {
    "if": "fi",
    "case": "esac",
    "for": "done",
    "select": "done",
    "while": "done",
    "until": "done",
    "{": "}",
    "[[": "]]",
}
_CLOSERS = frozenset({"fi", "esac", "done", "}"})
_MIDDLES = {"then": "fi", "else": "fi", "elif": "fi", "do": "done"}  # valid only inside their construct
# Reserved words after which the next word starts a command again (where reserved words count).
_LEAD_INS = frozenset({"if", "then", "else", "elif", "while", "until", "do", "!", "time", "{", "coproc"})
_EXTGLOB = frozenset("@!?*+")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Runs of characters that need no handling of their own, consumed at once (speed only).
_RUN = re.compile(r"[^ \t\n;&|<>()'\"`\\#{\[]+")
_SPECIAL = {
    '"': re.compile(r'[\\"`$]'),
    "`": re.compile(r"[\\`]"),
    "$'": re.compile(r"[\\']"),
    "${": re.compile(r"[\\'\"`}$<>]"),
    "arith": re.compile(r"[\\'\"`$()\[\]]"),
    "g)": re.compile(r"[\\'\"`$()]"),
}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[.*\])?\+?=", re.S)
# A command held open only by reserved words (Python's ``if x:`` opens an ``if`` that never closes), or
# by a heredoc whose delimiter does not start like a name (``x << 4`` is a shift in most languages), is
# followed for at most this many lines and bytes; past that, lines are checked one at a time again.
MAX_HELD_LINES = 32
MAX_HELD_BYTES = 64 * 1024
_HELD = frozenset({"fi", "esac", "done", "}", "]]"})  # stack entries that only reserved words hold open


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


_CONTROL = re.compile("[\x00-\x09\x0b-\x1f\x7f]")
_NOT_CONTROL = bytes(code for code in range(256) if code >= 32 and code != 127)


def control_keys(text: str) -> bool:
    """C0 controls and DEL, except Enter (LF, or CR right before LF)."""
    found = text.encode("utf-8", "surrogatepass").translate(None, _NOT_CONTROL)  # fast: only control bytes
    if found.count(b"\n") == len(found):
        return False
    return any(m.group() != "\r" or not text.startswith("\n", m.end()) for m in _CONTROL.finditer(text))


def interrupt_only(keys: str) -> bool:
    body = keys[:-1] if keys.endswith("\n") else keys
    return bool(body) and set(body) <= INTERRUPT_KEYS


def _balanced(text: str, index: int) -> int:
    """The index just after the ``$(...)``, ``${...}``, ``$[...]`` or backtick group starting at ``index``.

    ``len(text) + 1`` when it does not close: bash then keeps reading the word on the next lines.
    """
    if text[index] == "`":
        close = text.find("`", index + 1)
        return close + 1 if close >= 0 else len(text) + 1
    opener = text[index + 1]
    closer = {"(": ")", "{": "}", "[": "]"}[opener]
    depth, index = 0, index + 1
    while index < len(text):
        char = text[index]
        if char in "'\"":
            close = text.find(char, index + 1)
            if close < 0:
                return len(text) + 1
            index = close
        elif char == "\\":
            index += 1
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text) + 1


def _heredoc_word(text: str, index: int) -> tuple[str, bool, bool, int] | None:
    """The delimiter of a heredoc whose ``<<`` ends just before ``index``: (word, strip tabs, named, end).

    Any word is a delimiter (``<<1``, ``<<.``, ``<<'!'``, ``<<$x``); ``named`` says it starts like a
    name, which is what 0.1.0 recognised. A ``$(...)`` or backtick in it is part of the word, even over
    several lines; ``end`` is past the text when it does not close yet. None when no word follows (a
    syntax error).
    """
    strip_tabs = text.startswith("-", index)
    index += 1 if strip_tabs else 0
    while index < len(text) and text[index] in " \t":
        index += 1
    start = index
    parts: list[str] = []
    quoted = False
    while index < len(text) and text[index] not in _WORD_BREAKS:
        char = text[index]
        if char in "'\"":
            close = text.find(char, index + 1)
            if close < 0 or "\n" in text[index:close]:  # the quoted word goes on over lines: bash reads on
                return text[start:], strip_tabs, False, len(text) + 1
            parts.append(text[index + 1 : close])
            quoted = True
            index = close + 1
        elif char == "\\":
            if text.startswith("\n", index + 1):  # a line continuation: the word goes on
                if index + 2 >= len(text):
                    return text[start:], strip_tabs, False, len(text) + 1
            else:
                parts.append(text[index + 1 : index + 2])
                quoted = True
            index += 2
        elif char == "`" or (char == "$" and text[index + 1 : index + 2] in ("(", "{", "[")):
            close = _balanced(text, index)
            parts.append(text[index:close])
            index = close
        else:
            parts.append(char)
            index += 1
    word = "".join(parts)
    if not word and not quoted:
        return None
    return word, strip_tabs, bool(word) and (word[0].isalpha() or word[0] == "_"), index


def _next_char(text: str, index: int) -> str:
    """The first character at or after ``index`` that is not a space or tab."""
    while index < len(text) and text[index] in " \t":
        index += 1
    return text[index] if index < len(text) else ""


@dataclass
class _Grammar:
    """Where one command (the whole input, or the inside of a ``$(...)`` or subshell) is."""

    command: bool = True  # the next word starts a command, so reserved words count
    word: list[str] = field(default_factory=list)
    word_command: bool = False  # the current word started where a command starts
    word_plain: bool = True  # no quotes, escapes or expansions: it can be a reserved word
    word_assign: bool = False  # the current word is where an assignment can be (``a[`` opens a subscript)
    not_name: bool = False  # the current word is known not to be a plain name (see ``_word_is_name``)
    assigning: bool = False  # only assignments so far in this command
    name: bool = False  # the last word was a plain word where a command starts: ``name ()`` defines a function
    case_words: int = 0  # after ``case``: 2 = its word comes next, 1 = ``in`` comes next
    pattern: bool = False  # in a ``case`` pattern (before its ``)``), where only ``esac`` counts
    loop: int = 0  # ``for``/``select`` header: 1 its name, 2 after the name, 3 its word list, 4 ``do`` next
    function_name: bool = False  # after ``function``: its name comes next
    function_body: bool = False  # after ``name()`` or ``function name``: a compound command must follow
    after_time: int = 0  # after ``time`` (1), ``time -p`` (2): ``-p`` (once) and ``--`` keep the command position
    coproc: int = 0  # 1: after ``coproc``; 2: after ``coproc NAME``, where only an opening reserved word counts
    after_compound: bool = False  # a subshell or compound command just ended: a closing reserved word counts


@dataclass(frozen=True)
class _Analysis:
    open: bool  # the shell still reads the command that starts at ``start``
    start: int  # where that command starts (after the last command that ended or was dropped)
    lexical: bool  # held by a quote, a named heredoc, a final ``\`` or a trailing ``|``/``&&``/``||``
    bounded: bool  # held only by reserved words or an unnamed heredoc (see MAX_HELD_LINES)
    done: tuple[int, int] | None  # the last command that ended without a syntax error


class _Continuation:
    """One pass over complete lines of shell input, as an interactive bash reads them.

    Tracks quotes (also nested: ``"$(echo "``), escaped newlines, heredocs (any delimiter), a trailing
    ``|``, ``&&`` or ``||``, the constructs a shell keeps reading until they close (``(``, ``$(``, ``<(``,
    ``>(``, ``((``, ``$((``, ``$[``, ``${``, arrays, ``{ }``, ``[[ ]]``, ``if``, ``case``, ``for``,
    ``select``, ``while``, ``until``, a function waiting for its body) and the syntax errors that make
    an interactive bash drop the whole command (``foo(``, a stray ``fi`` or ``)``, a ``for`` header not
    followed by ``do``, a function body that is not a compound command). Reserved words count only where
    a command starts. It is not a parser: a construct it wrongly keeps open only means later lines are
    checked together with earlier ones.
    """

    def __init__(self, text: str):
        self.text = text
        self.stack: list[str] = []  # what closes each open construct, innermost last
        self.saved: list[_Grammar] = []  # the grammar around each open ``)``, restored when it closes
        self.g = _Grammar()
        self.heredocs: list[tuple[str, bool, bool]] = []  # (delimiter, strip tabs, named) on this line
        self.prev = "\n"
        self.line: list[str] = []
        self.last_line = ""
        self.error = False  # a syntax error on this line: bash drops the command
        self.escaped_end = False
        self.open_word = False  # a heredoc delimiter that is still being read
        self.bodies_at: int | None = None  # the first line of an unfinished heredoc body not read yet
        self.end = 0  # how far the text has been read (see ``resume``)
        self.start = 0
        self.done: tuple[int, int] | None = None

    # -- words and reserved words --

    def _start_word(self) -> None:
        g = self.g
        if not g.word:
            g.word_command = g.command
            g.word_assign = g.command or g.assigning
            g.word_plain = True
            g.not_name = False
            g.command = False
            g.name = False

    def _syntax_error(self) -> None:
        self.error = True

    def _end_word(self) -> None:
        g, stack = self.g, self.stack
        if not g.word:
            return
        token = "".join(g.word) if g.word_plain else ""
        at_command = g.word_command
        g.assigning = g.word_assign and bool(_ASSIGNMENT.match("".join(g.word)))
        g.word = []
        g.name = False
        top = stack[-1] if stack else ""
        if top in _CONDITION:  # operands, until the ``]]``
            if token == "]]" and top == "]]":
                stack.pop()
            return
        if g.case_words == 2:
            g.case_words = 1
            return
        if g.case_words == 1:
            g.case_words = 0
            if token == "in":
                g.pattern = True
            else:
                self._syntax_error()
            return
        if g.pattern:
            if token == "esac" and top == "esac":
                stack.pop()
                g.pattern = False
            return
        if g.loop:
            self._loop_word(token)
            return
        if g.function_name:
            g.function_name = False
            g.function_body = True
            g.command = True
            return
        if g.function_body:
            g.function_body = False
            if not (at_command and token in _OPENERS):
                self._syntax_error()
                return
        if g.coproc == 1:  # ``coproc`` then a compound command, a name, or a simple command
            g.coproc = 0
            if not (at_command and token in _OPENERS):
                g.coproc = 2
                g.command = True
                return
        elif g.coproc == 2:  # ``coproc NAME`` then a compound command, or more of a simple command
            g.coproc = 0
            if not (at_command and token in _OPENERS):
                return
        if g.after_compound:  # ``{ (a) }``, ``then (a) fi``: only a closing reserved word counts here
            g.after_compound = False
            if token in _CLOSERS or token in _MIDDLES:
                self._reserved(token, top)
            return
        if not at_command:
            return
        if g.after_time:
            if (token == "-p" and g.after_time == 1) or token == "--":
                g.after_time = 2 if token == "-p" else 0
                g.command = True
                return
            g.after_time = 0
        self._reserved(token, top)

    def _loop_word(self, token: str) -> None:
        g = self.g
        if g.loop == 1:  # the loop's name
            g.loop = 2
        elif g.loop == 2:
            if token == "in":
                g.loop = 3
            elif token == "do":  # ``for x do``
                g.loop = 0
                g.command = True
            else:
                self._syntax_error()
        elif g.loop == 4:
            g.loop = 0
            if token == "do":
                g.command = True
            elif token == "{" and self.stack and self.stack[-1] == "done":  # ``for x in a; { ...; }``
                self.stack[-1] = "}"
                g.command = True
            else:
                self._syntax_error()

    def _reserved(self, token: str, top: str) -> None:
        """A plain word where a command starts."""
        g, stack = self.g, self.stack
        if token in _OPENERS:
            stack.append(_OPENERS[token])
            if token == "case":
                g.case_words = 2
            elif token in ("for", "select"):
                g.loop = 1
        elif token in _CLOSERS:
            if top != token:
                self._syntax_error()
                return
            stack.pop()
            g.after_compound = True
        elif token in _MIDDLES:
            if top != _MIDDLES[token]:
                self._syntax_error()
                return
        elif token in ("in", "]]"):
            self._syntax_error()
            return
        elif token == "function":
            g.function_name = True
        elif token == "coproc":
            g.coproc = 1
        else:
            g.name = bool(token)
        if token in _LEAD_INS:
            g.command = True
        if token == "time":
            g.after_time = 1

    # -- nested contexts --

    def _enter_command(self, closer: str = ")") -> None:
        """``$(``, ``<(`` or ``>(`` (``)``), or a subshell (``s)``): a new command until the matching ``)``."""
        self.stack.append(closer)
        self.saved.append(self.g)
        self.g = _Grammar()

    def _dollar(self, index: int) -> int:
        """A ``$`` inside double quotes, ``${...}``, arithmetic or an array: what it opens, if anything."""
        text = self.text
        following = text[index + 1] if index + 1 < len(text) else ""
        if following == "(":
            if text.startswith("((", index + 1):
                self.stack.append("))")
                return index + 3
            self._enter_command()
            return index + 2
        if following == "{":
            self.stack.append("${")
            return index + 2
        if following == "[":
            self.stack.append("]")
            return index + 2
        return index + 1

    def _quoted(self, top: str, char: str, index: int) -> int:
        if top == "'":
            close = self.text.find("'", index)
            if close < 0:
                return len(self.text)
            self.stack.pop()
            self.prev = "'"
            return close + 1
        found = _SPECIAL[top].search(self.text, index)
        if found is None:
            return len(self.text)
        index, char = found.start(), found.group()
        if char == "\\":  # escapes the next character, a newline too
            return index + 2
        if char == top[-1]:
            self.stack.pop()
            self.prev = char
            self.line.append("q")
            return index + 1
        if top == '"':
            if char == "`":
                self.stack.append("`")
                return index + 1
            if char == "$":
                return self._dollar(index)
        return index + 1

    def _open_quote(self, char: str) -> None:
        self.stack.append("$'" if char == "'" and self.prev == "$" else char)

    def _parameter(self, char: str, index: int) -> int:
        """Inside ``${...}``: literal up to the closing ``}``, except quotes and nested expansions."""
        found = _SPECIAL["${"].search(self.text, index)
        if found is None:
            return len(self.text)
        if found.start() > index:
            self.prev = self.text[found.start() - 1]
        index, char = found.start(), found.group()
        if char in "'\"`":
            self._open_quote(char)
        elif char == "\\":
            return index + 2
        elif char == "}":
            self.stack.pop()
        elif char == "$":
            self.prev = char
            return self._dollar(index)
        elif char in "<>" and self.text.startswith("(", index + 1):  # ``${x:-<(cmd)}``
            self._enter_command()
            self.prev = "("
            return index + 2
        self.prev = char
        return index + 1

    def _arithmetic(self, top: str, char: str, index: int) -> int:
        """Inside ``((``, ``$((`` or ``$[``: no commands, heredocs or comments; brackets nest."""
        text, stack = self.text, self.stack
        found = _SPECIAL["arith"].search(text, index)
        if found is None:
            return len(text)
        index, char = found.start(), found.group()
        self.prev = char
        if char in "'\"`":
            self._open_quote(char)
        elif char == "\\":
            return index + 2
        elif char == "$":
            return self._dollar(index)
        elif char == "(":
            stack.append("a)")
        elif char == "[":
            stack.append("]")
        elif char == "]" and top == "]":
            stack.pop()
        elif char == ")" and top == "a)":
            stack.pop()
        elif char == ")" and top == "))":
            if text.startswith(")", index + 1):
                stack.pop()
                return index + 2
            stack[-1] = "a)"  # ``((a); b)``: bash reads on until the parentheses balance
        return index + 1

    def _glob(self, char: str, index: int) -> int:
        """Inside an extglob group or an array: words only; parentheses nest."""
        found = _SPECIAL["g)"].search(self.text, index)
        if found is None:
            return len(self.text)
        index, char = found.start(), found.group()
        if char in "'\"`":
            self._open_quote(char)
        elif char == "\\":
            return index + 2
        elif char == "$":
            self.prev = char
            return self._dollar(index)
        elif char == "(":
            self.stack.append("g)")
        elif char == ")":
            self.stack.pop()
        self.prev = char
        return index + 1

    # -- the shell grammar --

    def _shell(self, top: str, char: str, index: int) -> int:
        text, g = self.text, self.g
        if char not in " \t(":
            g.name = False
        if char in " \t":
            end = index + 1
            while end < len(text) and text[end] in " \t":
                end += 1
            self._end_word()
            self.line.append(" ")
            self.prev = " "
            return end
        run = _RUN.match(text, index)
        if run is not None:  # ordinary word characters
            self._start_word()
            g.word.append(run.group())
            self.line.append(run.group())
            self.prev = text[run.end() - 1]
            return run.end()
        if char == "\\":
            if text.startswith("\n", index + 1):
                if index + 2 >= len(text):
                    self.escaped_end = True
                return index + 2
            self._start_word()
            g.word_plain = False
            g.word.append("x")
            self.line.append("x")
            self.prev = "x"
            return index + 2
        if char in "'\"`":
            self._start_word()
            g.word_plain = False
            self._open_quote(char)
            g.word.append(char)
            return index + 1
        if char == "#" and self.prev in _WORD_BREAKS and not g.word:  # a comment, up to the newline
            end = text.find("\n", index)
            return end if end >= 0 else len(text)
        if char == "<" and text.startswith("<", index + 1):
            return self._redirect_heredoc(top, index)
        if char == "\n":
            return self._newline(top, index)
        self.line.append(char)
        index = self._unquoted(top, char, index)
        self.prev = char
        return index

    def _redirect_heredoc(self, top: str, index: int) -> int:
        text, g = self.text, self.g
        self._end_word()
        if self.error:
            return index + 2
        g.command = False
        if text.startswith("<", index + 2):  # here-string
            self.line.append("<<<")
            self.prev = "<"
            return index + 3
        self.line.append("<<")
        if top in _CONDITION:  # a syntax error in ``[[ ]]``: not a heredoc either way
            self.prev = "<"
            return index + 2
        found = _heredoc_word(text, index + 2)
        if found is None:
            self._syntax_error()
            return index + 2
        word, strip_tabs, named, end = found
        if end > len(text):  # the delimiter word goes on: bash keeps reading it
            self.open_word = True
            return len(text)
        self.heredocs.append((word, strip_tabs, named))
        self.prev = "x"
        return end

    def _unquoted(self, top: str, char: str, index: int) -> int:
        """One unquoted character other than a newline, quote, escape or ``<<``; returns the next index."""
        text, g, stack = self.text, self.g, self.stack
        following = text[index + 1] if index + 1 < len(text) else ""
        if char in " \t":
            self._end_word()
        elif char in ";&|":
            self._end_word()
            if char == ";" and following in ";&":  # ``;;``, ``;&``, ``;;&``: the next case pattern
                g.pattern = bool(stack) and stack[-1] == "esac"
                g.command = not g.pattern
                self.line.append(following)
                return index + 2
            if g.function_body:  # ``f() ;``: the body must be a compound command
                self._syntax_error()
            if char == ";" and g.loop in (2, 3):
                g.loop = 4
            g.after_compound = False
            if not g.pattern and top not in _CONDITION:  # ``a|b)`` is still the pattern
                g.command = not (char in "&|" and self.prev in "<>")  # ``>&2`` and ``>|`` redirect
        elif char in "<>":
            self._end_word()
            g.command = False  # a redirection: reserved words do not count after it
        elif char == "(":
            return self._open_paren(top, index, following)
        elif char == ")":
            return self._close_paren(top, index)
        elif char in "{[" and self._expansion_opens():  # ``${`` and ``$[``
            g.word_plain = False
            g.word.append(char)
            stack.append("${" if char == "{" else "]")
        elif char == "[" and g.word_assign and g.word_plain and self._word_is_name():
            # ``a[`` where an assignment can be: bash reads the subscript up to its ``]``, over lines too
            g.word.append(char)
            stack.append("]")
        else:
            self._start_word()
            g.word.append(char)
        return index + 1

    def _open_paren(self, top: str, index: int, following: str) -> int:
        text, g, stack = self.text, self.g, self.stack
        if top in _CONDITION:  # grouping in ``[[ ]]``
            self._end_word()
            stack.append("c)")
            return index + 1
        last = g.word[-1][-1] if g.word else ""
        if g.pattern and last != "$":  # ``case x in (a)``, or an extglob group in a pattern
            if last in _EXTGLOB:
                g.word_plain = False
                stack.append("g)")
            else:
                self._end_word()
            return index + 1
        if g.word:
            if last == "$":  # ``$(`` and ``$((``
                g.word_plain = False
                g.word.append("(")  # so a ``$`` after the ``)`` starts a new run of ``$``
                if following == "(":
                    stack.append("))")
                    return index + 2
                self._enter_command()
                return index + 1
            if last == "=" or last in _EXTGLOB:  # an array assignment, or an extglob group
                g.word_plain = False
                stack.append("g)")
                return index + 1
            token = "".join(g.word) if g.word_plain else ""
            if g.word_command and (token in _LEAD_INS or (token in ("for", "select") and following == "(")):
                self._end_word()  # ``if(``, ``{(``, ``for((``: the reserved word, then the parenthesis
            elif (g.word_command or g.function_name) and _next_char(text, index + 1) == ")":
                self._end_word()  # ``name()``
                return self._function_parens(index)
            else:
                self._syntax_error()  # ``foo(``: bash drops the command
                return index + 1
        if self.prev in "<>":  # ``<(`` and ``>(``
            self._enter_command()
            return index + 1
        if (g.function_body or g.name) and _next_char(text, index + 1) == ")":  # ``name ()``, ``function f ()``
            return self._function_parens(index)
        if following == "(":  # ``((``, ``for ((``
            if g.loop == 1:
                g.loop = 0
            g.function_body = False
            g.command = False
            stack.append("))")
            return index + 2
        if g.command or g.function_body:  # a subshell
            g.function_body = False
            g.command = False  # after it, no command word can follow
            self._enter_command("s)")
            return index + 1
        self._syntax_error()  # ``echo (``, ``x = (1, 2)``: bash drops the command
        return index + 1

    def _function_parens(self, index: int) -> int:
        """Skip the ``()`` of a function definition; its body (a compound command) must follow."""
        g = self.g
        g.function_name = False
        g.function_body = True
        g.command = True
        return self.text.index(")", index + 1) + 1

    def _close_paren(self, top: str, index: int) -> int:
        stack = self.stack
        self._end_word()
        if top == "c)":
            stack.pop()
            return index + 1
        if self.g.pattern:  # the end of a case pattern: a command follows
            self.g.pattern = False
            self.g.command = True
            return index + 1
        if top in (")", "s)"):
            stack.pop()
            self.g = self.saved.pop() if self.saved else _Grammar(command=False)
            self.g.after_compound = top == "s)"
            return index + 1
        self._syntax_error()  # no ``(`` is open here
        return index + 1

    # Neither helper joins the whole word for every ``{`` or ``[``: on a long word of them (a minified JSON
    # line) that cost grew with the square of the word's length, inside the post hook's lock.

    def _expansion_opens(self) -> bool:
        """Whether ``{`` or ``[`` here opens ``${``/``$[``: the word ends in an odd run of ``$``."""
        dollars = 0
        for part in reversed(self.g.word):  # only the parts in the trailing run of ``$``
            rest = part.rstrip("$")
            dollars += len(part) - len(rest)
            if rest:
                break
        return dollars % 2 == 1

    def _word_is_name(self) -> bool:
        """Whether the current word is a plain name, as ``a`` in ``a[`` (also ``a\\<newline>b[``, which is
        two parts). A word that is not a name never becomes one as it grows, which is remembered."""
        g = self.g
        if g.not_name:
            return False
        if _NAME.fullmatch("".join(g.word)):
            return True
        g.not_name = True
        return False

    # -- lines --

    def _newline(self, top: str, index: int) -> int | None:
        g = self.g
        self._end_word()
        significant = "".join(self.line).strip()
        if significant:
            self.last_line = significant
        self.line = []
        self.prev = "\n"
        if top not in _CONDITION:
            g.command = True
        g.after_compound = False
        if g.loop in (2, 3):
            g.loop = 4
        index += 1
        if self.error:  # bash drops the command and starts afresh on the next line
            self._reset()
            self.done = None
            self.start = index
            return index
        return self._after_line(index)

    def _after_line(self, index: int) -> int | None:
        """Read the heredoc bodies the line opened, then see whether the command is complete."""
        if self.heredocs:
            end = self._heredoc_bodies(index)
            if end is None:
                return None
            index = end
        self.bodies_at = None
        if not self._held():
            if has_text(self.text[self.start : index]):
                self.done = (self.start, index)
            self.start = index
            self.last_line = ""
        return index

    def _held(self) -> bool:
        g = self.g
        return bool(
            self.stack
            or self.heredocs
            or g.function_name
            or g.function_body
            or self.last_line.endswith(("|", "&&", "|&"))
        )

    def _reset(self) -> None:
        self.stack = []
        self.saved = []
        self.g = _Grammar()
        self.heredocs = []
        self.error = False
        self.line = []
        self.last_line = ""

    def _heredoc_bodies(self, index: int) -> int | None:
        """Skip the bodies of the heredocs opened on the line that just ended; None if one is unfinished."""
        text, size = self.text, len(self.text)
        while self.heredocs:
            word, strip_tabs, _named = self.heredocs[0]
            while True:
                # Read on from here when more text comes: the body lines before it did not end the heredoc,
                # so a long body is not read again for every new line.
                self.bodies_at = index
                if index >= size:
                    return None
                end = text.find("\n", index)
                if end < 0:
                    return None
                body = text[index:end]
                index = end + 1
                if (body.lstrip("\t") if strip_tabs else body) == word:
                    break
            self.heredocs.pop(0)
        return index

    def run(self) -> _Analysis:
        return self._finish(self._scan(0))

    def resume(self, text: str) -> _Analysis:
        """Go on reading ``text``, which is the text read so far plus more whole lines.

        Only for an analysis that was open from the first character (``start == 0``) and is
        ``resumable``: the result is the same as ``_Continuation(text).run()``, for the cost of the new
        lines only.
        """
        if len(text) > self.end:  # a final ``\`` newline is a continuation now
            self.escaped_end = False
        self.text = text
        index = self._after_line(self.bodies_at) if self.bodies_at is not None else self.end
        return self._finish(None if index is None else self._scan(index))

    @property
    def resumable(self) -> bool:
        return not self.open_word and not self.error

    def _scan(self, index: int | None) -> int | None:
        text, size = self.text, len(self.text)
        while index is not None and index < size:
            char = text[index]
            if self.error and char != "\n":  # bash discards the rest of the line
                end = text.find("\n", index)
                index = size if end < 0 else end
                continue
            top = self.stack[-1] if self.stack else ""
            if top in _QUOTES:
                index = self._quoted(top, char, index)
            elif top == "${":
                index = self._parameter(char, index)
            elif top in _ARITHMETIC:
                index = self._arithmetic(top, char, index)
            elif top == "g)":
                index = self._glob(char, index)
            else:
                index = self._shell(top, char, index)
        return index

    def _finish(self, index: int | None) -> _Analysis:
        text, size = self.text, len(self.text)
        if index is not None:
            self.end = size
        top = self.stack[-1] if self.stack else ""
        shell = top not in _QUOTES and top not in _ARITHMETIC and top not in ("${", "g)")
        # Input without a final newline ends its last word. A final ``\`` newline does not: the word goes on
        # on the next line (``ca\`` then ``se x in`` is ``case``), and ``resume`` must find it still open.
        if index is not None and not self.error and shell and not self.escaped_end:
            self._end_word()
            significant = "".join(self.line).strip()
            if significant:
                self.last_line = significant
        quoted = any(entry in _QUOTES for entry in self.stack)
        named = any(named for _word, _tabs, named in self.heredocs)
        trailing = self.last_line.endswith(("|", "&&", "|&"))
        lexical = quoted or named or self.escaped_end or self.open_word or trailing
        held = not self.error and (index is None or self.escaped_end or self.open_word or self._held())
        if not held:
            if not self.error and has_text(text[self.start :]):
                self.done = (self.start, size)
            elif self.error:
                self.done = None
            return _Analysis(False, size, False, False, self.done)
        bounded = not lexical and all(entry in _HELD for entry in self.stack)
        return _Analysis(True, self.start, lexical, bounded, self.done)


def continues(text: str) -> bool:
    """Whether a shell that read ``text`` (whole lines) still waits for more of the same command.

    True for an open quote or backtick (also nested, as in ``"$(echo "``), an escaped final newline, an
    unfinished heredoc, a last non-blank line ending in ``|``, ``||``, ``&&`` or ``|&``, or an open
    ``(``, ``$(``, ``<(``, ``>(``, ``$((``, ``$[``, ``${``, ``{``, ``[[``, ``if``, ``case``, loop or
    function body. A syntax error (``foo(``, a stray ``fi``) makes bash drop the command, so it ends
    it. Such a command is kept together for the next check, so lines a person approved one at a time
    (an unfinished ``bash -c $(``) are checked again together with the lines that complete them. Every
    complete line is checked either way.
    """
    return _Continuation(text).run().open


@dataclass(frozen=True)
class _Step:
    pending: str  # the unfinished input after the keys
    completed: bool  # the keys ended at least one line
    carry: str | None  # the command that ended, or was given up on, with these keys (see ProcessInput._carry)
    parser: _Continuation | None = None  # resumable for the next keys: it has read the held whole lines


def _cap(text: str) -> str:
    """At most MAX_HELD_BYTES of ``text``, cut at a line start, keeping the end."""
    if len(text.encode("utf-8", "surrogatepass")) <= MAX_HELD_BYTES:
        return text
    tail = text[-MAX_HELD_BYTES:]
    cut = tail.find("\n")
    return tail[cut + 1 :] if cut >= 0 else tail


def _advance(prior: str, keys: str, parser: _Continuation | None = None) -> _Step:
    """Where the input stands once ``keys`` follow ``prior``. ``parser``: the one that read ``prior``'s
    whole lines (from the last step), so only the new lines are read."""
    if interrupt_only(keys):  # Ctrl-C / Ctrl-D on its own: a terminal cancels what was typed
        return _Step("", False, None)
    text = prior + keys
    end = text.rfind("\n")
    if end < 0:
        return _Step(text, False, None, parser)
    head, tail = _normalise(text[: end + 1]), text[end + 1 :]
    completed = "\n" in keys
    if parser is not None and parser.resumable and head.startswith(parser.text):
        found = parser.resume(head)
    else:
        parser = _Continuation(head)
        found = parser.run()
    if not found.open:
        carry = head[found.done[0] : found.done[1]].rstrip("\n") if found.done else None
        return _Step(tail, completed, _cap(carry) if carry else None)
    held = head[found.start :]
    if found.bounded and (
        held.count("\n") > MAX_HELD_LINES or len(held.encode("utf-8", "surrogatepass")) > MAX_HELD_BYTES
    ):
        return _Step(tail, completed, _cap(held.rstrip("\n")))  # given up on: line by line again
    return _Step(held + tail, completed, None, parser if found.start == 0 else None)


def advance(prior: str, keys: str) -> str:
    """The unfinished input of a process that held ``prior`` once ``keys`` reach it."""
    return _advance(prior, keys).pending


def _cancel_asks(prior: str) -> bool:
    """Whether Ctrl-C or Ctrl-D on its own asks, as in 0.1.0: text is typed on the current line, or a
    quote, a named heredoc, a final ``\\`` or a trailing ``|`` holds the command (what 0.1.0 tracked).

    A terminal cancels the typed text, but a program that reads a pipe gets the key as a character
    and keeps the text, so tirith cannot tell what would run.
    """
    end = prior.rfind("\n")
    if has_text(prior[end + 1 :]):
        return True
    return end >= 0 and _Continuation(_normalise(prior[: end + 1])).run().lexical


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


def _with_context(context: str, scan: str | None) -> str | None:
    """``scan`` checked together with the carried line before it (see ``ProcessInput._carry``)."""
    return context + "\n" + scan if context and scan is not None else scan


def _related(a: str, b: str) -> bool:
    return a != b and (a.startswith(b) or b.startswith(a))


def _normalise(text: str) -> str:
    """Enter as CR LF counts as LF."""
    return text.replace("\r\n", "\n") if "\r" in text else text


def _ready(text: str, eof: bool) -> str | None:
    """What a shell would run from ``text`` now: complete lines, or everything at end of input."""
    normalised = _normalise(text)
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
    incomplete: bool = False  # tirith could not analyse the text this call completes (analysis_incomplete)


class ProcessInput:
    """Confirmed unfinished input and unresolved calls, guarded by one worker-thread lock.

    Calls are reserved before scanning. Overlapping calls settle together: only a single confirmed
    delivery has a known order. Multiple deliveries or unknown results leave an explicit fail-closed
    state for that process, not an invented command. Unconfirmed calls never expire.

    Capacity limits apply to the call or process that would need a new entry: its input fails
    closed, and tracking recovers as calls finish and processes exit. Input that ran anyway (an
    approved failed check, or ``fail_closed: false``) is still recorded, so the limits are soft.

    Defence in depth: when tirith reported ``analysis_incomplete`` for a line that ran and the line
    is no longer held as part of a longer command, the next line is checked together with it
    (``_carry``), in case the shell still reads it as one command for a reason this module misses.
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
        # process -> the text of its last line that tirith reported analysis_incomplete for, checked
        # again in front of the next line it ends. Defence in depth only: the oldest is dropped first.
        self._carry: OrderedDict[str, str] = OrderedDict()
        # process -> the parser that read its held whole lines: each delivery reads only its new lines
        self._parsers: dict[str, _Continuation] = {}
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
        self._parsers.pop(process, None)
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

    def _apply(self, process: str, keys: str, incomplete: bool = False) -> None:
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
        step = _advance(prior, keys, self._parsers.pop(process, None))
        if step.parser is not None:
            self._parsers[process] = step.parser
        if step.pending:
            self._pending[process] = step.pending  # plan() refuses a new process when full; this ran anyway
        else:
            self._pending.pop(process, None)
        if step.completed:  # the next line no longer needs the earlier carry
            self._carry.pop(process, None)
            if incomplete and step.carry:
                self._carry[process] = step.carry
                while len(self._carry) > self._max_processes:
                    self._carry.popitem(last=False)

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
                self._apply(entry.process, entry.keys, entry.incomplete)

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
            context = self._carry.get(process, "")
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
            elif interrupt_only(keys) and not _cancel_asks(prior):
                pass  # a terminal cancels what was typed, and the shell drops it: nothing runs
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
                scan = _with_context(context, _ready(text, eof)) if scannable else None
                return Plan(process, keys, text, scan=scan, error=error)
            if interrupt_only(keys):
                return Plan(process, keys, text)
            return Plan(process, keys, text, scan=_with_context(context, _ready(text, eof)))

    def started(
        self, call_id: object, process: str, keys: str, *, permitted: bool = True, incomplete: bool = False
    ) -> None:
        """The pre hook returned. An earlier terminal post wins over this late registration.

        ``incomplete``: tirith reported ``analysis_incomplete`` for what this call completes.
        """
        with self._lock:
            if call_id in self._finished:
                self._finished[call_id] = None  # the late pre has now returned; safe to retire this tombstone
            else:
                self._reserve(call_id, process, keys, preparing=False)
            entry = self._inflight.get(call_id)
            if entry is None:
                return  # finished already, or not tracked (its post marks the process unknown)
            entry.preparing = False
            entry.incomplete = incomplete
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
            self._carry.pop(process, None)
            self._parsers.pop(process, None)
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
            self._carry.clear()
            self._parsers.clear()
