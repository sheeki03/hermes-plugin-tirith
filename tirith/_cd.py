"""Whether a terminal command can move the shell to another directory (Hermes Desktop batches).

The command is split into simple commands, and each one's command word is found the way bash finds
it: after ``NAME=value`` assignments and redirections (``>/dev/null cd``, ``cd>/dev/null``), after the
reserved words that start a command (``if``, ``then``, ``do``, ``!``, ``{``, ``time [-p] [--]``), and
through the builtins that run the next word (``builtin``, ``command [-p]``, and ``eval``, whose
arguments are read as a command again). Quotes, backslashes and ``$'...'`` escapes are decoded, so
``'cd'``, ``c\\d`` and ``$'\\x63d'`` are ``cd``. Commands inside ``$(...)``, backticks, ``<(...)`` and
subshells count too: they cannot move this shell, but asking about them only costs one prompt.

A heuristic, not a parser: a directory change made under another name (a function, an alias, a
script) or built from a variable (``$CMD /tmp``, ``eval "$x"``) is not recognised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MOVES = frozenset({"cd", "pushd", "popd", "source", "."})
_METACHARS = " \t\n;&|()<>"
_LEADING = frozenset({"!", "{", "then", "do", "else", "elif", "if", "while", "until"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_FD = re.compile(r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}")
_ANSI = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c.|.)", re.S)
_ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_MAX_DEPTH = 8


@dataclass(frozen=True)
class _Word:
    text: str  # with quotes, backslashes and $'...' escapes decoded
    raw: str
    quoted: bool = False
    dynamic: bool = False  # has an expansion: its value is not known here


def _ansi_char(match: re.Match[str]) -> str:
    code = match.group(1)
    if code[0] in "xuU" and len(code) > 1:
        return chr(min(int(code[1:], 16), 0x10FFFF))
    if code[0] in "01234567":
        return chr(int(code, 8) & 0xFF)
    if code[0] == "c":
        return chr(ord(code[1]) & 0x1F)
    return _ANSI_SIMPLE.get(code, code)


def _group_end(text: str, index: int, opener: str, closer: str) -> int:
    """The index after the ``closer`` that matches the ``opener`` at ``index`` (quotes skipped)."""
    depth = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 1
        elif char == "'":
            close = text.find("'", index + 1)
            index = len(text) if close < 0 else close
        elif char == '"':
            index += 1
            while index < len(text) and text[index] != '"':
                index += 2 if text[index] == "\\" else 1
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


def _expansion(text: str, index: int, nested: list[str]) -> int:
    """Skip the ``$(...)``, ``$((...))``, ``${...}``, ``$[...]``, backtick, ``<(...)`` or ``>(...)`` at
    ``index``; what it contains is kept in ``nested`` to be checked as commands too."""
    if text[index] == "`":
        end = index + 1
        while end < len(text) and text[end] != "`":
            end += 2 if text[end] == "\\" else 1
        nested.append(text[index + 1 : end])
        return end + 1
    opener = text[index + 1]
    closer = {"(": ")", "{": "}", "[": "]"}[opener]
    end = _group_end(text, index + 1, opener, closer)
    nested.append(text[index + 2 : end - 1])
    return end


def _word(text: str, index: int, nested: list[str]) -> tuple[_Word, int]:
    start, size = index, len(text)
    parts: list[str] = []
    quoted = dynamic = False
    while index < size:
        char = text[index]
        following = text[index + 1 : index + 2]
        if char == "(" and parts and parts[-1][-1:] in ("=", "@", "!", "?", "*", "+"):  # an array or extglob
            index = _group_end(text, index, "(", ")")
            dynamic = True
            continue
        if char in _METACHARS:
            break
        if char == "\\":
            if following != "\n":
                parts.append(following)
                quoted = True
            index += 2
        elif char == "'":
            close = text.find("'", index + 1)
            close = size if close < 0 else close
            parts.append(text[index + 1 : close])
            quoted = True
            index = close + 1
        elif char == "$" and following == "'":
            close = index + 2
            while close < size and text[close] != "'":
                close += 2 if text[close] == "\\" else 1
            parts.append(_ANSI.sub(_ansi_char, text[index + 2 : close]))
            quoted = True
            index = close + 1
        elif char == '"' or (char == "$" and following == '"'):
            index += 2 if char == "$" else 1
            quoted = True
            while index < size and text[index] != '"':
                inner = text[index]
                after = text[index + 1 : index + 2]
                if inner == "\\":
                    if after != "\n":
                        parts.append(after if after in '$`"\\' else inner + after)
                    index += 2
                elif inner == "`" or (inner == "$" and after in ("(", "{", "[")):
                    index = _expansion(text, index, nested)
                    dynamic = True
                elif inner == "$" and (after.isalnum() or after in ("_", "@", "*", "#", "?", "$", "!", "-")):
                    dynamic = True
                    index += 1
                else:
                    parts.append(inner)
                    index += 1
            index += 1
        elif char == "`" or (char == "$" and following in ("(", "{", "[")):
            index = _expansion(text, index, nested)
            dynamic = True
        elif char == "$" and (following.isalnum() or following in ("_", "@", "*", "#", "?", "$", "!", "-")):
            dynamic = True
            index += 1
        else:
            parts.append(char)
            index += 1
    return _Word("".join(parts), text[start:index], quoted, dynamic), index


def _split(text: str, nested: list[str]) -> list[list[_Word]]:
    """The words of each simple command in ``text``; the texts of nested commands go to ``nested``."""
    commands: list[list[_Word]] = [[]]
    index, size = 0, len(text)
    target = False  # the next word is the target of a redirection
    while index < size:
        char = text[index]
        if char in " \t":
            index += 1
        elif char == "#" and (index == 0 or text[index - 1] in _METACHARS):  # a comment
            end = text.find("\n", index)
            index = size if end < 0 else end
        elif char == "\\" and text.startswith("\n", index + 1):
            index += 2
        elif char in "<>" and text.startswith("(", index + 1):  # <( and >(: a command of its own
            index = _expansion(text, index, nested)
            commands[-1].append(_Word("", text[index - 1 : index], dynamic=True))
        elif char in "<>" or (char == "&" and text.startswith(">", index + 1)):
            end = index + 1
            while end < size and text[end] in "<>&|":
                end += 1
            if text[index:end] == "<<" and text.startswith("-", end):
                end += 1
            index, target = end, True
        elif char in "\n;&|()":
            commands.append([])
            index += 1
            target = False
        else:
            word, index = _word(text, index, nested)
            if not word.quoted and _FD.fullmatch(word.raw) and text.startswith(("<", ">"), index):
                continue  # ``2>file``: the file descriptor of the redirection that follows
            if target:
                target = False
            elif word.raw in ("{", "}"):  # ``function f { cd /tmp; }``: a group starts or ends
                commands.append([word] if word.raw == "{" else [])
            else:
                commands[-1].append(word)
    return [words for words in commands if words]


def _command_moves(words: list[_Word], depth: int) -> bool:
    index = 0
    while index < len(words):
        word = words[index]
        plain = not word.quoted and not word.dynamic
        if plain and word.text in _LEADING:
            index += 1
        elif plain and word.text == "time":  # time [-p] [--]
            index += 1
            for option in ("-p", "--"):
                if index < len(words) and words[index].raw == option:
                    index += 1
        elif _ASSIGNMENT.match(word.raw):
            index += 1
        else:
            break
    if index >= len(words) or words[index].dynamic:
        return False
    name, rest = words[index].text, words[index + 1 :]
    if name in MOVES:
        return True
    if name == "builtin":
        return _command_moves(rest[1:] if rest[:1] and rest[0].raw == "--" else rest, depth)
    if name == "command":  # command [-pVv] [--] name: with -v or -V it only prints
        while rest and rest[0].raw.startswith("-") and not rest[0].quoted:
            option, rest = rest[0].raw, rest[1:]
            if option == "--":
                break
            if "v" in option or "V" in option:
                return False
        return _command_moves(rest, depth)
    if name == "eval":
        rest = rest[1:] if rest[:1] and rest[0].raw == "--" else rest
        return depth < _MAX_DEPTH and moves_directory(
            " ".join(word.raw if word.dynamic else word.text for word in rest), depth + 1
        )
    return False


def moves_directory(command: str, depth: int = 0) -> bool:
    """Whether ``command`` may change the shell's directory (a heuristic; see the module docstring)."""
    nested: list[str] = []
    if any(_command_moves(words, depth) for words in _split(command, nested)):
        return True
    return depth < _MAX_DEPTH and any(moves_directory(text, depth + 1) for text in nested)
