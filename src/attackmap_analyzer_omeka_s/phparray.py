"""A small, bounded reader for PHP array literals (mlaify/attackmap-analyzer-php-laminas#2).

Copied from attackmap-analyzer-php-laminas (#2 there) so this plugin has no
cross-plugin dependency; mlaify/AttackMap#259 will consider extracting shared PHP
helpers. Keep the two copies in sync.

Laminas config is a nested PHP array (`'router' => ['routes' => [...]]`), so a
flat `'route' => '...'` regex can't tell a child route from a top-level one.
This module tokenizes PHP source well enough to walk those arrays
structurally:

- `[` / `]` and `array(` / `)` are balanced; `(`, `{` inside values are skipped
  as opaque expressions (closures, `__DIR__ . '/x'`, function calls);
- single/double-quoted strings, heredoc/nowdoc and `//`, `#`, `/* */`
  comments are recognized, so brackets inside them don't count.

It never raises on garbage, truncated or hostile input: every loop advances,
nesting deeper than ``MAX_DEPTH`` becomes an opaque expression, and a file
yields at most ``MAX_TOKENS`` tokens.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Union

MAX_DEPTH = 64
MAX_TOKENS = 500_000

# Token kinds.
STR = "str"
OPEN = "open"  # `[` or `array(`: an array literal
CLOSE = "close"  # `]` or `)`
LPAREN = "lparen"  # `(` that is not `array(`
LBRACE = "lbrace"
RBRACE = "rbrace"
ARROW = "arrow"
COMMA = "comma"
WORD = "word"  # identifiers, `Foo\Bar::class`, numbers, `$vars`
OP = "op"  # anything else (`.`, `;`, `=`, `->`, ...)

_WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_\\$:")
_HEREDOC_START = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_DQ_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "$": "$"}


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    offset: int


class TokenList(list):
    """Tokens, plus ``truncated``: True when ``max_tokens`` stopped the
    tokenizer before the end of the source (``end_offset`` is where)."""

    truncated: bool = False
    end_offset: int = 0


def tokenize(source: str, start: int = 0, max_tokens: int = MAX_TOKENS) -> TokenList:
    """Tokenize PHP source from ``start``. Unterminated strings/comments run to EOF."""
    tokens = TokenList()
    n = len(source)
    i = start
    while i < n and len(tokens) < max_tokens:
        c = source[i]
        if c in " \t\r\n\f\v":
            i += 1
            continue
        if c == "/" and source.startswith("//", i) or c == "#" and not source.startswith("#[", i):
            end = source.find("\n", i)
            i = n if end < 0 else end + 1
            continue
        if c == "/" and source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if c == "'":
            value, i_next = _single_quoted(source, i)
            tokens.append(Token(STR, value, i))
            i = i_next
            continue
        if c == '"':
            value, i_next = _double_quoted(source, i)
            tokens.append(Token(STR, value, i))
            i = i_next
            continue
        if c == "<" and source.startswith("<<<", i):
            heredoc = _heredoc(source, i)
            if heredoc is not None:
                value, i_next = heredoc
                tokens.append(Token(STR, value, i))
                i = i_next
                continue
        if c == "[":
            tokens.append(Token(OPEN, c, i))
            i += 1
            continue
        if c in "])":
            tokens.append(Token(CLOSE, c, i))
            i += 1
            continue
        if c == "(":
            tokens.append(Token(LPAREN, c, i))
            i += 1
            continue
        if c == "{":
            tokens.append(Token(LBRACE, c, i))
            i += 1
            continue
        if c == "}":
            tokens.append(Token(RBRACE, c, i))
            i += 1
            continue
        if c == ",":
            tokens.append(Token(COMMA, c, i))
            i += 1
            continue
        if c == "=" and source.startswith("=>", i):
            tokens.append(Token(ARROW, "=>", i))
            i += 2
            continue
        if c in _WORD_CHARS:
            j = i + 1
            while j < n and source[j] in _WORD_CHARS:
                j += 1
            word = source[i:j]
            # `array(` opens an array literal, like `[`.
            k = j
            while k < n and source[k] in " \t\r\n":
                k += 1
            if word.lower() == "array" and k < n and source[k] == "(":
                tokens.append(Token(OPEN, "array(", i))
                i = k + 1
                continue
            tokens.append(Token(WORD, word, i))
            i = j
            continue
        tokens.append(Token(OP, c, i))
        i += 1
    tokens.truncated = i < n
    tokens.end_offset = i
    return tokens


def _single_quoted(source: str, i: int) -> tuple[str, int]:
    out: list[str] = []
    j = i + 1
    n = len(source)
    while j < n:
        c = source[j]
        if c == "\\" and j + 1 < n and source[j + 1] in "'\\":
            out.append(source[j + 1])
            j += 2
            continue
        if c == "'":
            return "".join(out), j + 1
        out.append(c)
        j += 1
    return "".join(out), n


def _double_quoted(source: str, i: int) -> tuple[str, int]:
    out: list[str] = []
    j = i + 1
    n = len(source)
    while j < n:
        c = source[j]
        if c == "\\" and j + 1 < n:
            nxt = source[j + 1]
            if nxt in _DQ_ESCAPES:
                out.append(_DQ_ESCAPES[nxt])
                j += 2
                continue
            out.append(c)
            j += 1
            continue
        if c == '"':
            return "".join(out), j + 1
        out.append(c)
        j += 1
    return "".join(out), n


def _heredoc(source: str, i: int) -> tuple[str, int] | None:
    match = _HEREDOC_START.match(source, i)
    if match is None:
        return None
    ident = match.group(2)
    body_start = source.find("\n", match.end())
    if body_start < 0:
        return "", len(source)
    pos = body_start + 1
    n = len(source)
    while pos < n:
        line_end = source.find("\n", pos)
        line = source[pos : n if line_end < 0 else line_end]
        stripped = line.lstrip(" \t")
        if stripped.startswith(ident) and not (
            len(stripped) > len(ident) and (stripped[len(ident)].isalnum() or stripped[len(ident)] == "_")
        ):
            end = pos + (len(line) - len(stripped)) + len(ident)
            return source[body_start + 1 : max(body_start + 1, pos - 1)], end
        if line_end < 0:
            break
        pos = line_end + 1
    return source[body_start + 1 :], n


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


@dataclass
class PhpString:
    value: str
    offset: int


@dataclass
class PhpExpr:
    """Anything that isn't a plain string or array: `Foo::class`, `true`,
    `null`, `__DIR__ . '/x'`, a closure. ``text`` is the space-joined tokens."""

    text: str
    offset: int


@dataclass
class PhpArray:
    offset: int
    items: list[tuple["PhpValue | None", "PhpValue"]] = field(default_factory=list)

    def get(self, key: str) -> "PhpValue | None":
        """The value of string key ``key`` (last one wins, as in PHP)."""
        found = None
        for item_key, value in self.items:
            if isinstance(item_key, PhpString) and item_key.value == key:
                found = value
        return found

    def entries(self) -> list[tuple[str, "PhpValue"]]:
        """``(key, value)`` pairs whose key is a string literal."""
        return [(k.value, v) for k, v in self.items if isinstance(k, PhpString)]


PhpValue = Union[PhpString, PhpExpr, PhpArray]


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.n = len(tokens)

    def parse_array(self, i: int, depth: int = 0) -> tuple[PhpArray, int]:
        """Parse the array whose OPEN token is at ``i``; return it and the index after its CLOSE."""
        array = PhpArray(offset=self.tokens[i].offset)
        i += 1
        while i < self.n:
            tok = self.tokens[i]
            if tok.kind == CLOSE or tok.kind == RBRACE:
                return array, i + 1
            if tok.kind == COMMA:
                i += 1
                continue
            first, j = self.parse_value(i, depth)
            if j < self.n and self.tokens[j].kind == ARROW:
                value, j = self.parse_value(j + 1, depth)
                array.items.append((first, value))
            else:
                array.items.append((None, first))
            # Skip anything unexpected up to the next separator.
            while j < self.n and self.tokens[j].kind not in (COMMA, CLOSE, RBRACE):
                j += 1
            i = max(j, i + 1)
        return array, self.n

    def parse_value(self, i: int, depth: int) -> tuple[PhpValue, int]:
        """Parse one value starting at ``i``; stops before a top-level `,`, `=>` or closer."""
        start = i
        if i >= self.n:
            return PhpExpr("", self.tokens[-1].offset if self.tokens else 0), i
        tok = self.tokens[i]
        if tok.kind == OPEN and depth < MAX_DEPTH:
            array, j = self.parse_array(i, depth + 1)
            if self._at_value_end(j):
                return array, j
            # `[...]` followed by more expression (`[...] + $x`): opaque.
            i = j
        elif tok.kind == STR and self._at_value_end(i + 1):
            return PhpString(tok.text, tok.offset), i + 1
        parts: list[str] = []
        level = 0
        while i < self.n:
            tok = self.tokens[i]
            if tok.kind in (OPEN, LPAREN, LBRACE):
                level += 1
            elif tok.kind in (CLOSE, RBRACE):
                if level == 0:
                    break
                level -= 1
            elif level == 0 and tok.kind in (COMMA, ARROW):
                break
            if len(parts) < 64:
                parts.append(tok.text)
            i += 1
        # May return ``start`` itself (an empty value before a closer); callers
        # guarantee progress.
        return PhpExpr(" ".join(parts), self.tokens[start].offset), i

    def _at_value_end(self, j: int) -> bool:
        return j >= self.n or self.tokens[j].kind in (COMMA, ARROW, CLOSE, RBRACE)


def parse_array_at(tokens: list[Token], index: int) -> PhpArray | None:
    """Parse the array literal whose OPEN token is ``tokens[index]``."""
    if not (0 <= index < len(tokens)) or tokens[index].kind != OPEN:
        return None
    array, _ = _Parser(tokens).parse_array(index)
    return array


def parse_array_span(tokens: list[Token], index: int) -> tuple[PhpArray | None, int]:
    """Like :func:`parse_array_at`, plus the token index after the array."""
    if not (0 <= index < len(tokens)) or tokens[index].kind != OPEN:
        return None, index + 1
    return _Parser(tokens).parse_array(index)


def parse_call_args(tokens: list[Token], index: int) -> tuple[list[PhpValue], int]:
    """Parse the arguments of a call whose `(` is ``tokens[index]``; return
    them and the token index after the closing `)`."""
    if not (0 <= index < len(tokens)) or tokens[index].kind not in (LPAREN, OPEN):
        return [], index + 1
    parser = _Parser(tokens)
    args: list[PhpValue] = []
    i = index + 1
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind in (CLOSE, RBRACE):
            return args, i + 1
        if tok.kind in (COMMA, ARROW):
            i += 1
            continue
        value, j = parser.parse_value(i, 0)
        args.append(value)
        i = max(j, i + 1)
    return args, len(tokens)


def keyed_arrays(tokens: list[Token], key: str) -> list[PhpArray]:
    """Every array literal that is the value of string key ``key`` (`'key' => [...]`)."""
    found: list[PhpArray] = []
    parser = _Parser(tokens)
    i = 0
    while i < len(tokens) - 2:
        tok = tokens[i]
        if tok.kind == STR and tok.text == key and tokens[i + 1].kind == ARROW and tokens[i + 2].kind == OPEN:
            array, end = parser.parse_array(i + 2)
            found.append(array)
            # Continue after it: a nested `'key' => [...]` was already parsed
            # as part of this one, and re-parsing would be quadratic.
            i = max(end, i + 1)
            continue
        i += 1
    return found


def keyed_array_spans(tokens: list[Token], key: str) -> list[tuple[int, int]]:
    """Source ``(start, end)`` offsets of every outermost array literal that is
    the value of string key ``key``. An unterminated array runs to the last token."""
    spans: list[tuple[int, int]] = []
    parser = _Parser(tokens)
    n = len(tokens)
    i = 0
    while i < n - 2:
        tok = tokens[i]
        if tok.kind == STR and tok.text == key and tokens[i + 1].kind == ARROW and tokens[i + 2].kind == OPEN:
            _, end = parser.parse_array(i + 2)
            last = tokens[min(end, n) - 1]
            spans.append((tokens[i + 2].offset, last.offset + len(last.text)))
            i = max(end, i + 1)
            continue
        i += 1
    return spans


# ---------------------------------------------------------------------------
# PHP names
# ---------------------------------------------------------------------------

_NAMESPACE_DECL = re.compile(r"^[ \t]*namespace[ \t]+([A-Za-z_\\][A-Za-z0-9_\\]*+)[ \t]*[;{]", re.MULTILINE)
_USE_DECL = re.compile(
    r"^[ \t]*use[ \t]+([A-Za-z_\\][A-Za-z0-9_\\]*+)(?:[ \t]+as[ \t]+([A-Za-z_][A-Za-z0-9_]*+))?[ \t]*;",
    re.MULTILINE | re.IGNORECASE,
)


@dataclass
class NameContext:
    """A file's `namespace` and `use` imports, for resolving `Foo::class`."""

    namespace: str = ""
    uses: dict[str, str] = field(default_factory=dict)

    @classmethod
    def of(cls, source: str) -> "NameContext":
        ns = _NAMESPACE_DECL.search(source)
        uses: dict[str, str] = {}
        for match in _USE_DECL.finditer(source):
            name = match.group(1).strip("\\")
            alias = match.group(2) or name.rsplit("\\", 1)[-1]
            uses.setdefault(alias, name)
        return cls(namespace=ns.group(1).strip("\\") if ns else "", uses=uses)

    def resolve(self, name: str) -> str:
        """Fully-qualify a class name written in this file (no leading `\\`)."""
        if name.startswith("\\"):
            return name.lstrip("\\")
        head, sep, tail = name.partition("\\")
        if head in self.uses:
            return self.uses[head] + (sep + tail if sep else "")
        if head.lower() == "namespace" and sep:
            return f"{self.namespace}\\{tail}" if self.namespace else tail
        return f"{self.namespace}\\{name}" if self.namespace else name


def class_name(value: PhpValue | None, names: NameContext) -> str | None:
    """`'Foo\\Bar'` or `Foo\\Bar::class` as a fully-qualified class name, else None."""
    if isinstance(value, PhpString):
        text = value.value.strip()
        return text.lstrip("\\") or None if _is_class_like(text) else None
    if isinstance(value, PhpExpr):
        text = value.text.strip()
        if text.endswith("::class") and " " not in text:
            base = text[: -len("::class")]
            if _is_class_like(base):
                return names.resolve(base)
    return None


def _is_class_like(text: str) -> bool:
    return bool(text) and all(c.isalnum() or c in "_\\" for c in text) and not text[0].isdigit()


def is_true(value: PhpValue | None) -> bool:
    return isinstance(value, PhpExpr) and value.text.strip().lower() == "true"
