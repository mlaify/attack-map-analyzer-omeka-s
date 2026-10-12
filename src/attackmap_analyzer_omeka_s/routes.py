"""Structural Laminas router and Mezzio route extraction (mlaify/attackmap-analyzer-php-laminas#2).

Copied from attackmap-analyzer-php-laminas (#2 there) so this plugin has no
cross-plugin dependency; mlaify/AttackMap#259 will consider extracting shared PHP
helpers. Keep the two copies in sync.

Laminas router config is a tree::

    'router' => ['routes' => [
        'admin' => [
            'type' => Literal::class,
            'options' => ['route' => '/admin', 'defaults' => [...]],
            'may_terminate' => true,
            'child_routes' => [
                'user' => ['type' => Segment::class, 'options' => ['route' => '/users[/:id]']],
                'save' => ['type' => Method::class, 'options' => ['verb' => 'post']],
            ],
        ],
    ]]

:func:`router_routes` walks it with :mod:`.phparray` and returns one record per
reachable path:

- **child_routes are joined** onto their parent's path (`/admin/users`). A
  parent is itself reachable only if it has no children or sets
  `'may_terminate' => true`.
- **Method routes** (`Method::class`, `'verb' => 'post'`, comma lists) put
  their HTTP method(s) on the parent's path instead of adding a path.
- **Segment optional parts** (`[/:action[/:id]]`) are expanded progressively:
  the minimal form, then one more optional group opened at a time in source
  order (`/users`, `/users/:id`). That is at most ``MAX_FORMS`` paths per route,
  so `/:controller[/:action[/:id]]` yields 3 paths, not every combination.
  Children join onto their parent's minimal form. `:param{delims}` and
  translated `{literal}` parts are reduced to `:param` and `literal`.
- `Hostname`/`Scheme` routes contribute no path; `Regex` routes use their
  `spec` (`/install`, with `%param%` as `:param`). Part, Wildcard, Query and
  console routes are skipped.

:func:`mezzio_routes` reads Mezzio/Expressive `$app->get('/x', ...)`,
`->post/put/patch/delete/any` and `$app->route('/x', $mw, ['GET', 'POST'])`.
FastRoute placeholders keep their name (`{id:\\d+}` becomes `{id}`) and
optional `[...]` parts expand the same way.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

from .phparray import (
    ARROW,
    LPAREN,
    OP,
    OPEN,
    WORD,
    PhpArray,
    PhpExpr,
    PhpString,
    PhpValue,
    STR,
    Token,
    TokenList,
    is_true,
    keyed_array_spans,
    parse_array_span,
    parse_call_args,
)

MAX_FORMS = 4
MAX_OPTIONAL_NESTING = 16
MAX_ROUTE_DEPTH = 32
MAX_ROUTES_PER_FILE = 5_000

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"})
_PATH_KINDS = frozenset({"literal", "segment", None})
# `:param{-/}` delimiter spec → `:param`; translated `{literal}` → `literal`.
_SEGMENT_DELIMS = re.compile(r"(:[A-Za-z0-9_-]++)\{[^{}]*\}")
_SEGMENT_TRANSLATE = re.compile(r"\{([^{}:]*)\}")
_REGEX_SPEC_PARAM = re.compile(r"%([A-Za-z0-9_-]++)%")
_MULTI_SLASH = re.compile(r"//++")
_MEZZIO_VERBS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "any": "ANY"}


@dataclass
class LaminasRoute:
    path: str
    method: str
    offset: int
    name: str
    template: str
    defaults: dict[str, PhpValue] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Optional-part expansion
# ---------------------------------------------------------------------------


def _parse_optional(template: str) -> list:
    """Parse ``template`` into a list of str and nested lists (optional groups)."""
    root: list = []
    stack: list[list] = [root]
    buf: list[str] = []
    for ch in template:
        if ch == "[" and len(stack) <= MAX_OPTIONAL_NESTING:
            stack[-1].append("".join(buf))
            buf = []
            group: list = []
            stack[-1].append(group)
            stack.append(group)
        elif ch == "]" and len(stack) > 1:
            stack[-1].append("".join(buf))
            buf = []
            stack.pop()
        else:
            buf.append(ch)
    stack[-1].append("".join(buf))
    return root


def _groups_preorder(node: list, out: list[int]) -> None:
    for part in node:
        if isinstance(part, list):
            out.append(id(part))
            _groups_preorder(part, out)


def _render(node: list, opened: set[int]) -> str:
    out: list[str] = []
    for part in node:
        if isinstance(part, list):
            if id(part) in opened:
                out.append(_render(part, opened))
        else:
            out.append(part)
    return "".join(out)


def expand_optional(template: str, max_forms: int = MAX_FORMS) -> list[str]:
    """Minimal form first, then one more optional group opened at a time.

    ``/:controller[/:action[/:id]]`` → ``/:controller``, ``/:controller/:action``,
    ``/:controller/:action/:id``. With more than ``max_forms - 1`` groups the
    last form is the maximal one. Unbalanced brackets never raise: a stray `]`
    is literal and an unclosed `[` closes at the end.
    """
    if "[" not in template:
        return [template]
    tree = _parse_optional(template)
    order: list[int] = []
    _groups_preorder(tree, order)
    counts = list(range(len(order) + 1))
    if len(counts) > max_forms:
        counts = counts[: max_forms - 1] + [len(order)]
    forms: list[str] = []
    for k in counts:
        form = _render(tree, set(order[:k]))
        if form not in forms:
            forms.append(form)
    return forms


def minimal_form(template: str) -> str:
    """``template`` with every optional group left out."""
    return _render(_parse_optional(template), set()) if "[" in template else template


def normalize_path(path: str) -> str:
    """Collapse `//`, drop a trailing `/` (except the root) and ensure a leading `/`."""
    path = _MULTI_SLASH.sub("/", path)
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return path


def _segment_text(piece: str) -> str:
    piece = _SEGMENT_DELIMS.sub(r"\1", piece)
    return _SEGMENT_TRANSLATE.sub(r"\1", piece)


# ---------------------------------------------------------------------------
# Laminas router config
# ---------------------------------------------------------------------------


def route_type(value: PhpValue | None) -> str | None:
    """`Segment::class`, `'Laminas\\Router\\Http\\Literal'`, `'segment'` → `segment`."""
    if isinstance(value, PhpString):
        text = value.value
    elif isinstance(value, PhpExpr):
        text = value.text
    else:
        return None
    text = text.strip()
    if text.endswith("::class"):
        text = text[: -len("::class")]
    short = text.rsplit("\\", 1)[-1].strip().lower()
    return short or None


@dataclass
class RouteNode:
    """What a named route passes to its children: the minimal path child
    routes join onto, the merged defaults, an inherited Method verb, and the
    full template (optional parts included) that Method children expand."""

    prefix: str
    defaults: dict[str, PhpValue] = field(default_factory=dict)
    method: str | None = None
    template: str | None = None


def route_trees(tokens: list[Token]) -> list[PhpArray]:
    """The route maps in a file: every `'router' => ['routes' => [...]]`, or
    else a file that just `return`s a route map.

    `'router' => $router` and `'routes' => $routes` follow a same-file
    `$routes = [...]` assignment (the last one before the use, else the first
    after it)."""
    trees: list[PhpArray] = []
    variables = _VariableArrays(tokens)
    seen: set[int] = set()  # the same `$router` used twice is walked once
    alive: list[PhpArray] = []
    i = 0
    n = len(tokens)
    while i < n - 2:
        tok = tokens[i]
        if tok.kind != STR or tok.text != "router" or tokens[i + 1].kind != ARROW:
            i += 1
            continue
        router, end = variables.value_at(i + 2)
        # Continue after a literal router array: a nested `'router' => [`
        # was parsed with it, and re-parsing would be quadratic.
        i = max(end, i + 1)
        if router is None or id(router) in seen:
            continue
        seen.add(id(router))
        alive.append(router)  # keep it alive so its id() isn't reused
        routes = router.get("routes")
        if isinstance(routes, PhpExpr):
            routes = variables.resolve(routes)
        if isinstance(routes, PhpArray) and id(routes) not in seen:
            seen.add(id(routes))
            trees.append(routes)
    return trees or _returned_route_maps(tokens)


class _VariableArrays:
    """`$name = [...]` assignments in a file, parsed on demand."""

    MAX_PARSES = 64

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.assignments: dict[str, list[int]] = {}
        self.cache: dict[int, PhpArray | None] = {}
        self.parses = 0
        n = len(tokens)
        for i in range(n - 2):
            tok = tokens[i]
            if (
                tok.kind == WORD
                and tok.text.startswith("$")
                and tokens[i + 1].kind == OP
                and tokens[i + 1].text == "="
                and tokens[i + 2].kind == OPEN
            ):
                self.assignments.setdefault(tok.text, []).append(i + 2)

    def _array(self, index: int) -> PhpArray | None:
        # Each assignment is parsed at most once, and at most MAX_PARSES are,
        # so hostile files can't make variable lookups quadratic.
        if index not in self.cache:
            if self.parses >= self.MAX_PARSES:
                return None
            self.parses += 1
            array, _ = parse_array_span(self.tokens, index)
            self.cache[index] = array
        return self.cache[index]

    def value_at(self, index: int) -> tuple[PhpArray | None, int]:
        """The array literal at token ``index`` (and the index after it), or
        the array a `$var` there holds (and ``index + 1``)."""
        if index >= len(self.tokens):
            return None, index
        tok = self.tokens[index]
        if tok.kind == OPEN:
            return parse_array_span(self.tokens, index)
        if tok.kind == WORD and tok.text.startswith("$"):
            return self._lookup(tok.text, tok.offset), index + 1
        return None, index + 1

    def resolve(self, value: PhpExpr) -> PhpArray | None:
        name = value.text.strip()
        if not name.startswith("$") or " " in name:
            return None
        return self._lookup(name, value.offset)

    def _lookup(self, name: str, offset: int) -> PhpArray | None:
        positions = self.assignments.get(name)
        if not positions:
            return None
        # The last assignment before the use, else the first one: token
        # indices ascend with offsets, so bisect on both.
        use = bisect.bisect_left(self.tokens, offset, key=lambda tok: tok.offset)
        at = bisect.bisect_left(positions, use)
        return self._array(positions[at - 1] if at > 0 else positions[0])


def router_routes(
    trees: list[PhpArray],
    known: dict[str, RouteNode] | None = None,
    index: dict[str, RouteNode] | None = None,
    consumed: set[int] | None = None,
) -> list[LaminasRoute]:
    """Routes from a file's route maps (see :func:`route_trees`).

    Laminas merges every module's config, so a module can add children to a
    route defined elsewhere (`'admin' => ['child_routes' => [...]]` with no
    type or route of its own). Such a stub is placed using ``known`` (full
    route name → :class:`RouteNode`); without an entry its children are
    skipped rather than reported as top-level paths. ``index``, when given,
    collects a :class:`RouteNode` for every named route walked, to build
    ``known`` across files. ``consumed``, when given, collects the source
    offsets of the `'route'`/`'spec'`/`'verb'` strings the walk used, so a
    caller can tell which literals it never reached.
    """
    out: list[LaminasRoute] = []
    ctx = _WalkContext(out, known or {}, index, consumed)
    for routes in trees:
        _walk(routes, "", "", "", {}, None, 0, ctx)
    return out


@dataclass
class _WalkContext:
    out: list[LaminasRoute]
    known: dict[str, RouteNode]
    index: dict[str, RouteNode] | None
    consumed: set[int] | None = None


def _returned_route_maps(tokens: list[Token]) -> list[PhpArray]:
    """`return ['home' => ['type' => ..., 'options' => ['route' => ...]]];` in a
    file `require`d as a router's routes."""
    maps: list[PhpArray] = []
    i = 0
    while i < len(tokens) - 1:
        if tokens[i].kind == WORD and tokens[i].text.lower() == "return" and tokens[i + 1].kind == OPEN:
            array, end = parse_array_span(tokens, i + 1)
            if array is not None and any(_looks_like_route_spec(v) for _, v in array.entries()):
                maps.append(array)
            # Skip the parsed array: re-parsing a nested `return [` would be quadratic.
            i = max(end, i + 1)
            continue
        i += 1
    return maps


def _looks_like_route_spec(value: PhpValue) -> bool:
    if not isinstance(value, PhpArray):
        return False
    options = value.get("options")
    return (
        value.get("type") is not None
        and isinstance(options, PhpArray)
        and isinstance(options.get("route"), PhpString)
    )


def _walk(
    routes: PhpArray,
    prefix: str,
    parent_template: str,
    prefix_name: str,
    defaults: dict[str, PhpValue],
    method: str | None,
    depth: int,
    ctx: _WalkContext,
) -> None:
    """``prefix`` is the parent's minimal path (child routes join onto it);
    ``parent_template`` keeps its optional parts, for Method children."""
    if depth > MAX_ROUTE_DEPTH:
        return
    out = ctx.out
    for name, spec in routes.entries():
        if len(out) >= MAX_ROUTES_PER_FILE:
            return
        if not isinstance(spec, PhpArray):
            continue
        kind = route_type(spec.get("type"))
        options = spec.get("options")
        if not isinstance(options, PhpArray):
            options = PhpArray(offset=spec.offset)
        own_defaults = options.get("defaults")
        full_name = f"{prefix_name}/{name}" if prefix_name else name
        children = spec.get("child_routes")
        terminates = not isinstance(children, PhpArray) or is_true(spec.get("may_terminate"))

        if kind is None and options.get("route") is None and isinstance(children, PhpArray):
            # A stub extending a route defined in another module's config.
            base = ctx.known.get(full_name)
            if base is None:
                continue
            merged = dict(base.defaults)
            if isinstance(own_defaults, PhpArray):
                merged.update(own_defaults.entries())
            base_template = base.template if base.template is not None else base.prefix
            _walk(children, base.prefix, base_template, full_name, merged, base.method, depth + 1, ctx)
            continue

        merged = dict(defaults)
        if isinstance(own_defaults, PhpArray):
            merged.update(own_defaults.entries())

        methods: list[str] | None = [method or "ANY"]
        template = parent_template
        offset = spec.offset
        literal: PhpValue | None = None
        if kind == "method":
            literal = options.get("verb")
            verbs = _verbs(literal)
            if not verbs:
                continue
            # The verb applies to every form of the parent: `/user[/:id]`
            # with a `delete` child is `DELETE /user` and `DELETE /user/:id`.
            methods = verbs
            offset = literal.offset if literal is not None else offset
        elif kind in ("hostname", "scheme"):
            methods = None  # matches the host/scheme, not a path
        elif kind == "regex":
            literal = options.get("spec")
            if not isinstance(literal, PhpString) or not literal.value.startswith("/"):
                continue
            template = prefix + _REGEX_SPEC_PARAM.sub(r":\1", literal.value)
            offset = literal.offset
        elif kind in _PATH_KINDS:
            literal = options.get("route")
            if not isinstance(literal, PhpString) or not literal.value.startswith(("/", "[")):
                continue
            template = prefix + _segment_text(literal.value)
            offset = literal.offset
        else:
            continue  # Part, Wildcard, Query, console `simple`, custom types
        if ctx.consumed is not None and literal is not None:
            ctx.consumed.add(literal.offset)

        if terminates and methods is not None:
            for form in expand_optional(template):
                path = normalize_path(form)
                for verb in methods:
                    out.append(LaminasRoute(path, verb, offset, full_name, template, merged))
        child_method = methods[0] if kind == "method" and methods and len(methods) == 1 else method
        if ctx.index is not None:
            ctx.index.setdefault(full_name, RouteNode(minimal_form(template), merged, child_method, template))
        if isinstance(children, PhpArray):
            _walk(children, minimal_form(template), template, full_name, merged, child_method, depth + 1, ctx)


def fallback_route_literals(
    content: str, tokens: TokenList, consumed: set[int], pattern: re.Pattern[str]
) -> list[tuple[str, int]]:
    """Flat `'route' => '/path'` matches (``pattern`` group 1 is the path) that
    the structural walk didn't consume: routes built in ways it can't follow,
    or past the tokenizer's cap (``tokens.truncated``). A literal inside a
    tokenized `child_routes` array is only a fragment of a path and is left
    out; past a truncation the arrays are unknown, so every literal there is
    kept. Returns ``(path, match offset)`` pairs."""
    spans = keyed_array_spans(tokens, "child_routes")
    starts = [start for start, _ in spans]
    found: list[tuple[str, int]] = []
    for match in pattern.finditer(content):
        literal = match.start(1) - 1
        if literal in consumed:
            continue
        at = bisect.bisect_right(starts, literal) - 1
        if at >= 0 and spans[at][0] <= literal < spans[at][1]:
            continue
        found.append((match.group(1), match.start()))
    return found


def _verbs(value: PhpValue | None) -> list[str]:
    if not isinstance(value, PhpString):
        return []
    verbs = [part.strip().upper() for part in value.value.split(",")]
    return [verb for verb in verbs if verb in _HTTP_METHODS]


# ---------------------------------------------------------------------------
# Mezzio
# ---------------------------------------------------------------------------


@dataclass
class MezzioRoute:
    path: str
    method: str
    offset: int


def _strip_fastroute_regex(path: str) -> str:
    """`/a/{id:\\d{1,3}}[/{slug}]` → `/a/{id}[/{slug}]`."""
    out: list[str] = []
    i = 0
    n = len(path)
    while i < n:
        ch = path[i]
        if ch != "{":
            out.append(ch)
            i += 1
            continue
        j = i + 1
        while j < n and path[j] not in ":}":
            j += 1
        out.append("{" + path[i + 1 : j] + "}")
        if j < n and path[j] == ":":
            depth = 1
            j += 1
            while j < n and depth:
                if path[j] == "{":
                    depth += 1
                elif path[j] == "}":
                    depth -= 1
                j += 1
            i = j
        else:
            i = j + 1
    return "".join(out)


def mezzio_routes(tokens: list[Token]) -> list[MezzioRoute]:
    """`$app->get('/path', ...)` and friends, and `$app->route('/path', $mw, [methods])`."""
    out: list[MezzioRoute] = []
    n = len(tokens)
    i = -1
    while i + 1 < n - 4:
        i += 1
        if len(out) >= MAX_ROUTES_PER_FILE:
            break
        if not (
            tokens[i].kind == WORD
            and tokens[i].text == "$app"
            and tokens[i + 1].kind == OP
            and tokens[i + 1].text == "-"
            and tokens[i + 2].kind == OP
            and tokens[i + 2].text == ">"
            and tokens[i + 3].kind == WORD
            and tokens[i + 4].kind == LPAREN
        ):
            continue
        verb = tokens[i + 3].text.lower()
        if verb != "route" and verb not in _MEZZIO_VERBS:
            continue
        args, end = parse_call_args(tokens, i + 4)
        # Continue after the call: routes aren't registered inside another
        # route's arguments, and re-parsing nested calls would be quadratic.
        i = max(end, i + 5) - 1
        if not args or not isinstance(args[0], PhpString) or not args[0].value.startswith("/"):
            continue
        if verb == "route":
            methods = _route_methods(args[2] if len(args) > 2 else None)
        else:
            methods = [_MEZZIO_VERBS[verb]]
        template = _strip_fastroute_regex(args[0].value)
        for form in expand_optional(template):
            path = normalize_path(form)
            for method in methods:
                out.append(MezzioRoute(path, method, args[0].offset))
    return out


def _route_methods(value: PhpValue | None) -> list[str]:
    if isinstance(value, PhpArray):
        methods = [
            v.value.strip().upper() for _, v in value.items if isinstance(v, PhpString)
        ]
        methods = [m for m in methods if m in _HTTP_METHODS]
        return methods or ["ANY"]
    return ["ANY"]  # null, Route::HTTP_METHOD_ANY, a variable


__all__ = [
    "LaminasRoute",
    "fallback_route_literals",
    "MezzioRoute",
    "RouteNode",
    "route_trees",
    "expand_optional",
    "mezzio_routes",
    "minimal_form",
    "normalize_path",
    "route_type",
    "router_routes",
]
