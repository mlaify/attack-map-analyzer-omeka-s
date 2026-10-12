"""Omeka S ACL rules and per-route access decisions (attack-map-analyzer-omeka-s#2).

Omeka decides who reaches a controller with its ACL (`Omeka\\Permissions\\Acl`,
a Laminas ACL). Controllers are ACL resources, the action is the privilege,
and `MvcListeners::authorizeUserAgainstController` checks
`userIsAllowed($controller, $action)` on every dispatch. The anonymous visitor
has no role, so a rule for the `null` role ("all roles") reaches them.

This module reads `$acl->allow(<roles>, <resources>, <privileges>[, <assertion>])`
and `->deny(...)` calls from a module's `Module.php` (`onBootstrap`,
`attachListeners` or helpers they call) and from `*AclFactory.php` (Omeka core's
rules), and answers, per controller and action:

- **anonymous**: an unconditional allow for `null` (or `'guest'`, the Guest
  module's self-registration role, treated as public) covers the controller
  and action.
- **required**: an anonymous deny covers it, or no anonymous rule covers it at
  all. Omeka denies by default, so a controller only some roles are allowed
  (or no rule names) needs a login. This is only concluded when every
  anonymous rule in the repo was resolved: an `allow(null, $controllers)`
  with a variable resource makes every unmatched controller unknown.
- **unknown**: a conditional rule (an assertion argument), a privilege list
  that doesn't settle the action, or an unresolved role.

Zero-argument `allow()` (Omeka grants everything during installation) is
ignored.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .phparray import (
    LPAREN,
    OP,
    WORD,
    NameContext,
    PhpArray,
    PhpExpr,
    PhpString,
    PhpValue,
    Token,
    class_name,
    parse_call_args,
)

ANONYMOUS_ROLES = frozenset({"guest"})
ALL = "*"
MAX_RULES_PER_FILE = 2_000


@dataclass
class AclRule:
    allow: bool
    file: str
    line: int
    # A rule for the anonymous visitor: role `null` or `'guest'`.
    anonymous: bool
    # The role couldn't be resolved (a variable): it might be anonymous.
    role_unresolved: bool
    roles: list[str]
    # Resolved resource names; `ALL` for a `null`/missing resource argument.
    resources: list[str]
    resources_unresolved: bool
    # None = every privilege (action).
    privileges: list[str] | None
    privileges_unresolved: bool
    conditional: bool

    @property
    def maybe_anonymous(self) -> bool:
        return self.anonymous or self.role_unresolved

    def covers(self, resource: str) -> bool:
        return ALL in self.resources or resource in self.resources


@dataclass
class Decision:
    auth: str  # "anonymous" | "required" | "unknown"
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


def _role_names(value: PhpValue | None) -> tuple[bool, bool, list[str]]:
    """(anonymous, unresolved, named roles) of a role argument."""
    if value is None:
        return True, False, ["null"]  # no role argument: all roles
    values = [v for _, v in value.items] if isinstance(value, PhpArray) else [value]
    anonymous = unresolved = False
    roles: list[str] = []
    for item in values:
        if isinstance(item, PhpExpr) and item.text.strip().lower() == "null":
            anonymous = True
            roles.append("null")
        elif isinstance(item, PhpString):
            name = item.value.strip()
            if name.lower() in ANONYMOUS_ROLES:
                anonymous = True
            roles.append(name)
        elif isinstance(item, PhpExpr) and "::ROLE_" in item.text and " " not in item.text.strip():
            # `Acl::ROLE_EDITOR` → `editor`
            roles.append(item.text.strip().rsplit("::ROLE_", 1)[1].lower())
        else:
            unresolved = True
    return anonymous, unresolved, roles


def _resource_names(value: PhpValue | None, names: NameContext) -> tuple[list[str], bool]:
    if value is None or (isinstance(value, PhpExpr) and value.text.strip().lower() == "null"):
        return [ALL], False
    values = [v for _, v in value.items] if isinstance(value, PhpArray) else [value]
    resources: list[str] = []
    unresolved = False
    for item in values:
        if isinstance(item, PhpString) and item.value.strip():
            resources.append(item.value.strip().lstrip("\\"))
            continue
        resolved = class_name(item, names)
        if resolved:
            resources.append(resolved)
        else:
            unresolved = True
    return resources, unresolved


def _privileges(value: PhpValue | None) -> tuple[list[str] | None, bool]:
    if value is None or (isinstance(value, PhpExpr) and value.text.strip().lower() == "null"):
        return None, False
    values = [v for _, v in value.items] if isinstance(value, PhpArray) else [value]
    privileges = [v.value for v in values if isinstance(v, PhpString)]
    return privileges, len(privileges) != len(values)


def acl_rules(tokens: list[Token], names: NameContext, file: str, line_of: Callable[[int], int]) -> list[AclRule]:
    """Every `->allow(...)` / `->deny(...)` call with at least one argument.

    ``line_of`` maps a source offset to its 1-based line."""
    rules: list[AclRule] = []
    n = len(tokens)
    i = 0
    while i < n - 3 and len(rules) < MAX_RULES_PER_FILE:
        if not (
            tokens[i].kind == OP
            and tokens[i].text == "-"
            and tokens[i + 1].kind == OP
            and tokens[i + 1].text == ">"
            and tokens[i + 2].kind == WORD
            and tokens[i + 2].text in ("allow", "deny")
            and tokens[i + 3].kind == LPAREN
        ):
            i += 1
            continue
        verb = tokens[i + 2].text
        offset = tokens[i + 2].offset
        args, end = parse_call_args(tokens, i + 3)
        i = max(end, i + 4)
        if not args:
            continue  # `$acl->allow()`: Omeka's installation-time grant-all
        anonymous, role_unresolved, roles = _role_names(args[0])
        resources, resources_unresolved = _resource_names(args[1] if len(args) > 1 else None, names)
        privileges, privileges_unresolved = _privileges(args[2] if len(args) > 2 else None)
        conditional = len(args) > 3 and not (isinstance(args[3], PhpExpr) and args[3].text.strip().lower() == "null")
        rules.append(
            AclRule(
                allow=verb == "allow",
                file=file,
                line=line_of(offset),
                anonymous=anonymous,
                role_unresolved=role_unresolved,
                roles=roles,
                resources=resources,
                resources_unresolved=resources_unresolved,
                privileges=privileges,
                privileges_unresolved=privileges_unresolved,
                conditional=conditional,
            )
        )
    return rules


def _describe(rule: AclRule, resource: str) -> str:
    roles = [role if role == "null" else f"'{role}'" for role in rule.roles]
    if rule.role_unresolved:
        roles.append("<unresolved>")
    role = roles[0] if len(roles) == 1 else "[" + ", ".join(roles) + "]"
    args = [role, f"'{resource}'"]
    if rule.privileges is not None:
        args.append("[" + ", ".join(f"'{p}'" for p in rule.privileges) + "]")
    if rule.conditional:
        args.append("<assertion>")
    verb = "allow" if rule.allow else "deny"
    return f"$acl->{verb}({', '.join(args)}) at {rule.file}:{rule.line}"


class Acl:
    """The repo's ACL rules, in source order (a later rule overrides an
    earlier one, as in Laminas ACL)."""

    def __init__(self, rules: list[AclRule]) -> None:
        self.rules = rules
        # An anonymous (or unresolved-role) rule whose resources we couldn't
        # resolve might cover any controller: never conclude default-deny.
        self.blocked = any(r.maybe_anonymous and r.resources_unresolved for r in rules)

    def decide(self, controller: str, action: str | None) -> Decision:
        """Access to ``controller``/``action`` (None = any action, from `:action`)."""
        anon = [r for r in self.rules if r.maybe_anonymous and r.covers(controller)]
        if anon:
            return self._decide_anonymous(anon, controller, action)
        if self.blocked:
            return Decision("unknown")
        roles = sorted(
            {
                role
                for r in self.rules
                if r.allow and not r.maybe_anonymous and r.covers(controller)
                for role in r.roles
            }
        )
        guards = [f"omeka_acl:requires_role({role})" for role in roles] or ["omeka_acl:default_deny"]
        if roles:
            basis = f"requires_role: {', '.join(roles)}"
        else:
            basis = "requires_role: only roles allowed every resource, site_admin and global_admin in stock Omeka"
        return Decision(
            "required",
            guards,
            f"Omeka ACL: no rule for the anonymous role covers {controller}; Omeka denies by default and checks "
            f"the role on every dispatch ({basis})",
        )

    @staticmethod
    def _decide_anonymous(anon: list[AclRule], controller: str, action: str | None) -> Decision:
        if action is not None:
            specific = [r for r in anon if r.privileges is not None and action in r.privileges]
            general = [r for r in anon if r.privileges is None]
            # Laminas: a privilege-specific rule beats an all-privileges one;
            # among equals the last rule wins.
            deciding = specific[-1] if specific else (general[-1] if general else None)
            if deciding is None:
                if any(r.privileges_unresolved for r in anon):
                    return Decision("unknown")
                # Only rules for other actions: this action falls through to
                # Omeka's default deny.
                return Decision(
                    "required",
                    ["omeka_acl:default_deny"],
                    f"Omeka ACL: anonymous rules for {controller} don't include action '{action}'; "
                    "Omeka denies by default",
                )
        else:
            # Any action (`:action` in the path): only an all-privileges rule
            # with no anonymous privilege-specific deny settles it.
            general = [r for r in anon if r.privileges is None]
            if not general or any(not r.allow and r.privileges is not None for r in anon):
                return Decision("unknown")
            deciding = general[-1]
        if deciding.role_unresolved and not deciding.anonymous or deciding.conditional:
            return Decision("unknown")
        if deciding.allow:
            return Decision("anonymous", [], _describe(deciding, controller))
        return Decision("required", ["omeka_acl:deny_anonymous"], _describe(deciding, controller))


def combine(decisions: list[Decision], namespace: str) -> Decision:
    """One decision for a `:controller` route, which reaches every controller
    registered under ``namespace``: anonymous or required only if all agree."""
    if not decisions:
        return Decision("unknown")
    kinds = {d.auth for d in decisions}
    if len(kinds) != 1 or kinds == {"unknown"}:
        return Decision("unknown")
    auth = kinds.pop()
    evidence = sorted({d.evidence or "" for d in decisions})
    shown = "; ".join(evidence[:3]) + (f"; +{len(evidence) - 3} more" if len(evidence) > 3 else "")
    summary = f"all {len(decisions)} controllers under {namespace}: {shown}"
    guards = sorted({g for d in decisions for g in d.guards})
    return Decision(auth, guards, summary)
