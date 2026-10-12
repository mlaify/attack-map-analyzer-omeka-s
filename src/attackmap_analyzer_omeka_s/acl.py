"""Omeka S ACL rules and per-route access decisions (attack-map-analyzer-omeka-s#2).

Omeka decides who reaches a controller with its ACL (`Omeka\\Permissions\\Acl`,
a Laminas ACL). Controllers are ACL resources, the action is the privilege,
and `MvcListeners::authorizeUserAgainstController` checks
`userIsAllowed($controller, $action)` on every dispatch. The anonymous visitor
has no role, so only rules for the `null` role ("all roles") reach them.

This module reads `$acl->allow(<roles>, <resources>, <privileges>[, <assertion>])`
and `->deny(...)` calls from a module's `Module.php` (`onBootstrap`,
`attachListeners` or helpers they call) and from `*AclFactory.php` (Omeka core's
rules), and answers per controller and action with Laminas' lookup order
(`Laminas\\Permissions\\Acl\\Acl::isAllowed`):

1. For each resource level, the specific controller first and then the
   all-resources level (`null`; Omeka's controllers have no parent resources):
   the role's own rules (the privilege, then all privileges), then the
   all-roles rules (the privilege, then all privileges). An all-roles,
   all-privileges *deny* on the specific controller doesn't stop the lookup;
   it continues to the all-resources level, as in Laminas.
2. For each (resource, role, privilege) slot the last rule written wins.
3. No rule: denied (Omeka's default).

Two public principals are checked: the anonymous visitor (all-roles rules
only) and `'guest'` (the Guest module's self-registration role, its own rules
then all-roles rules; treated as public). Role inheritance isn't modelled:
Omeka core and the Guest module add their roles without parents.

- **anonymous**: either principal is allowed.
- **required**: both are denied (by a rule or by default). Guards name the
  roles that are allowed (`omeka_acl:requires_role(<role>)`) or
  `omeka_acl:default_deny`.
- **unknown**: a conditional rule (an assertion) decides, a `:action` route's
  actions disagree, or a rule's role or resource couldn't be resolved (an
  unresolved anonymous resource, or a zero-argument `allow()` outside
  `*AclFactory.php`, turns every deny into unknown).

Zero-argument `allow()` in `*AclFactory.php` is Omeka's grant-all while it is
not installed or needs a migration. The installer and migration controllers
(``INSTALL_CONTROLLERS``) serve exactly then, so they are never reported as
`required` (`unknown` with a note instead).

Decisions are memoised per (controller, action), rules are indexed by
(principal, resource, privilege), and an ``Acl`` makes at most
``MAX_DECISIONS`` fresh decisions; past that budget it answers `unknown`.
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
MAX_DECISIONS = 50_000
MAX_PRIVILEGES_PER_DECISION = 256
_OTHER_ACTION = "\0any-other-action"
# Controllers that run while Omeka isn't installed or needs a migration, when
# AclFactory grants everything (`$acl->allow()`) and MvcListeners redirects there.
INSTALL_CONTROLLERS = frozenset({"Omeka\\Controller\\Install", "Omeka\\Controller\\Migrate"})


@dataclass
class AclRule:
    allow: bool
    file: str
    line: int
    # Role names as written; `null` for the all-roles role. `Acl::ROLE_*`
    # constants are resolved to their values (`Acl::ROLE_GUEST` → `guest`).
    roles: list[str]
    # The role argument couldn't be resolved (a variable): it might be anonymous.
    role_unresolved: bool
    # Resolved resource names; `ALL` for a `null` resource argument.
    resources: list[str]
    resources_unresolved: bool
    # None = every privilege (action).
    privileges: list[str] | None
    privileges_unresolved: bool
    conditional: bool
    # `$acl->allow()` with no arguments (grant-all).
    grant_all: bool = False

    @property
    def anonymous(self) -> bool:
        return any(role == "null" or role.lower() in ANONYMOUS_ROLES for role in self.roles)

    @property
    def maybe_anonymous(self) -> bool:
        return self.anonymous or self.role_unresolved


@dataclass
class Decision:
    auth: str  # "anonymous" | "required" | "unknown"
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


def _role_names(value: PhpValue | None) -> tuple[bool, list[str]]:
    """(unresolved, role names) of a role argument; `null` is the all-roles role."""
    if value is None:
        return False, ["null"]
    values = [v for _, v in value.items] if isinstance(value, PhpArray) else [value]
    unresolved = False
    roles: list[str] = []
    for item in values:
        text = item.text.strip() if isinstance(item, PhpExpr) else ""
        if isinstance(item, PhpExpr) and text.lower() == "null":
            roles.append("null")
        elif isinstance(item, PhpString):
            roles.append(item.value.strip())
        elif isinstance(item, PhpExpr) and "::ROLE_" in text and " " not in text:
            # `Acl::ROLE_SITE_ADMIN` → `site_admin`, `Acl::ROLE_GUEST` → `guest`:
            # Omeka's constants are the lower-cased suffix.
            roles.append(text.rsplit("::ROLE_", 1)[1].lower())
        else:
            unresolved = True
    return unresolved, roles


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
    """Every `->allow(...)` / `->deny(...)` call. ``line_of`` maps a source
    offset to its 1-based line."""
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
            rules.append(
                AclRule(
                    allow=verb == "allow",
                    file=file,
                    line=line_of(offset),
                    roles=["null"],
                    role_unresolved=False,
                    resources=[ALL],
                    resources_unresolved=False,
                    privileges=None,
                    privileges_unresolved=False,
                    conditional=False,
                    grant_all=True,
                )
            )
            continue
        role_unresolved, roles = _role_names(args[0])
        resources, resources_unresolved = _resource_names(args[1] if len(args) > 1 else None, names)
        privileges, privileges_unresolved = _privileges(args[2] if len(args) > 2 else None)
        conditional = len(args) > 3 and not (isinstance(args[3], PhpExpr) and args[3].text.strip().lower() == "null")
        rules.append(
            AclRule(
                allow=verb == "allow",
                file=file,
                line=line_of(offset),
                roles=roles,
                role_unresolved=role_unresolved,
                resources=resources,
                resources_unresolved=resources_unresolved,
                privileges=privileges,
                privileges_unresolved=privileges_unresolved,
                conditional=conditional,
            )
        )
    return rules


def _describe(rule: AclRule, resource: str) -> str:
    """The rule as written, narrowed to the resource that matched."""
    roles = [role if role == "null" else f"'{role}'" for role in rule.roles]
    if rule.role_unresolved:
        roles.append("<unresolved>")
    role = roles[0] if len(roles) == 1 else "[" + ", ".join(roles) + "]"
    shown = "null" if resource == ALL else f"'{resource}'"
    if len(rule.resources) > 1:
        shown += f" (1 of {len(rule.resources)} resources)"
    args = [role, shown]
    if rule.privileges is not None:
        args.append("[" + ", ".join(f"'{p}'" for p in rule.privileges) + "]")
    if rule.conditional:
        args.append("<assertion>")
    verb = "allow" if rule.allow else "deny"
    return f"$acl->{verb}({', '.join(args)}) at {rule.file}:{rule.line}"


# A lookup result: True/False (allowed/denied by a rule), None (a conditional
# rule decides: unknown), or "default" (no rule: Omeka's default deny).


class Acl:
    """The repo's ACL rules, indexed by principal and (resource, privilege)."""

    def __init__(
        self,
        rules: list[AclRule],
        registered: set[str] | None = None,
        aliases: set[str] | None = None,
    ) -> None:
        self.rules = rules
        # None: registrations unknown (unit use); otherwise the ACL resources
        # Omeka adds (controllers.invokables / factories keys).
        self.registered = registered
        self.aliases = aliases or set()
        # Something we couldn't resolve might allow the visitor anything.
        self.blocked = any(
            (r.maybe_anonymous and r.resources_unresolved)
            or (r.grant_all and not r.file.endswith("AclFactory.php"))
            for r in rules
        )
        # Per principal: resource → the rules naming it, in program order
        # (each rule once per resource it names, never expanded per
        # privilege), so the index stays linear in the source.
        self.all_roles: dict[str, list[tuple[int, AclRule]]] = {}
        self.guest: dict[str, list[tuple[int, AclRule]]] = {}
        self.unresolved_role_resources: set[str] = set()
        self.allowed_roles: dict[str, set[str]] = {}
        self.unresolved_privileges: set[str] = set()
        self._privilege_sets: dict[int, frozenset[str]] = {}
        for seq, rule in enumerate(rules):
            if rule.grant_all:
                continue  # install-time grant (AclFactory) or a blocker (above)
            if rule.privileges is not None:
                self._privilege_sets[id(rule)] = frozenset(rule.privileges)
            tables = []
            for role in rule.roles:
                if role == "null":
                    tables.append(self.all_roles)
                elif role.lower() in ANONYMOUS_ROLES:
                    tables.append(self.guest)
            for resource in rule.resources:
                if rule.privileges_unresolved:
                    self.unresolved_privileges.add(resource)
                if rule.role_unresolved:
                    self.unresolved_role_resources.add(resource)
                for table in tables:
                    table.setdefault(resource, []).append((seq, rule))
                if rule.allow:
                    for role in rule.roles:
                        if role != "null" and role.lower() not in ANONYMOUS_ROLES:
                            self.allowed_roles.setdefault(resource, set()).add(role)
        self._slot_memo: dict[tuple[int, str, str | None], tuple[int, AclRule] | None] = {}
        self._memo: dict[tuple[str, str | None], Decision] = {}
        self.fresh_decisions = 0

    # -- Laminas lookup -------------------------------------------------

    def _written(self, table: dict[str, list[tuple[int, AclRule]]], resource: str, privilege: str | None):
        """The last rule written to the (resource, privilege) slot directly:
        ``(seq, rule)`` or None. ``privilege`` None is the all-privileges slot."""
        key = (id(table), resource, privilege)
        if key in self._slot_memo:
            return self._slot_memo[key]
        found = None
        for seq, rule in reversed(table.get(resource, ())):
            if privilege is None:
                if rule.privileges is None:
                    found = (seq, rule)
                    break
            elif rule.privileges is not None and privilege in self._privilege_sets[id(rule)]:
                found = (seq, rule)
                break
        self._slot_memo[key] = found
        return found

    def _slot(self, table: dict[str, list[tuple[int, AclRule]]], level: str, privilege: str | None):
        """The rule in a slot. Laminas' setRule applies a `null`-resource rule
        to every resource registered so far, overwriting their slots; Omeka
        registers every controller before adding rules, so at a specific
        level the later of the specific rule and the `null`-resource rule wins."""
        own = self._written(table, level, privilege)
        if level == ALL:
            return own[1] if own else None
        spread = self._written(table, ALL, privilege)
        if own is None or (spread is not None and spread[0] > own[0]):
            return spread[1] if spread else None
        return own[1]

    def _lookup(self, tables: list[tuple[str, dict[str, list[tuple[int, AclRule]]]]], resource: str, privilege: str):
        """(result, rule, resource level) for one principal; see the module docstring."""
        for level in (resource, ALL) if resource != ALL else (ALL,):
            for kind, table in tables:
                rule = self._slot(table, level, privilege)
                if rule is not None:
                    return (None if rule.conditional else rule.allow), rule, level
                rule = self._slot(table, level, None)
                if rule is not None:
                    if rule.conditional:
                        return None, rule, level
                    if kind == "role" or rule.allow or level == ALL:
                        return rule.allow, rule, level
                    # All-roles, all-privileges deny on the specific
                    # resource: Laminas continues to the parent level.
        return "default", None, None

    def _privileges_for(self, resource: str) -> set[str] | None:
        """Privileges public rules name for ``resource`` or all resources;
        None past ``MAX_PRIVILEGES_PER_DECISION``."""
        found: set[str] = set()
        for table in (self.all_roles, self.guest):
            for level in (resource, ALL):
                for _seq, rule in table.get(level, ()):
                    if rule.privileges is not None:
                        found.update(rule.privileges)
                        if len(found) > MAX_PRIVILEGES_PER_DECISION:
                            return None
        return found

    def _public(self, resource: str, privilege: str):
        """Is the visitor or a guest allowed? Returns (result, rule, level)."""
        visitor = self._lookup([("all", self.all_roles)], resource, privilege)
        if visitor[0] is True:
            return visitor
        guest = self._lookup([("role", self.guest), ("all", self.all_roles)], resource, privilege)
        if guest[0] is True:
            return guest
        if visitor[0] is None or guest[0] is None:
            return None, visitor[1] or guest[1], visitor[2] or guest[2]
        # Both denied: report the visitor's reason.
        return visitor

    # -- decisions --------------------------------------------------------

    def decide(self, controller: str, action: str | None) -> Decision:
        """Access to ``controller``/``action`` (None = any action, from `:action`)."""
        key = (controller, action)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        if self.fresh_decisions >= MAX_DECISIONS:
            return Decision("unknown")  # per-repo budget spent
        self.fresh_decisions += 1
        decision = self._decide(controller, action)
        if decision.auth == "required" and controller in INSTALL_CONTROLLERS:
            decision = Decision(
                "unknown",
                [],
                f"{controller} serves while Omeka isn't installed or needs a migration, when AclFactory grants "
                "every role everything ($acl->allow()) and MvcListeners redirects there; after that: "
                + (decision.evidence or ""),
            )
        self._memo[key] = decision
        return decision

    def _decide(self, controller: str, action: str | None) -> Decision:
        if self.registered is not None and controller not in self.registered:
            if controller in self.aliases:
                return Decision(
                    "anonymous",
                    [],
                    f"'{controller}' is a controller alias, not an ACL resource (Omeka adds only "
                    "controllers.invokables/factories keys), and authorizeUserAgainstController allows a "
                    "controller that isn't a resource",
                )
            return Decision("unknown")  # registered somewhere we didn't see, or not at all
        if controller in self.unresolved_role_resources or ALL in self.unresolved_role_resources:
            return Decision("unknown")
        # A privilege list we couldn't read (a variable or constant) might
        # name any action, fixed or not.
        if controller in self.unresolved_privileges or ALL in self.unresolved_privileges:
            return Decision("unknown")
        if action is not None:
            result, rule, level = self._public(controller, action)
            return self._from_result(controller, result, rule, level, action)
        privileges = self._privileges_for(controller)
        if privileges is None:
            return Decision("unknown")
        outcomes = [self._public(controller, p) for p in sorted(privileges)]
        other = self._public(controller, _OTHER_ACTION)
        results = {o[0] for o in outcomes} | {other[0]}
        if results == {True}:
            return self._from_result(controller, True, other[1], other[2], None)
        if results <= {False, "default"}:
            return self._from_result(controller, other[0], other[1], other[2], None)
        return Decision("unknown")  # some actions public, some not, or conditional

    def _from_result(self, controller: str, result, rule: AclRule | None, level: str | None, action: str | None):
        if result is True and rule is not None and level is not None:
            return Decision("anonymous", [], _describe(rule, level))
        if result is None:
            return Decision("unknown")
        if self.blocked:
            return Decision("unknown")
        roles = sorted(self.allowed_roles.get(controller, set()) | self.allowed_roles.get(ALL, set()))
        if result is False and rule is not None and level is not None:
            guards = ["omeka_acl:deny_anonymous", *(f"omeka_acl:requires_role({r})" for r in roles)]
            return Decision("required", guards, _describe(rule, level))
        guards = [f"omeka_acl:requires_role({role})" for role in roles] or ["omeka_acl:default_deny"]
        if roles:
            basis = f"requires_role: {', '.join(roles)}"
        else:
            basis = "requires_role: only roles allowed every resource, site_admin and global_admin in stock Omeka"
        what = f"{controller} action '{action}'" if action is not None else controller
        return Decision(
            "required",
            guards,
            f"Omeka ACL: no rule allows the anonymous role {what}; Omeka denies by default and checks "
            f"the role on every dispatch ({basis})",
        )


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
