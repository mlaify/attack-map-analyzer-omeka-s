"""Omeka S ACL rules, API key auth, joined routes and a cheap detect()
(attack-map-analyzer-omeka-s#2)."""

from __future__ import annotations

import pathlib
import random
import time
from pathlib import Path

import pytest

from attackmap_analyzer_omeka_s import OmekaSAnalyzer
from attackmap_analyzer_omeka_s import analyzer as analyzer_module
from attackmap_analyzer_omeka_s.acl import Acl, acl_rules
from attackmap_analyzer_omeka_s.phparray import NameContext, tokenize
from attackmap_analyzer_omeka_s.routes import expand_optional, mezzio_routes, route_trees, router_routes

FIXTURES = Path(__file__).parent / "fixtures"
MODULE = FIXTURES / "omeka_acl_module"
CORE = FIXTURES / "omeka_core_api"


def _routes(repo: Path) -> dict[tuple[str, str], object]:
    return {(r.path, r.method): r for r in OmekaSAnalyzer().analyze(repo).routes}


# ---------------------------------------------------------------------------
# ACL decisions
# ---------------------------------------------------------------------------


def test_acl_allow_null_marks_routes_anonymous() -> None:
    routes = _routes(MODULE)
    # `$acl->allow(null, ['Gallery\Controller\Site\Index'])`, reached through
    # the `site` child route's __NAMESPACE__ + 'Index'.
    for key in [("/s/:site-slug/gallery", "ANY"), ("/s/:site-slug/gallery/:action", "ANY")]:
        route = routes[key]
        assert route.auth == "anonymous"
        assert route.guards == []
        assert route.guard_evidence == "$acl->allow(null, 'Gallery\\Controller\\Site\\Index') at Module.php:23"


def test_acl_privilege_list_settles_the_route_action() -> None:
    routes = _routes(MODULE)
    # allow(null, [FeedController::class], ['index']), class resolved via `use`.
    assert routes[("/gallery-feed", "ANY")].auth == "anonymous"
    # Action `full` isn't in the anonymous privileges: Omeka's default deny.
    full = routes[("/gallery-feed/full", "ANY")]
    assert (full.auth, full.guards) == ("required", ["omeka_acl:default_deny"])


def test_controller_allowed_only_to_a_role_requires_login() -> None:
    upload = _routes(MODULE)[("/gallery-upload", "POST")]
    assert (upload.auth, upload.guards) == ("required", ["omeka_acl:requires_role(editor)"])
    assert "requires_role: editor" in upload.guard_evidence


def test_controller_with_no_rule_is_default_deny() -> None:
    private = _routes(MODULE)[("/gallery-private", "ANY")]
    assert (private.auth, private.guards) == ("required", ["omeka_acl:default_deny"])


def test_guest_role_counts_as_anonymous() -> None:
    assert _routes(MODULE)[("/gallery-guest", "ANY")].auth == "anonymous"


def test_conditional_allow_is_unknown() -> None:
    vote = _routes(MODULE)[("/gallery-vote", "ANY")]
    assert (vote.auth, vote.guards, vote.guard_evidence) == ("unknown", [], None)


def test_anonymous_deny_beats_allow_for_that_action() -> None:
    routes = _routes(MODULE)
    closed = routes[("/gallery-closed", "ANY")]
    assert (closed.auth, closed.guards) == ("required", ["omeka_acl:deny_anonymous"])
    # Any action (`:action`): the allow covers some, the deny others.
    assert routes[("/gallery-closed/:action", "ANY")].auth == "unknown"


def test_admin_routes_require_login_even_when_the_acl_allows_null() -> None:
    routes = _routes(MODULE)
    # The module's `admin` stub joins Omeka core's `/admin` and inherits __ADMIN__.
    for key in [("/admin/gallery", "ANY"), ("/admin/gallery/:action", "ANY")]:
        # Admin\IndexController has no rule: login, then the ACL's default deny.
        assert (routes[key].auth, routes[key].guards) == ("required", ["omeka:admin_login", "omeka_acl:default_deny"])
        assert "__ADMIN__" in routes[key].guard_evidence
    core = _routes(CORE)
    admin = core[("/admin/:controller", "ANY")]
    # Every Admin controller: Item for researcher (some actions), all for global_admin.
    assert admin.auth == "required"
    assert admin.guards[0] == "omeka:admin_login"
    assert "omeka_acl:requires_role(global_admin)" in admin.guards


def test_dynamic_controller_route_is_anonymous_only_if_every_controller_is() -> None:
    core = _routes(CORE)
    route = core[("/s/:site-slug/:controller", "ANY")]
    assert route.auth == "anonymous"
    assert route.guard_evidence.startswith("all 2 controllers under Omeka\\Controller\\Site:")


def test_install_route_is_not_required() -> None:
    install = _routes(CORE)[("/install", "ANY")]
    # Only `allow('global_admin')` covers it once installed, but AclFactory's
    # `$acl->allow()` grants everyone everything before installation, when
    # MvcListeners redirects every request here.
    assert (install.auth, install.guards) == ("unknown", [])
    assert "isn't installed" in install.guard_evidence


def test_unresolved_anonymous_allow_blocks_default_deny(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"type": "omeka-s-module"}')
    (tmp_path / "Module.php").write_text(
        "<?php\nnamespace M;\nclass Module {\n  public function onBootstrap($e) {\n"
        "    $acl->allow(null, $this->publicControllers());\n  }\n}\n"
    )
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "module.config.php").write_text(
        "<?php\nnamespace M;\nreturn ['controllers' => ['invokables' => [Controller\\IndexController::class => 'X']],\n"
        "'router' => ['routes' => ['m' => ['type' => 'Literal', "
        "'options' => ['route' => '/m', 'defaults' => ['controller' => Controller\\IndexController::class]]]]]];\n"
    )
    route = OmekaSAnalyzer().analyze(tmp_path).routes[0]
    assert (route.path, route.auth) == ("/m", "unknown")


def test_no_decision_outside_an_omeka_repo(tmp_path: Path) -> None:
    # Run on a plain Laminas app (opt-in `-m omeka-s`): no default-deny claims.
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "routes.php").write_text(
        "<?php\nreturn ['router' => ['routes' => ['m' => ['type' => 'Literal', "
        "'options' => ['route' => '/m', 'defaults' => ['controller' => 'App\\\\Index']]]]]];\n"
    )
    route = OmekaSAnalyzer().analyze(tmp_path).routes[0]
    assert (route.path, route.auth) == ("/m", "unknown")


def test_zero_argument_allow_outside_acl_factory_blocks_default_deny() -> None:
    source = "<?php $acl->allow(); $acl->allow(null, 'C'); $x->allowed('y');"
    rules = acl_rules(tokenize(source), NameContext(), "Module.php", lambda offset: 1)
    assert [r.grant_all for r in rules] == [True, False]
    acl = Acl(rules)
    assert acl.decide("C", "index").auth == "anonymous"
    # A grant-all in a module might reach anything: no default-deny claims.
    assert acl.decide("D", "index").auth == "unknown"


def test_zero_argument_allow_in_acl_factory_is_the_install_grant() -> None:
    source = "<?php $acl->allow(); $acl->allow('editor', 'D');"
    acl = Acl(acl_rules(tokenize(source), NameContext(), "src/Service/AclFactory.php", lambda offset: 1))
    assert acl.decide("D", "index").auth == "required"


def test_role_constants_and_arrays() -> None:
    source = (
        "<?php $acl->allow([Acl::ROLE_AUTHOR, 'reviewer'], ['A', 'B'], 'edit');"
        "$acl->allow([null, 'editor'], 'C');"
    )
    rules = acl_rules(tokenize(source), NameContext(), "f.php", lambda offset: 1)
    assert rules[0].roles == ["author", "reviewer"] and not rules[0].anonymous
    assert rules[1].anonymous
    acl = Acl(rules)
    assert acl.decide("A", "edit").guards == ["omeka_acl:requires_role(author)", "omeka_acl:requires_role(reviewer)"]
    assert acl.decide("C", None).auth == "anonymous"


def test_acl_rules_outside_module_or_acl_factory_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"type": "omeka-s-module"}')
    (tmp_path / "src").mkdir()
    # A job temporarily granting access is not a bootstrap rule.
    (tmp_path / "src" / "Job.php").write_text("<?php\n$acl->allow(null, 'M\\\\Controller\\\\Index');\n")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "module.config.php").write_text(
        "<?php\nreturn ['controllers' => ['invokables' => ['M\\\\Controller\\\\Index' => 'X']],\n"
        "'router' => ['routes' => ['m' => ['type' => 'Literal', "
        "'options' => ['route' => '/m', 'defaults' => ['controller' => 'M\\\\Controller\\\\Index']]]]]];\n"
    )
    route = OmekaSAnalyzer().analyze(tmp_path).routes[0]
    assert route.auth == "required"


# ---------------------------------------------------------------------------
# API key auth
# ---------------------------------------------------------------------------


def test_api_key_auth_is_surfaced_for_api_routes() -> None:
    result = OmekaSAnalyzer().analyze(CORE)
    routes = {(r.path, r.method): r for r in result.routes}
    for key in [("/api", "ANY"), ("/api/:resource", "ANY"), ("/api/:resource/:id", "ANY")]:
        assert routes[key].auth == "anonymous"  # `allow(null, 'Omeka\Controller\Api')`
        assert "key_identity/key_credential" in routes[key].guard_evidence
    assert "key_identity" not in (routes[("/install", "ANY")].guard_evidence or "")
    hints = {(h.hint, h.file, h.line) for h in result.protocol_hints}
    assert ("protocol:omeka_api_key", "application/config/routes.config.php", 52) in hints
    assert ("protocol:omeka_api_key", "application/src/Mvc/MvcListeners.php", 13) in hints
    assert len(hints) == 2


def test_module_child_of_core_api_route_inherits_api_key_auth(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"type": "omeka-s-module"}')
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "module.config.php").write_text(
        "<?php\nreturn ['router' => ['routes' => ['api' => ['child_routes' => ['export' => "
        "['type' => 'Literal', 'options' => ['route' => '/export']]]]]]];\n"
    )
    result = OmekaSAnalyzer().analyze(tmp_path)
    (route,) = result.routes
    assert route.path == "/api/export"
    assert "key_identity" in route.guard_evidence
    assert [(h.hint, h.file) for h in result.protocol_hints] == [("protocol:omeka_api_key", "config/module.config.php")]


def test_message_mentioning_key_identity_is_not_api_key_auth(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"type": "omeka-s-module"}')
    (tmp_path / "Note.php").write_text("<?php\n$m = 'Use \"key_identity\" and \"key_credential\".';\n")
    assert OmekaSAnalyzer().analyze(tmp_path).protocol_hints == []


# ---------------------------------------------------------------------------
# Routes defined by the repo win over Omeka core's built-in parents
# ---------------------------------------------------------------------------


def test_repo_defined_parent_overrides_core_seed(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"name": "omeka/omeka-s"}')
    (tmp_path / "a.php").write_text(
        "<?php\nreturn ['router' => ['routes' => ['admin' => ['type' => 'Literal', "
        "'options' => ['route' => '/backend']]]]];\n"
    )
    (tmp_path / "b.php").write_text(
        "<?php\nreturn ['router' => ['routes' => ['admin' => ['child_routes' => ['x' => "
        "['type' => 'Literal', 'options' => ['route' => '/x']]]]]]];\n"
    )
    paths = {r.path for r in OmekaSAnalyzer().analyze(tmp_path).routes}
    assert paths == {"/backend", "/backend/x"}


# ---------------------------------------------------------------------------
# detect(): markers only
# ---------------------------------------------------------------------------


@pytest.fixture
def read_counter(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reads: list[str] = []
    real_bytes = pathlib.Path.read_bytes
    real_text = pathlib.Path.read_text
    real_source = analyzer_module.read_source

    def counting_bytes(self: Path) -> bytes:
        reads.append(str(self))
        return real_bytes(self)

    def counting_text(self: Path, *args, **kwargs) -> str:  # noqa: ANN002, ANN003
        reads.append(str(self))
        return real_text(self, *args, **kwargs)

    def counting_source(path, **kwargs):  # noqa: ANN001, ANN003
        reads.append(f"read_source:{path}")
        return real_source(path, **kwargs)

    monkeypatch.setattr(pathlib.Path, "read_bytes", counting_bytes)
    monkeypatch.setattr(pathlib.Path, "read_text", counting_text)
    monkeypatch.setattr(analyzer_module, "read_source", counting_source)
    return reads


def _php_tree(root: Path, count: int = 300) -> None:
    for i in range(count):
        folder = root / "src" / f"pkg{i % 10}"
        folder.mkdir(parents=True, exist_ok=True)
        # The old detect() read every file looking for this.
        (folder / f"F{i}.php").write_text("<?php\nnamespace Omeka\\Thing;\n" + "// filler\n" * 50)


def test_detect_reads_no_php_files_on_a_non_omeka_repo(tmp_path: Path, read_counter: list[str]) -> None:
    _php_tree(tmp_path)
    (tmp_path / "composer.json").write_text('{"require": {"slim/slim": "^4.0"}}')
    assert OmekaSAnalyzer().detect(tmp_path) is False
    # composer.json at most (read_source reads it via read_bytes).
    assert all("composer.json" in entry for entry in read_counter), read_counter
    assert len([e for e in read_counter if e.startswith("read_source:")]) <= 1


@pytest.mark.parametrize(
    "marker",
    ["application/Module.php", "config/module.ini", "modules/Mapping/config/module.ini"],
)
def test_detect_layout_markers_need_no_reads(tmp_path: Path, read_counter: list[str], marker: str) -> None:
    _php_tree(tmp_path, 20)
    path = tmp_path / marker
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")
    read_counter.clear()
    assert OmekaSAnalyzer().detect(tmp_path) is True
    assert read_counter == []


@pytest.mark.parametrize(
    "composer",
    [
        '{"name": "omeka/omeka-s"}',
        '{"name": "acme/omeka-s-module-x", "type": "omeka-s-module"}',
        '{"require-dev": {"omeka/omeka-s": "^4.0"}}',
    ],
)
def test_detect_composer_markers(tmp_path: Path, read_counter: list[str], composer: str) -> None:
    (tmp_path / "composer.json").write_text(composer)
    read_counter.clear()
    assert OmekaSAnalyzer().detect(tmp_path) is True
    assert len([e for e in read_counter if e.startswith("read_source:")]) == 1


def test_detect_rejects_a_plain_laminas_skeleton(tmp_path: Path) -> None:
    # `module/` + `config/application.config.php` + a module.config.php is
    # any Laminas MVC app, not Omeka.
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "application.config.php").write_text("<?php return [];")
    (tmp_path / "module" / "Application" / "config").mkdir(parents=True)
    (tmp_path / "module" / "Application" / "config" / "module.config.php").write_text("<?php return [];")
    assert OmekaSAnalyzer().detect(tmp_path) is False


# ---------------------------------------------------------------------------
# The copied PHP helpers never raise on garbage
# ---------------------------------------------------------------------------

_FUZZ_ALPHABET = list("[](){},'\"=>/\\#*$:;. \n\tarxyl-") + [
    "array(",
    "=>",
    "'router'",
    "'routes'",
    "'child_routes' => [",
    "->allow(",
    "->deny(",
    "null",
    "::class",
    "<<<EOT\n",
    "\nEOT",
    "/*",
    "*/",
]


def _fuzz_inputs() -> list[str]:
    rng = random.Random(20261012)
    seeds = [p.read_text(encoding="utf-8", errors="replace") for p in sorted(FIXTURES.rglob("*.php"))]
    inputs: list[str] = []
    for seed in seeds:
        for _ in range(25):
            cut = rng.randrange(len(seed) + 1)
            inputs.append(seed[:cut])
            junk = "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randrange(1, 30)))
            inputs.append(seed[:cut] + junk + seed[cut:])
    for _ in range(300):
        inputs.append("".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randrange(0, 400))))
    return inputs


def test_parsers_never_raise_on_garbage() -> None:
    for text in _fuzz_inputs():
        tokens = tokenize(text)
        names = NameContext.of(text)
        router_routes(route_trees(tokens), known={}, index={})
        mezzio_routes(tokens)
        rules = acl_rules(tokens, names, "f.php", lambda offset: 1)
        acl = Acl(rules)
        acl.decide("X", None)
        acl.decide("X", "index")
        expand_optional(text[:200])


def test_analyze_never_raises_on_truncated_fixtures(tmp_path: Path) -> None:
    rng = random.Random(7)
    for fixture in (MODULE, CORE):
        for source in sorted(fixture.rglob("*")):
            if not source.is_file():
                continue
            target = tmp_path / fixture.name / source.relative_to(fixture)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes()
            target.write_bytes(data[: rng.randrange(len(data) + 1)])
        OmekaSAnalyzer().analyze(tmp_path / fixture.name)


@pytest.mark.parametrize(
    "payload",
    [
        "[" * 50_000,
        "->allow(" * 20_000,
        "->allow(null, [" * 20_000,
        "'router' => ['routes' => [" + "'a' => ['options' => ['route' => '/a'], 'child_routes' => [" * 5_000,
        "'controllers' => ['invokables' => [" * 10_000,
    ],
    ids=["brackets", "allow_calls", "allow_arrays", "child_routes", "controllers"],
)
def test_hostile_input_is_bounded(payload: str) -> None:
    start = time.perf_counter()
    tokens = tokenize("<?php return [" + payload)
    router_routes(route_trees(tokens), known={}, index={})
    Acl(acl_rules(tokens, NameContext(), "f.php", lambda offset: 1)).decide("X", None)
    analyzer_module._registered_controllers(tokens, NameContext())
    assert time.perf_counter() - start < 5.0



# ---------------------------------------------------------------------------
# Review fixes: Laminas lookup order, registration, role constants, budget
# ---------------------------------------------------------------------------


def _acl(source: str, registered: set[str] | None = None, aliases: set[str] | None = None) -> Acl:
    return Acl(acl_rules(tokenize(source), NameContext(), "Module.php", lambda offset: 1), registered, aliases)


def test_specific_resource_rule_beats_an_all_resources_rule() -> None:
    acl = _acl("<?php $acl->allow(null, 'A\\Controller\\Pub'); $acl->deny(null, null, ['delete']);")
    # Laminas checks the specific resource first: its all-privileges allow
    # settles `delete` before the all-resources deny is consulted.
    decision = acl.decide("A\\Controller\\Pub", "delete")
    assert decision.auth == "anonymous"
    assert decision.evidence == "$acl->allow(null, 'A\\Controller\\Pub') at Module.php:1"
    # Another controller falls through to the all-resources deny.
    other = acl.decide("A\\Controller\\Other", "delete")
    assert (other.auth, other.guards[0]) == ("required", "omeka_acl:deny_anonymous")
    assert other.evidence == "$acl->deny(null, null, ['delete']) at Module.php:1"


def test_all_roles_deny_on_a_resource_continues_to_all_resources() -> None:
    # Laminas: an all-roles, all-privileges deny on the specific resource
    # doesn't stop the lookup; the all-resources allow applies.
    acl = _acl("<?php $acl->deny(null, 'X'); $acl->allow(null, null);")
    assert acl.decide("X", "index").auth == "anonymous"


def test_privilege_specific_deny_on_the_resource_wins() -> None:
    acl = _acl("<?php $acl->allow(null, null); $acl->deny(null, 'X', ['edit']);")
    assert acl.decide("X", "edit").auth == "required"
    assert acl.decide("X", "show").auth == "anonymous"
    # `:action` routes: some actions public, some not.
    assert acl.decide("X", None).auth == "unknown"


def test_last_rule_for_a_slot_wins() -> None:
    acl = _acl("<?php $acl->allow(null, 'X', ['a']); $acl->deny(null, 'X', ['a']);")
    assert acl.decide("X", "a").auth == "required"
    acl = _acl("<?php $acl->deny(null, 'X', ['a']); $acl->allow(null, 'X', ['a']);")
    assert acl.decide("X", "a").auth == "anonymous"


def test_guest_role_constant_is_resolved_like_the_string() -> None:
    for role in ("[Acl::ROLE_GUEST]", "Acl::ROLE_GUEST", "'guest'", "['guest']"):
        acl = _acl(f"<?php $acl->allow({role}, 'X');")
        assert acl.decide("X", "index").auth == "anonymous", role
    acl = _acl("<?php $acl->allow(Acl::ROLE_SITE_ADMIN, 'X');")
    assert acl.decide("X", "index").guards == ["omeka_acl:requires_role(site_admin)"]


def test_guest_rules_beat_all_roles_rules_for_the_guest() -> None:
    # The visitor is denied, but a guest's own allow comes first in its lookup.
    acl = _acl("<?php $acl->deny(null, 'X', ['index']); $acl->allow('guest', 'X');")
    assert acl.decide("X", "index").auth == "anonymous"


def test_alias_controller_is_not_an_acl_resource() -> None:
    acl = _acl("<?php $acl->allow('editor', 'Real');", registered={"Real"}, aliases={"Alias"})
    alias = acl.decide("Alias", "index")
    assert alias.auth == "anonymous"
    assert "not an ACL resource" in alias.evidence
    assert acl.decide("Real", "index").auth == "required"
    # Not registered anywhere we saw: no claim.
    assert acl.decide("Unknown", "index") .auth == "unknown"


def test_route_to_alias_or_unregistered_controller_is_not_required(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"type": "omeka-s-module"}')
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "module.config.php").write_text(
        "<?php\nreturn ['controllers' => ['invokables' => ['M\\\\Real' => 'R'], 'aliases' => ['M\\\\Alias' => 'M\\\\Real']],\n"
        "'router' => ['routes' => [\n"
        "  'a' => ['type' => 'Literal', 'options' => ['route' => '/a', 'defaults' => ['controller' => 'M\\\\Alias']]],\n"
        "  'u' => ['type' => 'Literal', 'options' => ['route' => '/u', 'defaults' => ['controller' => 'M\\\\Nowhere']]],\n"
        "  'r' => ['type' => 'Literal', 'options' => ['route' => '/r', 'defaults' => ['controller' => 'M\\\\Real']]],\n"
        "]]];\n"
    )
    routes = {r.path: r.auth for r in OmekaSAnalyzer().analyze(tmp_path).routes}
    assert routes == {"/a": "anonymous", "/u": "unknown", "/r": "required"}


def test_method_children_cover_every_form_of_an_optional_parent() -> None:
    source = """<?php return ['router' => ['routes' => [
        'user' => ['type' => 'Segment', 'options' => ['route' => '/user[/:id]'], 'child_routes' => [
            'delete' => ['type' => 'Method', 'options' => ['verb' => 'delete']],
        ]],
    ]]];"""
    found = {(r.path, r.method) for r in router_routes(route_trees(tokenize(source)))}
    assert found == {("/user", "DELETE"), ("/user/:id", "DELETE")}


def _big_repo(root: Path, controllers: int = 2000, rules: int = 2000, routes: int = 200) -> None:
    (root / "composer.json").write_text('{"type": "omeka-s-module"}')
    namespaces = 10
    per = controllers // namespaces
    (root / "Module.php").write_text(
        "<?php\nnamespace Big;\nclass Module {\n  public function onBootstrap($e) {\n"
        + "".join(
            f"    $acl->allow({'null' if i % 3 == 0 else repr('editor')}, 'Big\\\\N{i % namespaces}\\\\C{i % per}', ['a{i % 7}']);\n"
            for i in range(rules)
        )
        + "  }\n}\n"
    )
    (root / "config").mkdir()
    invokables = "".join(f"'Big\\\\N{i % namespaces}\\\\C{i // namespaces}' => 'X',\n" for i in range(controllers))
    route_entries = "".join(
        f"'r{j}' => ['type' => 'Segment', 'options' => ['route' => '/r{j}/:controller[/:action[/:id]]', "
        f"'defaults' => ['__NAMESPACE__' => 'Big\\\\N{j % namespaces}', 'action' => 'a{j % 5}']]],\n"
        for j in range(routes)
    )
    (root / "config" / "module.config.php").write_text(
        f"<?php\nreturn ['controllers' => ['invokables' => [\n{invokables}]],\n"
        f"'router' => ['routes' => [\n{route_entries}]]];\n"
    )


def test_many_controllers_rules_and_dynamic_routes_stay_fast(tmp_path: Path) -> None:
    _big_repo(tmp_path)
    start = time.perf_counter()
    result = OmekaSAnalyzer().analyze(tmp_path)
    elapsed = time.perf_counter() - start
    assert len(result.routes) == 600
    # The pre-index version took ~20 s here (286 s on a larger case).
    assert elapsed < 5.0, f"{elapsed:.1f}s"


def test_decision_budget_degrades_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    from attackmap_analyzer_omeka_s import acl as acl_module

    monkeypatch.setattr(acl_module, "MAX_DECISIONS", 2)
    acl = _acl("<?php $acl->allow(null, null);")
    assert [acl.decide(c, "x").auth for c in ("A", "B", "C")] == ["anonymous", "anonymous", "unknown"]
    # Memoised decisions don't count against the budget.
    assert acl.decide("A", "x").auth == "anonymous"
