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


def test_role_only_controller_in_core_requires_login() -> None:
    install = _routes(CORE)[("/install", "ANY")]
    # `$acl->allow('global_admin')` covers every resource; no anonymous rule.
    assert (install.auth, install.guards) == ("required", ["omeka_acl:requires_role(global_admin)"])


def test_unresolved_anonymous_allow_blocks_default_deny(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"type": "omeka-s-module"}')
    (tmp_path / "Module.php").write_text(
        "<?php\nnamespace M;\nclass Module {\n  public function onBootstrap($e) {\n"
        "    $acl->allow(null, $this->publicControllers());\n  }\n}\n"
    )
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "module.config.php").write_text(
        "<?php\nnamespace M;\nreturn ['router' => ['routes' => ['m' => ['type' => 'Literal', "
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


def test_zero_argument_allow_is_ignored() -> None:
    source = "<?php $acl->allow(); $acl->allow(null, 'C'); $x->allowed('y');"
    rules = acl_rules(tokenize(source), NameContext(), "f.php", lambda offset: 1)
    assert len(rules) == 1 and rules[0].resources == ["C"]
    assert Acl(rules).decide("C", "index").auth == "anonymous"


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
        "<?php\nreturn ['router' => ['routes' => ['m' => ['type' => 'Literal', "
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
