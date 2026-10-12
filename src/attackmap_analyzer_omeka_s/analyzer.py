from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, line_snippet, read_source, rel

from .acl import Acl, AclRule, Decision, acl_rules, combine
from .contracts import (
    AnalyzerMetadata,
    DatabaseHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
)
from .phparray import (
    NameContext,
    PhpArray,
    PhpExpr,
    PhpString,
    PhpValue,
    Token,
    class_name,
    is_true,
    keyed_arrays,
    tokenize,
)
from .routes import LaminasRoute, RouteNode, route_trees, router_routes

# Fallback for a file with no recognizable `'router' => ['routes' => ...]`
# tree (see `routes.py` for the structural walk): Laminas router
# `'options' => ['route' => '/my-module[/:id]']`. Only URL
# path specs: rooted (`/...`) or an optional child segment (`[/:id]`). Omeka
# module `navigation` pages use the same key for a route *name*
# (`'route' => 'admin/my-module'`), which is not a path (port of
# mlaify/attackmap-analyzer-php-web#2's config-path fix).
ROUTE_PATH_PATTERN = re.compile(r"['\"]route['\"]\s*=>\s*['\"]([/\[][^'\"]*)['\"]", re.IGNORECASE)
ROUTE_NAME_PATTERN = re.compile(r"['\"]([A-Za-z0-9_\\-]+)['\"]\s*=>\s*\[\s*['\"]type['\"]\s*=>", re.IGNORECASE)
# `Foo\\BarController::class` — whole token matched possessively, keyword
# checked in Python (see the service pattern below; mlaify/AttackMap#236).
CONTROLLER_PATTERN = re.compile(r"(?<![A-Za-z0-9_\\])([A-Za-z_\\][A-Za-z0-9_\\]*+)::class")
# Match the whole `Foo\\BarService::class` token in one possessive pass, then
# check for a service keyword in Python. The old single regex
# (`[..]*(?:Service|…)[..]*::class`) backtracked quadratically on a long
# identifier-like line, enough to stall a scan (mlaify/AttackMap#236).
SERVICE_PATTERN = re.compile(r"(?<![A-Za-z0-9_\\])([A-Za-z_\\][A-Za-z0-9_\\]*+)::class")
_SERVICE_WORD = re.compile(r"Service|Manager|Repository|Adapter|Connection", re.IGNORECASE)
OMEKA_SERVICE_PATTERN = re.compile(r"Omeka\\([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)", re.IGNORECASE)
OUTBOUND_PATTERNS = [
    re.compile(r"curl_init\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"file_get_contents\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"->(?:get|post|put|patch|delete|request)\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
]
# Secret-shaped env var names only. `API`/`DB` on their own matched
# `DB_HOST`/`API_URL`; `DB_PASSWORD`/`API_KEY`/`API_TOKEN` still match via
# PASSWORD/KEY/TOKEN. Case-sensitive: env var names are upper-case
# (port of mlaify/attackmap-analyzer-php-web#2).
_SECRET_NAME = r"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD)[A-Z0-9_]*)"
SECRET_PATTERNS = [
    re.compile(r"getenv\s*\(\s*['\"]" + _SECRET_NAME + r"['\"]"),
    re.compile(r"\$_ENV\s*\[\s*['\"]" + _SECRET_NAME + r"['\"]\s*\]"),
]
# Module-config keys that bind Omeka/Laminas extension points.
EXTENSION_KEY_PATTERNS = [
    (re.compile(r"['\"]service_manager['\"]", re.IGNORECASE), "omeka_extension:service_manager"),
    (re.compile(r"['\"]factories['\"]", re.IGNORECASE), "omeka_extension:factory"),
    (re.compile(r"['\"]navigation['\"]", re.IGNORECASE), "omeka_extension:navigation"),
]
DATASTORE_PATTERN = re.compile(r"omeka\\connection|new pdo\(|doctrine", re.IGNORECASE)
# Omeka API key authentication: `?key_identity=…&key_credential=…`, read by
# `MvcListeners::authenticateApiKey` on routes whose defaults set `__KEYAUTH__`.
# Only code that reads the parameter counts, not a message mentioning it.
API_KEY_PARAM_PATTERN = re.compile(
    r"(?:getQuery|fromQuery|getParam|fromRoute)\s*\(\s*['\"]key_(?:identity|credential)['\"]"
)
API_KEY_HINT = "protocol:omeka_api_key"
_API_KEY_NOTE = "Omeka API key auth accepted (key_identity/key_credential query parameters)"

# Omeka core's parent routes (application/config/routes.config.php), so a
# module's `'admin' => ['child_routes' => [...]]` stub joins onto `/admin`
# and inherits `__ADMIN__` when the module is analyzed without core. Routes the
# repo defines itself take precedence.
_SEED = -1  # offset of a value that doesn't come from the scanned repo
OMEKA_CORE_ROUTES: dict[str, RouteNode] = {
    "top": RouteNode(
        "/",
        {"__NAMESPACE__": PhpString("Omeka\\Controller", _SEED), "controller": PhpString("Index", _SEED)},
    ),
    "site": RouteNode(
        "/s/:site-slug",
        {
            "__NAMESPACE__": PhpString("Omeka\\Controller\\Site", _SEED),
            "__SITE__": PhpExpr("true", _SEED),
            "controller": PhpString("Index", _SEED),
            "action": PhpString("index", _SEED),
        },
    ),
    "admin": RouteNode(
        "/admin",
        {
            "__NAMESPACE__": PhpString("Omeka\\Controller\\Admin", _SEED),
            "__ADMIN__": PhpExpr("true", _SEED),
            "controller": PhpString("Index", _SEED),
            "action": PhpString("browse", _SEED),
        },
    ),
    "admin/site": RouteNode(
        "/admin/site",
        {
            "__NAMESPACE__": PhpString("Omeka\\Controller\\SiteAdmin", _SEED),
            "__ADMIN__": PhpExpr("true", _SEED),
            "__SITEADMIN__": PhpExpr("true", _SEED),
            "controller": PhpString("Index", _SEED),
            "action": PhpString("index", _SEED),
        },
    ),
    "admin/site/slug": RouteNode(
        "/admin/site/s/:site-slug",
        {
            "__NAMESPACE__": PhpString("Omeka\\Controller\\SiteAdmin", _SEED),
            "__ADMIN__": PhpExpr("true", _SEED),
            "__SITEADMIN__": PhpExpr("true", _SEED),
            "controller": PhpString("Index", _SEED),
            "action": PhpString("edit", _SEED),
        },
    ),
    "api": RouteNode(
        "/api",
        {
            "__API__": PhpExpr("true", _SEED),
            "__KEYAUTH__": PhpExpr("true", _SEED),
            "controller": PhpString("Omeka\\Controller\\Api", _SEED),
        },
    ),
}
_ADMIN_EVIDENCE = (
    "route default '__ADMIN__' => true: Omeka redirects anonymous admin requests to the login page "
    "(MvcListeners::redirectToLogin)"
)
# Files whose `->allow()` / `->deny()` calls are ACL rules: a module's
# Module.php (onBootstrap / attachListeners) and Omeka core's AclFactory.
_ACL_FILE_NAMES = ("Module.php",)
_ACL_FILE_SUFFIXES = ("AclFactory.php",)


_MODULES_DIR_SCAN_LIMIT = 500


def _is_acl_file(name: str) -> bool:
    return name in _ACL_FILE_NAMES or name.endswith(_ACL_FILE_SUFFIXES)


# (file, content, route trees, names) awaiting the cross-file route index.
_RouteFile = tuple[str, str, list[PhpArray], NameContext]


class OmekaSAnalyzer:
    metadata = AnalyzerMetadata(
        name="omeka-s",
        display_name="Omeka S Analyzer",
        version="0.1.0",
        description="Application-aware Omeka S analyzer for Laminas module config, services, and extension surfaces.",
        scope="Omeka S and Omeka-style Laminas MVC projects with module config-driven routes and services.",
        targets=["omeka-s", "php-laminas", "php-web"],
        languages=["php"],
        priority=160,
        experimental=True,
        enabled_by_default=False,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        """Markers only, no PHP file contents (#2): composer.json naming
        `omeka/omeka-s` (or an `omeka/*` dependency, or an `omeka-s-module`
        package), Omeka core's `application/Module.php`, or a module's
        `config/module.ini` (at the root or under `modules/<Name>/`). At most
        one small file (composer.json) is read."""
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        return self._has_omeka_layout(root) or self._has_omeka_composer_signals(root)

    @staticmethod
    def _has_omeka_layout(root: Path) -> bool:
        """`application/Module.php` or a `config/module.ini`, by existence only."""
        if _contained_file(root, "application/Module.php") or _contained_file(root, "config/module.ini"):
            return True
        modules = root / "modules"
        if not modules.is_dir() or modules.is_symlink():
            return False
        try:
            entries = sorted(modules.iterdir())[:_MODULES_DIR_SCAN_LIMIT]
        except OSError:
            return False
        return any(_contained_file(root, f"modules/{entry.name}/config/module.ini") for entry in entries)

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        self._extract_composer_signals(root, result)

        pending: list[_RouteFile] = []
        rules: list[AclRule] = []
        controllers: set[str] = set()
        # Pruned by repo-relative dir name (vendor, node_modules, .git, ...);
        # symlinks out of the repo are not followed (AttackMap#253).
        for file_path in iter_repo_files(root, suffixes={".php"}):
            result.files_scanned += 1
            if "php" not in result.languages:
                result.languages.append("php")

            content = read_source(file_path)
            if content is None:
                continue

            relative = rel(file_path, root)
            # Tokenized once, only when route, ACL or controller config is present.
            has_routes = "'route" in content or '"route' in content
            has_rules = _is_acl_file(file_path.name) and ("->allow" in content or "->deny" in content)
            has_controllers = "'controllers'" in content or '"controllers"' in content
            tokens = tokenize(content) if has_routes or has_rules or has_controllers else []
            names = NameContext.of(content) if tokens else NameContext()
            self._extract_routes_and_surfaces(content, relative, result, pending, tokens, names)
            if has_rules:
                rules.extend(acl_rules(tokens, names, relative, lambda offset, c=content: line_of(c, offset)))
            if has_controllers:
                controllers.update(_registered_controllers(tokens, names))
            self._extract_controllers_and_services(content, relative, result)
            self._extract_extension_points(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_secret_hints(content, relative, result)
            self._extract_api_key_params(content, relative, result)

        omeka_app = bool(rules) or self._has_omeka_composer_signals(root) or self._has_omeka_layout(root)
        self._emit_router_routes(pending, Acl(rules), controllers, omeka_app, result)
        result.languages.sort()
        return result

    def _has_omeka_composer_signals(self, root: Path) -> bool:
        data = self._load_composer(root)
        if data is None:
            return False
        name = data.get("name")
        if isinstance(name, str) and name.lower() == "omeka/omeka-s":
            return True
        if data.get("type") == "omeka-s-module":
            return True

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }
        for package in requirements:
            lowered = package.lower()
            if lowered.startswith("omeka/") or lowered == "omeka-s":
                return True
        return False

    def _extract_composer_signals(self, root: Path, result: ScanResult) -> None:
        text = read_source(root / "composer.json", root=root)
        data = self._load_composer(root)
        if data is None or text is None:
            return

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }
        for package in requirements:
            lowered = package.lower()
            offset = self._composer_offset(text, package)
            if lowered.startswith("omeka/") or lowered == "omeka-s":
                self._append_framework(result, "omeka_dependency", "composer.json", text, offset, 0.9)
            if lowered.startswith("laminas/") or lowered.startswith("zendframework/"):
                self._append_framework(result, "laminas_dependency", "composer.json", text, offset, 0.9)
            if "doctrine" in lowered:
                self._append_unique_database(result, "sql", "composer.json", text, offset)

    def _extract_routes_and_surfaces(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        pending: list[_RouteFile],
        tokens: list[Token],
        names: NameContext,
    ) -> None:
        """Route-name surfaces and fallback routes now; router trees go to
        ``pending`` for :meth:`_emit_router_routes`, which needs every file's
        route names and ACL rules."""
        trees = route_trees(tokens) if tokens else []
        if trees:
            pending.append((relative, content, trees, names))

        # A child route's `'route' => '[/:id]'` is only a fragment of a path,
        # so the flat literal fallback is for files with no router tree at all.
        if not trees and "child_routes" not in content:
            for match in ROUTE_PATH_PATTERN.finditer(content):
                path = match.group(1)
                line = line_of(content, match.start())
                self._append_unique_route(result, Route(path=path, file=relative, line=line))
                self._append_surface_hint_for_path(result, path, relative, content, match.start())

        for match in ROUTE_NAME_PATTERN.finditer(content):
            route_name = match.group(1).lower()
            for surface in ("admin", "api", "site"):
                if surface in route_name:
                    self._append_framework(result, f"omeka_surface:{surface}", relative, content, match.start(), 0.6)
                    break

    def _extract_api_key_params(self, content: str, relative: str, result: ScanResult) -> None:
        match = API_KEY_PARAM_PATTERN.search(content)
        if match:
            self._append_protocol(result, relative, content, line_of(content, match.start()))

    def _emit_router_routes(
        self, pending: list[_RouteFile], acl: Acl, controllers: set[str], omeka_app: bool, result: ScanResult
    ) -> None:
        # Laminas merges all modules' config: index every named route first
        # (on top of Omeka core's well-known parents) so a module's
        # `'admin' => ['child_routes' => [...]]` stub joins onto `/admin`.
        index: dict[str, RouteNode] = {}
        for _ in range(3):
            before = len(index)
            for _relative, _content, trees, _names in pending:
                router_routes(trees, known={**OMEKA_CORE_ROUTES, **index}, index=index)
            if len(index) == before:
                break
        known = {**OMEKA_CORE_ROUTES, **index}
        for relative, content, trees, names in pending:
            keyauth_line: int | None = None
            for found in router_routes(trees, known=known):
                line = line_of(content, found.offset)
                decision = self._decide(found, names, acl, controllers, omeka_app)
                evidence = decision.evidence
                if is_true(found.defaults.get("__KEYAUTH__")):
                    keyauth_line = keyauth_line or line
                    evidence = f"{evidence}; {_API_KEY_NOTE}" if evidence else _API_KEY_NOTE
                self._append_unique_route(
                    result,
                    Route(
                        path=found.path,
                        method=found.method,
                        file=relative,
                        line=line,
                        auth=decision.auth,
                        guards=decision.guards,
                        guard_evidence=evidence,
                    ),
                )
                self._append_surface_hint_for_path(result, found.path, relative, content, found.offset)
            if keyauth_line is not None:
                # Anchor on the file's own `'__KEYAUTH__' => true` if it has one.
                own = content.find("__KEYAUTH__")
                self._append_protocol(result, relative, content, line_of(content, own) if own >= 0 else keyauth_line)

    @staticmethod
    def _decide(
        found: LaminasRoute, names: NameContext, acl: Acl, controllers: set[str], omeka_app: bool
    ) -> Decision:
        acl_decision = (
            OmekaSAnalyzer._decide_acl(found, names, acl, controllers) if omeka_app else Decision("unknown")
        )
        if is_true(found.defaults.get("__ADMIN__")):
            # Login first; the ACL's role check still applies after it.
            if acl_decision.auth == "required":
                return Decision(
                    "required",
                    ["omeka:admin_login", *acl_decision.guards],
                    f"{_ADMIN_EVIDENCE}; {acl_decision.evidence}",
                )
            return Decision("required", ["omeka:admin_login"], _ADMIN_EVIDENCE)
        return acl_decision

    @staticmethod
    def _decide_acl(found: LaminasRoute, names: NameContext, acl: Acl, controllers: set[str]) -> Decision:
        defaults = found.defaults
        namespace = _string(defaults.get("__NAMESPACE__"))
        action = None if ":action" in found.path else _string(defaults.get("action"))
        if ":controller" in found.path:
            if not namespace:
                return Decision("unknown")
            prefix = namespace + "\\"
            candidates = sorted(c for c in controllers if c.startswith(prefix) and "\\" not in c[len(prefix) :])
            return combine([acl.decide(c, action) for c in candidates], namespace)
        controller = _controller_name(defaults.get("controller"), namespace, names)
        if controller is None:
            return Decision("unknown")
        return acl.decide(controller, action)

    def _extract_controllers_and_services(self, content: str, relative: str, result: ScanResult) -> None:
        first_controller: int | None = None
        for match in CONTROLLER_PATTERN.finditer(content):
            if "controller" not in match.group(1).lower():
                continue
            if first_controller is None:
                first_controller = match.start()
            self._append_framework(result, f"controller:{match.group(1)}", relative, content, match.start(), 0.8)
        if first_controller is not None:
            self._append_framework(result, "laminas_controller_mapping", relative, content, first_controller, 0.8)

        for match in SERVICE_PATTERN.finditer(content):
            service_name = match.group(1)
            if not _SERVICE_WORD.search(service_name):
                continue
            self._append_framework(result, f"service:{service_name}", relative, content, match.start(), 0.7)
            if "Connection" in service_name:
                self._append_unique_database(result, "sql", relative, content, match.start())

        for match in OMEKA_SERVICE_PATTERN.finditer(content):
            service_name = match.group(1)
            self._append_framework(result, f"omeka_service:{service_name}", relative, content, match.start(), 0.7)
            if service_name.lower().endswith("connection"):
                self._append_unique_database(result, "sql", relative, content, match.start())

    def _extract_extension_points(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in EXTENSION_KEY_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_framework(result, hint, relative, content, match.start(), 0.7)
        normalized = relative.replace("\\", "/")
        if "/module/" in f"/{normalized}/":
            # Derived from the file's location, not a source line: anchor at line 1.
            self._append_framework(
                result, "omeka_extension:module", relative, None, None, 0.6, evidence=f"inferred from path {relative}"
            )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_external(result, match.group(1), relative, content, match.start())

    def _extract_datastores(self, content: str, relative: str, result: ScanResult) -> None:
        match = DATASTORE_PATTERN.search(content)
        if match:
            self._append_unique_database(result, "sql", relative, content, match.start())

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative, content, match.start())

    def _append_surface_hint_for_path(
        self, result: ScanResult, path: str, relative: str, content: str, offset: int
    ) -> None:
        lowered = path.lower()
        surface = None
        if lowered.startswith("/admin") or "/admin/" in lowered:
            surface = "admin"
        elif lowered.startswith("/api") or "/api/" in lowered:
            surface = "api"
        elif lowered.startswith("/s/") or lowered.startswith("/site"):
            surface = "site"
        if surface:
            self._append_framework(result, f"omeka_surface:{surface}", relative, content, offset, 0.7)

    @staticmethod
    def _load_composer(root: Path) -> dict | None:
        text = read_source(root / "composer.json", root=root)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _composer_offset(text: str, package: str) -> int:
        """Offset of a package's `"name": "constraint"` entry in composer.json (0 if not found)."""
        index = text.find(f'"{package}"')
        return index if index >= 0 else 0

    @staticmethod
    def _append_unique_route(result: ScanResult, route: Route) -> None:
        key = (route.path, route.method, route.file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(route)

    @staticmethod
    def _append_protocol(result: ScanResult, file: str, content: str, line: int) -> None:
        if any((item.hint, item.file) == (API_KEY_HINT, file) for item in result.protocol_hints):
            return
        result.protocol_hints.append(
            ProtocolHint(
                hint=API_KEY_HINT,
                file=file,
                line=line,
                evidence_text=line_snippet(content, line) or API_KEY_HINT,
                confidence=0.8,
            )
        )

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, content: str, offset: int) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        line = line_of(content, offset)
        result.external_calls.append(
            ExternalCall(target=target, file=file, line=line, evidence_text=line_snippet(content, line) or target)
        )

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, content: str, offset: int) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        line = line_of(content, offset)
        result.databases.append(
            DatabaseHint(kind=kind, file=file, line=line, evidence_text=line_snippet(content, line) or kind)
        )

    @staticmethod
    def _append_framework(
        result: ScanResult,
        hint: str,
        file: str,
        content: str | None,
        offset: int | None,
        confidence: float,
        *,
        evidence: str | None = None,
    ) -> None:
        """Append a FrameworkHint once per (hint, file).

        Located at ``offset`` when given; path-derived hints pass
        ``content=None`` and are anchored at line 1 with ``evidence``.
        """
        if any((item.hint, item.file) == (hint, file) for item in result.framework_hints):
            return
        if content is not None and offset is not None:
            line = line_of(content, offset)
            evidence_text = line_snippet(content, line) or hint
        else:
            line = 1
            evidence_text = evidence or hint
        result.framework_hints.append(
            FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence_text, confidence=confidence)
        )

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, content: str, offset: int) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        line = line_of(content, offset)
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=line_snippet(content, line) or name)
        )


def _contained_file(root: Path, relative: str) -> bool:
    """``root/relative`` is a regular file that doesn't resolve outside ``root``."""
    path = root / relative
    try:
        return path.is_file() and path.resolve().is_relative_to(root)
    except OSError:
        return False


def _string(value: PhpValue | None) -> str | None:
    if isinstance(value, PhpString):
        text = value.value.strip().lstrip("\\")
        return text or None
    return None


def _controller_name(value: PhpValue | None, namespace: str | None, names: NameContext) -> str | None:
    """The controller a route dispatches to, as Laminas' ModuleRouteListener
    resolves it: a short name (`'item-set'`) under `__NAMESPACE__` becomes
    `<namespace>\\ItemSet`."""
    if isinstance(value, PhpString):
        name = value.value.strip().lstrip("\\")
    else:
        name = class_name(value, names) or ""
    if not name:
        return None
    if namespace and not name.startswith(namespace):
        short = "".join(part[:1].upper() + part[1:] for part in name.replace("-", " ").split(" ") if part)
        name = f"{namespace}\\{short}"
    return name


def _registered_controllers(tokens: list[Token], names: NameContext) -> set[str]:
    """Controller names from `'controllers' => ['invokables' | 'factories' | 'aliases' => [...]]`."""
    found: set[str] = set()
    for controllers in keyed_arrays(tokens, "controllers"):
        for kind in ("invokables", "factories", "aliases"):
            bucket = controllers.get(kind)
            if not isinstance(bucket, PhpArray):
                continue
            for key, _value in bucket.items:
                if isinstance(key, PhpString):
                    name = key.value.strip().lstrip("\\")
                else:
                    name = class_name(key, names) or "" if key is not None else ""
                if name:
                    found.add(name)
    return found
