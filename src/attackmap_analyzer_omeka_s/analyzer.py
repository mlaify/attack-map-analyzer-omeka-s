from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, line_snippet, read_source, rel

from .contracts import AnalyzerMetadata, DatabaseHint, ExternalCall, FrameworkHint, Route, ScanResult, SecretHint

# Laminas router `'options' => ['route' => '/my-module[/:id]']`. Only URL
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
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False

        if self._has_omeka_composer_signals(root):
            return True

        if (
            (root / "config" / "application.config.php").exists()
            and (root / "module").is_dir()
            and next(iter_repo_files(root, names={"module.config.php"}), None) is not None
        ):
            return True

        for file_path in iter_repo_files(root, suffixes={".php"}):
            content = read_source(file_path)
            if content and ("namespace Omeka" in content or "Omeka\\Connection" in content):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        self._extract_composer_signals(root, result)

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
            self._extract_routes_and_surfaces(content, relative, result)
            self._extract_controllers_and_services(content, relative, result)
            self._extract_extension_points(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _has_omeka_composer_signals(self, root: Path) -> bool:
        data = self._load_composer(root)
        if data is None:
            return False

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

    def _extract_routes_and_surfaces(self, content: str, relative: str, result: ScanResult) -> None:
        for match in ROUTE_PATH_PATTERN.finditer(content):
            path = match.group(1)
            self._append_unique_route(result, path, "ANY", relative, line_of(content, match.start()))
            self._append_surface_hint_for_path(result, path, relative, content, match.start())

        for match in ROUTE_NAME_PATTERN.finditer(content):
            route_name = match.group(1).lower()
            for surface in ("admin", "api", "site"):
                if surface in route_name:
                    self._append_framework(result, f"omeka_surface:{surface}", relative, content, match.start(), 0.6)
                    break

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
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

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
