from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, read_source, rel

from .contracts import AnalyzerMetadata, AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

ROUTE_PATH_PATTERN = re.compile(r"['\"]route['\"]\s*=>\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
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
SECRET_PATTERNS = [
    re.compile(r"getenv\s*\(\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]", re.IGNORECASE),
    re.compile(r"\$_ENV\s*\[\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]\s*\]", re.IGNORECASE),
]


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
        data = self._load_composer(root)
        if data is None:
            return

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }
        for package in requirements:
            lowered = package.lower()
            if lowered.startswith("omeka/") or lowered == "omeka-s":
                self._append_unique_auth(result, "omeka_dependency", "composer.json")
            if lowered.startswith("laminas/") or lowered.startswith("zendframework/"):
                self._append_unique_auth(result, "laminas_dependency", "composer.json")
            if "doctrine" in lowered:
                self._append_unique_database(result, "sql", "composer.json")

    def _extract_routes_and_surfaces(self, content: str, relative: str, result: ScanResult) -> None:
        for match in ROUTE_PATH_PATTERN.finditer(content):
            path = match.group(1)
            self._append_unique_route(result, path, "ANY", relative)
            self._append_surface_hint_for_path(result, path, relative)

        for match in ROUTE_NAME_PATTERN.finditer(content):
            route_name = match.group(1).lower()
            if "admin" in route_name:
                self._append_unique_auth(result, "omeka_surface:admin", relative)
            elif "api" in route_name:
                self._append_unique_auth(result, "omeka_surface:api", relative)
            elif "site" in route_name:
                self._append_unique_auth(result, "omeka_surface:site", relative)

    def _extract_controllers_and_services(self, content: str, relative: str, result: ScanResult) -> None:
        found_controller = False
        for match in CONTROLLER_PATTERN.finditer(content):
            if "controller" not in match.group(1).lower():
                continue
            found_controller = True
            self._append_unique_auth(result, f"controller:{match.group(1)}", relative)
        if found_controller:
            self._append_unique_auth(result, "laminas_controller_mapping", relative)

        for match in SERVICE_PATTERN.finditer(content):
            service_name = match.group(1)
            if not _SERVICE_WORD.search(service_name):
                continue
            self._append_unique_auth(result, f"service:{service_name}", relative)
            if "Connection" in service_name:
                self._append_unique_database(result, "sql", relative)

        for match in OMEKA_SERVICE_PATTERN.finditer(content):
            service_name = match.group(1)
            self._append_unique_auth(result, f"omeka_service:{service_name}", relative)
            if service_name.lower().endswith("connection"):
                self._append_unique_database(result, "sql", relative)

    def _extract_extension_points(self, content: str, relative: str, result: ScanResult) -> None:
        lowered = content.lower()
        if "'service_manager'" in lowered or '"service_manager"' in lowered:
            self._append_unique_auth(result, "omeka_extension:service_manager", relative)
        if "'factories'" in lowered or '"factories"' in lowered:
            self._append_unique_auth(result, "omeka_extension:factory", relative)
        if "'navigation'" in lowered or '"navigation"' in lowered:
            self._append_unique_auth(result, "omeka_extension:navigation", relative)
        normalized = relative.replace("\\", "/")
        if "/module/" in f"/{normalized}/":
            self._append_unique_auth(result, "omeka_extension:module", relative)

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_external(result, match.group(1), relative)

    def _extract_datastores(self, content: str, relative: str, result: ScanResult) -> None:
        lowered = content.lower()
        if "omeka\\connection" in lowered or "new pdo(" in lowered or "doctrine" in lowered:
            self._append_unique_database(result, "sql", relative)

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative)

    def _append_surface_hint_for_path(self, result: ScanResult, path: str, relative: str) -> None:
        lowered = path.lower()
        if lowered.startswith("/admin") or "/admin/" in lowered:
            self._append_unique_auth(result, "omeka_surface:admin", relative)
        elif lowered.startswith("/api") or "/api/" in lowered:
            self._append_unique_auth(result, "omeka_surface:api", relative)
        elif lowered.startswith("/s/") or lowered.startswith("/site"):
            self._append_unique_auth(result, "omeka_surface:site", relative)

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
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file))
