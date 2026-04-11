from __future__ import annotations

import json
import re
from pathlib import Path

from .contracts import AnalyzerMetadata, AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

ROUTE_PATH_PATTERN = re.compile(r"['\"]route['\"]\s*=>\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ROUTE_NAME_PATTERN = re.compile(r"['\"]([A-Za-z0-9_\\-]+)['\"]\s*=>\s*\[\s*['\"]type['\"]\s*=>", re.IGNORECASE)
CONTROLLER_PATTERN = re.compile(r"([A-Za-z_\\][A-Za-z0-9_\\]*Controller[A-Za-z0-9_\\]*)::class", re.IGNORECASE)
SERVICE_PATTERN = re.compile(
    r"([A-Za-z_\\][A-Za-z0-9_\\]*(?:Service|Manager|Repository|Adapter|Connection)[A-Za-z0-9_\\]*)::class",
    re.IGNORECASE,
)
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
        priority=20,
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

        if self._has_omeka_composer_signals(root / "composer.json"):
            return True

        if (root / "config" / "application.config.php").exists() and any(root.rglob("module.config.php")):
            if (root / "module").is_dir():
                return True

        for file_path in root.rglob("*.php"):
            if any(part in {"vendor", ".git", "node_modules"} for part in file_path.parts):
                continue
            content = self._read_text(file_path)
            if content and ("namespace Omeka" in content or "Omeka\\Connection" in content):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        composer_path = root / "composer.json"
        if composer_path.exists():
            self._extract_composer_signals(composer_path, result)

        for file_path in root.rglob("*.php"):
            if not file_path.is_file():
                continue
            if any(part in {"vendor", ".git", "node_modules"} for part in file_path.parts):
                continue

            result.files_scanned += 1
            if "php" not in result.languages:
                result.languages.append("php")

            content = self._read_text(file_path)
            if content is None:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes_and_surfaces(content, relative, result)
            self._extract_controllers_and_services(content, relative, result)
            self._extract_extension_points(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _has_omeka_composer_signals(self, composer_path: Path) -> bool:
        if not composer_path.exists():
            return False
        try:
            data = json.loads(composer_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
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

    def _extract_composer_signals(self, composer_path: Path, result: ScanResult) -> None:
        try:
            data = json.loads(composer_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
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
            found_controller = True
            self._append_unique_auth(result, f"controller:{match.group(1)}", relative)
        if found_controller:
            self._append_unique_auth(result, "laminas_controller_mapping", relative)

        for match in SERVICE_PATTERN.finditer(content):
            service_name = match.group(1)
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
        if "/module/" in f"/{relative.replace('\\\\', '/')}/":
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
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return None

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
