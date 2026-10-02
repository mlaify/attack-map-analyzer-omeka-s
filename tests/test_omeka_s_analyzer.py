import shutil
import sys
from pathlib import Path

import pytest

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap_analyzer_omeka_s.contracts import AnalyzerMetadata, ScanResult
from attackmap_analyzer_omeka_s import OmekaSAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_contracts_use_shared_sdk_types() -> None:
    assert AnalyzerMetadata is SharedAnalyzerMetadata
    assert ScanResult is SharedScanResult


def test_metadata_contains_required_fields() -> None:
    analyzer = OmekaSAnalyzer()
    metadata = analyzer.metadata

    assert metadata.name == "omeka-s"
    assert metadata.display_name == "Omeka S Analyzer"
    assert metadata.version == "0.1.0"
    assert metadata.description
    assert metadata.scope
    assert metadata.targets
    assert metadata.languages == ["php"]
    assert metadata.experimental is True


def test_detect_identifies_omeka_s_project() -> None:
    analyzer = OmekaSAnalyzer()
    assert analyzer.detect(FIXTURES / "omeka_s_app") is True


def test_analyze_extracts_omeka_surfaces_and_services() -> None:
    analyzer = OmekaSAnalyzer()
    result = analyzer.analyze(FIXTURES / "omeka_s_app")

    route_paths = {route.path for route in result.routes}
    framework_hints = {hint.hint for hint in result.framework_hints}
    external_targets = {call.target for call in result.external_calls}
    database_kinds = {hint.kind for hint in result.databases}

    assert "/admin" in route_paths
    assert "/api" in route_paths
    assert "/s/:site-slug" in route_paths

    # Omeka/Laminas metadata is a FrameworkHint, not an AuthHint (AttackMap#258).
    assert "omeka_surface:admin" in framework_hints
    assert "omeka_surface:api" in framework_hints
    assert "omeka_surface:site" in framework_hints
    assert "omeka_extension:service_manager" in framework_hints
    assert "omeka_extension:navigation" in framework_hints
    assert "omeka_dependency" in framework_hints
    assert any(hint.startswith("controller:Application\\Controller\\") for hint in framework_hints)
    assert any(hint.startswith("service:Omeka\\Connection") for hint in framework_hints)
    assert any(hint.startswith("omeka_service:Connection") for hint in framework_hints)
    assert result.auth_hints == []

    assert "sql" in database_kinds
    assert "https://collector.example.net/ingest" in external_targets


def test_analyze_returns_core_compatible_scan_shape() -> None:
    analyzer = OmekaSAnalyzer()
    result = analyzer.analyze(FIXTURES / "omeka_s_app")

    assert isinstance(result.root, str)
    assert isinstance(result.files_scanned, int)
    assert isinstance(result.languages, list)
    assert hasattr(result, "routes")
    assert hasattr(result, "external_calls")
    assert hasattr(result, "databases")
    assert hasattr(result, "auth_hints")
    assert hasattr(result, "secret_hints")


def test_metadata_priority_and_opt_in() -> None:
    # Core runs analyzers in (priority, name) order and merges first-seen-wins
    # (AttackMap#221): this app-specific analyzer runs after php-web (40) and
    # php-laminas (70), and stays opt-in via `-m omeka-s`.
    metadata = OmekaSAnalyzer().metadata
    assert metadata.priority == 160
    assert metadata.enabled_by_default is False


# ---------------------------------------------------------------------------
# Repo walking via attackmap.sdk.fs (AttackMap#253)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parent", ["build/out", "build/vendor"])
def test_repo_checked_out_under_skip_dir_name_is_still_analyzed(tmp_path: Path, parent: str) -> None:
    # Skip dirs used to be matched against absolute path parts, so a repo
    # under any `vendor/` directory yielded no PHP files at all.
    repo = tmp_path / parent / "repo"
    shutil.copytree(FIXTURES / "omeka_s_app", repo)
    analyzer = OmekaSAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned > 0
    assert result.routes
    assert result.framework_hints


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_source_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.php").write_text("<?php\nreturn ['route' => '/outside-secret', 'k' => getenv('OUTSIDE_SECRET_KEY')];\n")
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "omeka_s_app", repo)
    (repo / "module" / "CustomModule" / "config" / "linked.php").symlink_to(outside / "secret.php")

    result = OmekaSAnalyzer().analyze(repo)
    assert "/outside-secret" not in {r.path for r in result.routes}
    assert "OUTSIDE_SECRET_KEY" not in {s.name for s in result.secret_hints}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_detect_does_not_follow_symlink_out_of_repo(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Module.php").write_text("<?php\nnamespace Omeka;\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Module.php").symlink_to(outside / "Module.php")
    assert OmekaSAnalyzer().detect(repo) is False


def test_framework_hints_cite_their_source_line() -> None:
    result = OmekaSAnalyzer().analyze(FIXTURES / "omeka_s_app")
    for hint in result.framework_hints:
        lines = (FIXTURES / "omeka_s_app" / hint.file).read_text().split("\n")
        if hint.evidence_text.startswith("inferred from path"):
            assert hint.line == 1  # path-derived (omeka_extension:module)
        else:
            assert hint.evidence_text == lines[hint.line - 1].strip()


# ---------------------------------------------------------------------------
# False positives on ordinary PHP (port of mlaify/attackmap-analyzer-php-web#2)
# ---------------------------------------------------------------------------

NOISE = FIXTURES / "omeka_module_noise"


def test_navigation_route_names_are_not_routes() -> None:
    # Omeka admin navigation `'route' => 'admin/harvester'` names a route;
    # only the router's path specs are routes.
    result = OmekaSAnalyzer().analyze(NOISE)
    assert {(r.path, r.method) for r in result.routes} == {("/harvester[/:action]", "ANY"), ("[/:id]", "ANY")}


def test_db_and_api_connection_settings_are_not_secrets() -> None:
    result = OmekaSAnalyzer().analyze(NOISE)
    assert {s.name for s in result.secret_hints} == {"DB_PASSWORD", "API_TOKEN"}
