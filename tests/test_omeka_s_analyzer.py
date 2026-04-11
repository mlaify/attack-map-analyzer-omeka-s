from pathlib import Path

from attackmap_analyzer_omeka_s import OmekaSAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


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
    auth_hints = {hint.hint for hint in result.auth_hints}
    external_targets = {call.target for call in result.external_calls}
    database_kinds = {hint.kind for hint in result.databases}

    assert "/admin" in route_paths
    assert "/api" in route_paths
    assert "/s/:site-slug" in route_paths

    assert "omeka_surface:admin" in auth_hints
    assert "omeka_surface:api" in auth_hints
    assert "omeka_surface:site" in auth_hints
    assert "omeka_extension:service_manager" in auth_hints
    assert "omeka_extension:navigation" in auth_hints
    assert any(hint.startswith("controller:Application\\Controller\\") for hint in auth_hints)
    assert any(hint.startswith("service:Omeka\\Connection") for hint in auth_hints)
    assert any(hint.startswith("omeka_service:Connection") for hint in auth_hints)

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
