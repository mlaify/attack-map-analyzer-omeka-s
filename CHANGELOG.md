# Changelog

All notable changes to `attackmap-analyzer-omeka-s` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — false positives on ordinary PHP (port of mlaify/attackmap-analyzer-php-web#2)

- **Route names are not routes.** `'route' =>` values must be URL path specs: rooted (`/harvester[/:action]`) or an optional child segment (`[/:id]`). Omeka module admin navigation (`'navigation' => ['AdminModule' => [['route' => 'admin/harvester']]]`) no longer yields `ANY admin/harvester` routes. This is the Laminas form of php-web's config `'path' =>` fix.
- **`DB_*` / `API_*` settings are not secrets.** Secret env names must contain `SECRET`, `TOKEN`, `KEY`, `PASSWORD` or `PASSWD`, matched case-sensitively. `getenv('DB_HOST')`, `$_ENV['API_URL']` and lower-case names such as `getenv('cache_key_prefix')` no longer match; `DB_PASSWORD`, `API_KEY` and `API_TOKEN` still do.
- Not applicable here: php-web's Slim `$x->get('/…')` receiver check (no Slim/FastRoute extraction), its `jwt` / `auth` tightening (this analyzer emits no auth hints) and its `detect()` fix (this `detect()` already needs an `omeka/` composer dependency, `module/` + `config/application.config.php` + a `module.config.php`, or `namespace Omeka` / `Omeka\Connection` in a non-vendored PHP file).

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **No more non-auth `AuthHint`s.** Every hint this analyzer emitted as an `AuthHint` was Omeka/Laminas framework metadata, so it now emits them as `FrameworkHint` (`framework_hints`) with the same hint strings. Core's Omeka/MVC chain linker (`omeka_dependency`, `omeka_extension:`, `omeka_surface:`, `laminas_dependency`, `controller:`, `service:`) already reads `framework_hints`:
  - `controller:<FQCN>`, `laminas_controller_mapping`, `service:<FQCN>` → `FrameworkHint`
  - `omeka_service:*`, `omeka_extension:*`, `omeka_surface:*` → `FrameworkHint`
  - `omeka_dependency`, `laminas_dependency` (composer.json) → `FrameworkHint`
  The analyzer has no auth detectors of its own, so `auth_hints` is now always empty; generic PHP auth signals come from `php-web`.
- **Every signal now cites a line and quotes it.** Routes, external calls, databases, framework hints and secret hints carry `line` and (where the model has it) `evidence_text` via `attackmap.sdk.line_of` / `line_snippet`. Composer-declared dependencies point at the package's line in `composer.json`; `omeka_extension:module` (derived from the file living under `module/`) is anchored at line 1 with `evidence_text: "inferred from path <file>"`. Framework hints set `confidence` (0.9 dependencies, 0.8 controllers, 0.7 services/extension keys/path surfaces, 0.6 route-name surfaces and module paths).
- **Breaking for direct consumers of `ScanResult.auth_hints`:** code that looked for Omeka/Laminas hints in `auth_hints` must read `framework_hints`. AttackMap core already does.
- New `tests/test_signal_conformance.py` asserts the analyzer emits no non-auth `AuthHint` and every signal has an in-range `line` and evidence.

### Fixed — AttackMap#253

- **Repo walking now uses `attackmap.sdk.fs`.** `detect()` and `analyze()` walk with `iter_repo_files` and read with `read_source`. Skip dirs are matched by repo-relative name and pruned, so a repo checked out under a `vendor/` directory is analyzed instead of yielding no PHP files.
- **Symlinked files pointing outside the repo are not analyzed** (or used for detection), unreadable files no longer raise out of `detect()`/`analyze()`, and cp1252/latin-1 PHP sources are decoded instead of silently dropped. AttackMap's own report directories are skipped.
- `detect()`'s `module.config.php` probe stops at the first match and no longer looks inside `vendor/`.

### Changed

- **Priority 20 → 160** (AttackMap#221). Core now runs analyzers in `(priority, name)` order and merges first-seen-wins, so this application-specific analyzer runs after the generic `php-web` (40) and `php-laminas` (70) analyzers. Still experimental and opt-in: `attackmap analyze <repo> -m omeka-s`.
- Skip list is now the SDK's `DEFAULT_SKIP_DIRS` (was `vendor`, `.git`, `node_modules`; adds `build`, `dist`, `out`, `target`, virtualenvs and caches).
- Files are visited in sorted, depth-first order, so signal order is deterministic across filesystems. The set of signals is unchanged.
- Signal `file` paths are always POSIX-style, including on Windows.
- Requires an AttackMap core that ships `attackmap.sdk.fs`.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Application-aware Omeka S analyzer plugin for AttackMap
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attack-map-analyzer-omeka-s/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attack-map-analyzer-omeka-s/releases/tag/v0.1.0
