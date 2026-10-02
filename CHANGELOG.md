# Changelog

All notable changes to `attackmap-analyzer-omeka-s` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
