# AttackMap Omeka S Analyzer

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

`attackmap-analyzer-omeka-s` is an application-aware analyzer module for AttackMap.

It focuses on Omeka S and emits structured scan signals for:
- likely admin, site, and API surfaces
- route and controller hints from Laminas-style module config (router `'route' => '/path'` specs; navigation's `'route' => 'admin/my-module'` names a route and is not one)
- secret-shaped env var names (`getenv`, `$_ENV`) containing `SECRET`, `TOKEN`, `KEY`, `PASSWORD` or `PASSWD`, matched case-sensitively; `DB_HOST`-style connection settings are not secrets
- Omeka service usage (for example `Omeka\\Connection`)
- module extension points such as navigation and service manager factories

This module is intentionally heuristic and incremental.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-omeka-s.git
```

## Usage with AttackMap

```bash
attackmap analyze /path/to/repo --module omeka-s
```
