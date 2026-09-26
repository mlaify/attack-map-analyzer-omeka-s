# AttackMap Omeka S Analyzer

> [!IMPORTANT]
> **Looking for help.** AttackMap is looking for contributors and co-maintainers.
> Development is paused until more hands join — if you'd like to help with the
> core engine, an analyzer, the macOS app, or the docs, open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

`attackmap-analyzer-omeka-s` is an application-aware analyzer module for AttackMap.

It focuses on Omeka S and emits structured scan signals for:
- likely admin, site, and API surfaces
- route and controller hints from Laminas-style module config
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
