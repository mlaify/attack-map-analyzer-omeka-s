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
- routes from Laminas-style module config, walked structurally: `child_routes` joined onto their parent (including a module's `'admin' => ['child_routes' => ...]` stub, joined onto Omeka core's `/admin`), `may_terminate`, Method verbs, Segment optional parts and Regex `spec`s (see [Routes](#routes)); navigation's `'route' => 'admin/my-module'` names a route and is not one
- per-route access from Omeka's ACL and admin login (see [Route access](#route-access)), recorded on `Route.auth` / `guards` / `guard_evidence`
- Omeka API key authentication (`key_identity` / `key_credential`) as a `protocol:omeka_api_key` `ProtocolHint`
- controller hints
- secret-shaped env var names (`getenv`, `$_ENV`) containing `SECRET`, `TOKEN`, `KEY`, `PASSWORD` or `PASSWD`, matched case-sensitively; `DB_HOST`-style connection settings are not secrets
- Omeka service usage (for example `Omeka\\Connection`)
- module extension points such as navigation and service manager factories

This module is intentionally heuristic and incremental.

## Detection

`detect()` looks at markers only and reads at most one small file (`composer.json`):

- `application/Module.php` (Omeka S core), `config/module.ini` (a module repo) or `modules/<Name>/config/module.ini`, by existence;
- `composer.json` named `omeka/omeka-s`, of type `omeka-s-module`, or requiring an `omeka/*` package.

A generic Laminas app (`module/` + `config/application.config.php`) is not Omeka S.

## Routes

Router config is read with a small PHP-array tokenizer (`phparray.py`, `routes.py`, copied from `attackmap-analyzer-php-laminas` so this plugin has no cross-plugin dependency; mlaify/AttackMap#259 tracks extracting shared PHP helpers). `child_routes` are joined, `may_terminate` is honored, Method children set the HTTP method, and Segment optional parts expand to the minimal form plus one more optional group per form (at most 4 paths per route). Laminas merges every module's config, so a module's stub (`'admin' => ['child_routes' => [...]]`, no type or route) joins the route of that name defined elsewhere in the repo, or else Omeka core's `top`, `site`, `admin`, `admin/site`, `admin/site/slug` and `api` routes (with their `__NAMESPACE__`, `__ADMIN__` and `__KEYAUTH__` defaults).

## Route access

Each route's `auth` is decided from Omeka's own checks:

- **`__ADMIN__` routes** (`/admin/...`, including module routes under `admin`) are `required`: `MvcListeners::redirectToLogin` sends anonymous visitors to the login page. Guards: `omeka:admin_login`, plus the ACL role guards below.
- **The ACL.** `$acl->allow(<roles>, <resources>, <privileges>[, <assertion>])` and `->deny(...)` are read from `Module.php` (`onBootstrap`, `attachListeners` and helpers) and `*AclFactory.php` (Omeka core). Resources are controller names (`'Omeka\Controller\Site\Item'`, `Controller\IndexController::class` resolved through `namespace`/`use`); the route's controller comes from its `controller` default, through `__NAMESPACE__` as Laminas' `ModuleRouteListener` does (`'item-set'` → `…\ItemSet`). The privilege is the action.
  - **Lookup order** follows Laminas' `Acl::isAllowed`: the specific controller before the all-resources level (`null` resource); at each level the role's own rules, then all-roles rules; the privilege before all privileges; the last rule written for a slot wins. An all-roles, all-privileges deny on the controller continues to the all-resources level, as in Laminas. Two public principals are checked: the visitor (all-roles rules only) and `'guest'` (the Guest module's self-registration role, treated as public; `Acl::ROLE_*` constants resolve to their values, so `Acl::ROLE_GUEST` is `'guest'`). Role inheritance isn't modelled; Omeka adds its roles without parents.
  - `anonymous`: the visitor or a guest is allowed. `guard_evidence` quotes the deciding rule, narrowed to the matched resource, and its location.
  - `required`: both are denied by a rule (`omeka_acl:deny_anonymous`) or by Omeka's default deny. Omeka checks the role on every dispatch (`authorizeUserAgainstController`). Guards: `omeka_acl:requires_role(<role>)` for each role allowed, or `omeka_acl:default_deny`.
  - `unknown`: a conditional rule (assertion) decides, a `:action` route's actions disagree, a rule's role or privileges couldn't be resolved, or the per-repo budget (50,000 fresh decisions) is spent. An anonymous rule whose resource can't be resolved (`allow(null, $controllers)`), or a zero-argument `allow()` outside `*AclFactory.php`, turns every deny into `unknown`.
  - **Registration.** Omeka adds only the keys of `controllers.invokables`/`factories` as ACL resources, and `authorizeUserAgainstController` lets through a controller that isn't a resource. A route to a controller *alias* is therefore `anonymous` (with that evidence); a route to a controller registered nowhere the analyzer saw is `unknown`.
  - A `:controller` route (`/s/:site-slug/:controller`) is decided over every controller and alias under its `__NAMESPACE__`: `anonymous` or `required` only if all agree. Decisions are memoised per (controller, action) and per (namespace, action), with rules indexed by resource and privilege.
  - **Install and migration.** AclFactory's zero-argument `allow()` grants everything while Omeka isn't installed or needs a migration, when MvcListeners sends every request to `/install` or `/migrate`. Those controllers are never `required`: `unknown`, with a note.
  - ACL decisions are only made in a repo with Omeka markers or ACL rules.
- **API key auth.** Routes whose defaults set `'__KEYAUTH__' => true` (Omeka's `/api`) accept `key_identity`/`key_credential` query parameters (`MvcListeners::authenticateApiKey`). Their `guard_evidence` says so, and a `protocol:omeka_api_key` `ProtocolHint` is emitted for the route file and for code that reads the parameters (`getQuery('key_identity')`). API keys are optional: `/api` is `anonymous` at the controller level (`allow(null, 'Omeka\Controller\Api')`), and the API adapters' own ACL decides per resource.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-omeka-s.git
```

## Usage with AttackMap

```bash
attackmap analyze /path/to/repo --module omeka-s
```
