# `zentinel explain` — request decision trace

`zentinel explain` answers "if this request arrived, what would the proxy do
with it?" — without starting a listener or making any network call. It is a
pure, read-only dry run over the same routing engine the running proxy uses.

It exists to serve the Manifesto's second principle — *security must be
explicit; every decision visible and traceable*.

## Usage

```bash
zentinel explain --config zentinel.kdl \
    --method GET --path /api/users --header host=example.com
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-c, --config <path>` | embedded default | Config to evaluate against |
| `-m, --method <verb>` | `GET` | HTTP method (matched case-insensitively — upper-cased) |
| `-p, --path <path>` | `/` | Request path |
| `--host <host>` | (empty) | Host header value; overrides a `host=` entry in `--header` |
| `--header name=value` | — | Extra header for header-based conditions (repeatable) |
| `--json` | off | Emit machine-readable JSON instead of text |

Logs go to **stderr**; the report goes to **stdout**, so `--json` output pipes
cleanly. Exit code is `0` on a match and `1` on no match (script-gateable).

## What it reports

1. **Matched route** — id, priority, specificity, and *what it beat* (other
   routes that also matched but lost on priority/specificity).
2. **Filter/agent chain** — filters in declared execution order, each with its
   type and phase (`request` / `response` / `both`); agent filters are flagged.
   A referenced-but-undefined filter id is called out (it is silently skipped at
   runtime).
3. **Effective timeout** — the route-level override if set, otherwise the
   per-listener `request-timeout-secs` fallback (all listeners are shown, since
   explain is not bound to one).
4. **Failure mode** — `open` or `closed`.
5. **Upstream selection** — pool name, load-balancing algorithm, target count;
   or `(none)` for static / built-in routes.

## Example

```
Request: GET /api/private/orders  (host: example.com)

Matched route: "private-api"  [priority 100, specificity 1022]
  Beat: (no other route matched)
  Filters (in declared order):
    1. public-cors          cors         [both]
    2. auth                 agent        [request]  <- agent
  WAF: disabled
  Effective timeout: per-listener request-timeout — http=60s
  Failure mode: closed
  Upstream: "api"  [RoundRobin, 1 target(s)]
```

On no match, explain lists every route evaluated and the first condition that
rejected it:

```
No route matched.
  Evaluated 4 route(s):
    - "health" [priority 1000]  rejected: path == '/health' did not match
    - "private-api" [priority 100]  rejected: method in [GET] did not match
    ...
  (note: listener-scoped default routes are not evaluated by explain)
```

## Fidelity notes

- explain mirrors the **global** route matcher — the one used for requests not
  scoped to a namespace listener. Listener-scoped default routes are not
  applied; a request matching no global route is reported as no-match even if a
  listener would fall back to a default. This is stated in the output so nothing
  is silently implied.
- explain reports the **parsed** configuration exactly as the proxy sees it, so
  it also surfaces fields a config format does not carry. The KDL parser honors
  a route's `policies { timeout-secs … failure-mode … }`, but not the remaining
  policy fields (`rate-limit`, request/response buffering, `max-body-size`) —
  explain shows their defaults for KDL configs.
- explain mirrors production's request construction: the router matches against
  the **query-stripped** path (`uri.path()`) and evaluates `query-param`
  conditions from `uri.query()`. A `--path` with a `?query` therefore routes
  exactly as the running proxy would, query-param matches included.

## Implementation

- `RouteMatcher::explain_request` (`src/routing.rs`) evaluates every route
  (never short-circuits, never touches the route cache) and returns an
  `ExplainTrace`. Its winner is guaranteed identical to `match_request`.
- `src/explain.rs` resolves the winner's filter/agent chain, timeout, failure
  mode, and upstream from the config and renders text or JSON.
