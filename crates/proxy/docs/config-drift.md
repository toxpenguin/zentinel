# Config drift detection

Answers one question loudly: **is the config file on disk the same one the
proxy is actually running?** Kills the classic "edited the file, forgot to
reload" incident — the config looks right on disk, but the process is still
serving the old one.

## How it works

The proxy fingerprints every configuration it loads **from disk** (startup and
file reload) as a hex SHA-256 over the config's canonical JSON — see
`crate::config_fingerprint`. The fingerprint and its wall-clock load time are
exposed on the builtin `/config` admin endpoint:

```json
{
  "content_hash": "9f2c…",
  "loaded_at": "2026-07-25T12:34:56+00:00",
  "config": { ... }
}
```

`content_hash` is a hash only — no config content or secrets are leaked by it
(the `config` block itself remains redacted as before).

The CLI hashes the on-disk file through the identical `Config::from_file`
pipeline and compares:

```bash
zentinel validate --config zentinel.kdl \
    --against-running http://127.0.0.1:9090/-/config
```

Pass the full URL of the proxy's builtin `/config` admin endpoint.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | In sync — the running proxy is serving this file |
| 2 | **Drift** — on-disk file differs from what the proxy loaded (reload needed) |
| 1 | Could not reach the admin endpoint / parse its response |

The distinct codes let CI gate on drift (2) separately from an unreachable
proxy (1).

## Semantics (what the hash does and does not cover)

- **Fingerprints the last config loaded from disk**, not the live in-memory
  config. Runtime mutation — e.g. the Gateway API controller pushing
  Kubernetes-translated config via `apply_config` — deliberately does **not**
  move the fingerprint, because there is no file to reconcile it against. Drift
  detection targets file-driven deployments.
- **Covers the effective config** — post environment-variable substitution and
  post `include` merge. So if the proxy's runtime environment differs from the
  shell running `validate` (different `${VAR}` values), that is *real* drift and
  is reported as such.
- **Order-sensitive for lists** (routes, listeners): reordering routes can
  change priority and therefore behavior, so it changes the hash. It is
  **order-insensitive for maps** (`upstreams`, `filters` are `HashMap`s), whose
  iteration order carries no meaning.
