# Validation & Defaults

This document describes configuration validation rules and default values.

## Validation Process

Configuration validation occurs in multiple stages:

1. **Parse-time validation**: Syntax and type checking
2. **Schema validation**: Required fields, value constraints
3. **Semantic validation**: Cross-references, logical consistency
4. **Runtime validation**: File existence, network addresses

## Schema Version Compatibility

```kdl
schema-version "1.0"
```

| Config Version | Binary Support | Behavior |
|----------------|----------------|----------|
| < min supported | Not loadable | Error |
| = current | Full support | Exact match |
| > current | Loadable | Warning (may lack features) |

Current version: `1.0`
Minimum supported: `1.0`

## Validation Rules

### Server

| Property | Validation |
|----------|------------|
| `worker-threads` | `>= 0` (0 = auto-detect) |
| `max-connections` | `> 0` |
| `graceful-shutdown-timeout-secs` | `> 0` |
| `trace-id-format` | Must be `tinyflake` or `uuid` |

### Listeners

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `address` | Valid socket address (host:port) |
| `protocol` | Must be `http`, `https`, `h2`, or `h3` |
| `tls` | Required when protocol is `https` |
| `request-timeout-secs` | `> 0` |

**At least one listener is required.**

### Routes

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `matches` | At least one match condition |
| `upstream` | Must reference existing upstream (unless builtin/static) |
| `filters` | All filter IDs must exist |
| `builtin-handler` | Required when `service-type` is `builtin` |
| `static-files.root` | Required when `service-type` is `static` |

### Upstreams

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `targets` | At least one target required |
| `targets[].address` | Valid host:port format |
| `targets[].weight` | `> 0` |
| `health-check.interval-secs` | `> 0` |
| `health-check.timeout-secs` | `> 0`, `< interval-secs` |

### Filters

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `type` | Valid filter type |
| `rate-limit.max-rps` | `> 0` |
| `compress.algorithms` | At least one algorithm |
| `geo.database-path` | Non-empty |
| `geo.countries` | Valid ISO 3166-1 alpha-2 codes |
| `agent.agent` | Must reference existing agent |

### Agents

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `timeout-ms` | `> 0` |
| `chunk-timeout-ms` | `> 0` |
| `max-request-body-bytes` | `> 0` when set (omit for the 1 MiB default) |
| `max-response-body-bytes` | `> 0` when set (omit for the 1 MiB default) |
| `transport.unix-socket` | Parent directory must exist |
| `transport.grpc.address` | Valid address format |
| `events` | At least one event |

### WAF

| Property | Validation |
|----------|------------|
| `engine` | Must be `modsecurity`, `coraza`, or `custom` |
| `mode` | Must be `off`, `detection`, or `prevention` |
| `ruleset.paranoia-level` | `1-4` |
| `body-inspection.max-decompression-ratio` | `> 0` |

### Observability

| Property | Validation |
|----------|------------|
| `metrics.address` | Valid socket address |
| `tracing.sampling-rate` | `0.0-1.0` |
| `logging.level` | Valid log level |

### Limits

| Property | Validation |
|----------|------------|
| `max-header-size-bytes` | `> 0` |
| `max-header-count` | `> 0` |
| `max-body-size-bytes` | `> 0` |

## Reference Integrity

The validator ensures all cross-references are valid:

```
Route → Upstream      ✓ Upstream must exist
Route → Filter        ✓ Filter must exist
Filter → Agent        ✓ Agent must exist
Listener → Route      ✓ Default route must exist
```

Invalid references produce clear error messages:

```
Configuration validation failed:
  Route 'api' references non-existent upstream 'backend'
```

## Default Values

### Server Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `worker-threads` | `0` | Auto-detect CPU cores for optimal performance |
| `max-connections` | `10000` | Reasonable for most deployments |
| `graceful-shutdown-timeout-secs` | `30` | Allow in-flight requests to complete |
| `daemon` | `false` | Prefer systemd/container orchestration |
| `trace-id-format` | `tinyflake` | Compact, operator-friendly IDs |
| `auto-reload` | `false` | Explicit reload preferred in production |

### Listener Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `request-timeout-secs` | `60` | Standard HTTP timeout |
| `keepalive-timeout-secs` | `75` | Slightly longer than typical client |
| `max-concurrent-streams` | `100` | Reasonable HTTP/2 limit |

### TLS Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `min-version` | `tls1.2` | Security baseline |
| `client-auth` | `false` | mTLS opt-in |
| `ocsp-stapling` | `true` | Better client experience |
| `session-resumption` | `true` | Performance optimization |

### Route Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `priority` | `normal` | Standard priority |
| `service-type` | `web` | Traditional web proxy |
| `failure-mode` | `closed` | Security-first (fail-closed) |
| `waf-enabled` | `false` | WAF opt-in |
| `websocket` | `false` | WebSocket opt-in |

### Upstream Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `load-balancing` | `round-robin` | Simple, fair distribution |
| `targets[].weight` | `1` | Equal weight by default |
| `connection-pool.max-connections` | `100` | Reasonable pool size |
| `connection-pool.max-idle` | `20` | Balance memory vs latency |
| `connection-pool.idle-timeout-secs` | `60` | Reclaim idle connections |
| `timeouts.connect-secs` | `10` | Reasonable connect timeout |
| `timeouts.request-secs` | `60` | Standard request timeout |
| `timeouts.read-secs` | `30` | Balance responsiveness |
| `timeouts.write-secs` | `30` | Balance responsiveness |

### Health Check Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `interval-secs` | `10` | Balance responsiveness vs overhead |
| `timeout-secs` | `5` | Quick failure detection |
| `healthy-threshold` | `2` | Require consistent health |
| `unhealthy-threshold` | `3` | Tolerate transient failures |

### Filter Defaults

#### rate-limit

| Property | Default | Rationale |
|----------|---------|-----------|
| `burst` | `10` | Allow small bursts |
| `key` | `client-ip` | Per-client limiting |
| `on-limit` | `reject` | Clear feedback to client |
| `status-code` | `429` | Standard rate limit status |
| `backend` | `local` | Simple single-instance |

#### compress

| Property | Default | Rationale |
|----------|---------|-----------|
| `algorithms` | `["gzip", "brotli"]` | Wide client support |
| `min-size` | `1024` | Don't compress tiny responses |
| `level` | `6` | Balance ratio vs CPU |

#### cors

| Property | Default | Rationale |
|----------|---------|-----------|
| `allowed-origins` | `["*"]` | Permissive default |
| `allow-credentials` | `false` | Security default |
| `max-age-secs` | `86400` | Cache preflight 24h |

#### geo

| Property | Default | Rationale |
|----------|---------|-----------|
| `action` | `block` | Blocklist mode |
| `on-failure` | `open` | Fail-open on lookup error |
| `status-code` | `403` | Standard forbidden |
| `cache-ttl-secs` | `3600` | Cache lookups 1h |

### Agent Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `timeout-ms` | `1000` | 1 second timeout |
| `failure-mode` | `closed` | Security-first |
| `request-body-mode` | `buffer` | Simpler agent implementation |
| `chunk-timeout-ms` | `5000` | Per-chunk timeout |
| `max-concurrent-calls` | `100` | Prevent agent overload |

### WAF Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `mode` | `prevention` | Active blocking |
| `audit-log` | `true` | Security visibility |
| `ruleset.paranoia-level` | `1` | Low false positives |
| `ruleset.anomaly-threshold` | `5` | Standard CRS threshold |
| `body-inspection.inspect-request-body` | `true` | Inspect requests |
| `body-inspection.inspect-response-body` | `false` | Response inspection opt-in |
| `body-inspection.max-inspection-bytes` | `1048576` | 1MB inspection limit |

### Observability Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `metrics.enabled` | `true` | Observability by default |
| `metrics.address` | `0.0.0.0:9090` | Standard metrics port |
| `metrics.path` | `/metrics` | Standard Prometheus path |
| `logging.level` | `info` | Balanced verbosity |
| `logging.format` | `json` | Structured logging |
| `tracing.sampling-rate` | `0.01` | 1% sampling |
| `access-log.sample-rate` | `1.0` | Log all requests |

### Limits Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `max-header-size-bytes` | `8192` | 8KB header limit |
| `max-header-count` | `100` | Reasonable header count |
| `max-body-size-bytes` | `1048576` | 1MB body limit |
| `max-connections-per-client` | `100` | Per-client limit |

### Cache Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `enabled` | `true` | Caching when configured |
| `backend` | `memory` | Simple in-memory cache |
| `max-size-bytes` | `104857600` | 100MB cache |
| `lock-timeout-secs` | `10` | Prevent thundering herd |
| `disk-shards` | `16` | Concurrent disk access |

## Security Defaults

Zentinel follows a **security-first** design philosophy:

| Setting | Default | Security Impact |
|---------|---------|-----------------|
| `failure-mode` | `closed` | Block on failure (not fail-open) |
| `tls.min-version` | `tls1.2` | No legacy TLS |
| `waf-enabled` | `false` | WAF must be explicitly enabled |
| `agent.timeout-ms` | `1000` | Bounded agent calls |
| `limits.*` | Bounded | Prevent resource exhaustion |

## Validation Error Messages

Error messages include context for debugging:

```
Configuration validation failed:

  Route 'api' references non-existent upstream 'backend'

  Available upstreams: ["web-backend", "api-backend"]
```

```
Configuration validation failed:

  Filter 'auth' references non-existent agent 'auth-agent'

  Available agents: ["waf-agent"]
```

```
KDL configuration parse error:

  Expected closing brace

  --> at line 15, column 1
   14 | upstream "backend" {
   15 |     target "127.0.0.1:3000"
      | ^ expected '}'
   16 | }
```

## Dry-Run Validation

Validate configuration without starting the proxy:

```bash
zentinel --config zentinel.kdl --validate
```

Or programmatically:

```rust
let config = Config::from_file("zentinel.kdl")?;
config.validate()?;
println!("Configuration is valid");
```

## Lint Rules (best practices)

`zentinel lint --config zentinel.kdl` runs advisory best-practice checks over a
schema-valid config. Lint always exits `0` — warnings are recommendations, not
errors. Rules live in `crates/config/src/validate/lint.rs`.

Existing rules warn on: missing retry policy, missing route timeout, missing
upstream, missing/single-target health checks, HTTP on `:80` without TLS,
missing HSTS when TLS is enabled, and disabled metrics/access logs.

Additional rules:

### Unreachable route

Warns when a route can never match because a **strictly-higher-priority** route
is evaluated first and matches a superset of its requests (e.g. a
`priority "high"` `path-prefix "/"` catch-all placed above specific routes).

Conservative by design: it only warns when shadowing is *provable* and bails on
anything it cannot prove (regex conditions, host widening, an unconstrained
lower route). It never emits a false positive, and it detects only
strictly-higher-priority shadowing — equal-priority shadowing decided by
specificity tie-breaks is intentionally not flagged, so "no warning" is not a
guarantee that no route is shadowed.

### Agent filter without an explicit failure-mode

Warns when a route references an agent filter that declares no `failure-mode`.
On agent failure such a filter silently inherits the route's `failure-mode`,
which is an implied policy — set it explicitly on the filter.

### Shadow traffic to a production upstream

Warns when a route's `shadow` block mirrors traffic to an upstream that also
serves live traffic as some route's primary target (including the route's own).
Mirrored requests reaching production can cause duplicate side effects; use a
dedicated shadow upstream.

> Not viable as specified: the classic **timeout-inversion** rule (route timeout
> shorter than the upstream *connect* timeout) does not apply here. A route's
> `timeout-secs` is applied at runtime to the upstream **read** timeout
> (`peer.options.read_timeout` in `crates/proxy/src/proxy/http_trait.rs`) — a
> post-connect, per-response phase that is orthogonal to the connect timeout. A
> read timeout shorter than the connect timeout is normal (fast-read routes on a
> slow-connect backend), not an inversion, so such a rule would fire on
> perfectly sensible configs (e.g. `config/examples/api-gateway.kdl`).
>
> The **agent-timeout half** (agent timeout ≥ route timeout) is also **not
> viable as specified** — but for a phase reason, not an enforcement one. Route
> `timeout-secs` is a read-phase timeout (above) while an agent call is a
> separate, earlier phase, so "agent ≥ route" is not a same-budget inversion.
> (Agent `timeout-ms` and the `pool { }` block **are** enforced — see the
> correction below.)
>
> Not planned: a **weak-cipher / weak-TLS-minimum** rule. `TlsConfig.cipher_suites`
> is already flagged a **runtime no-op** by semantic validation — Pingora's TLS
> layer ignores custom cipher lists and uses secure rustls defaults — so a
> per-cipher warning would imply a weak suite is active when it is not. And
> `TlsVersion` admits only `TLS1.2`/`TLS1.3`, so a sub-1.2 minimum cannot be
> represented in the first place.
>
> **Correction (5a audit) — agent timeouts ARE enforced.** An earlier note here
> claimed the agent `timeout-ms` / `chunk-timeout-ms` / `pool { }` settings had
> "no runtime consumers" and drafted a no-op warning for them. **That was wrong**
> and was reverted before shipping. The mistake was methodology: a grep narrowed
> with `| grep -iE "agent"` dropped the wiring lines (which read `config.timeout_ms`
> / `p.connect_timeout_ms`, containing no "agent" token), and a code-graph search
> was capped and run against a stale branch. `crates/proxy/src/agents/agent_v2.rs`
> converts the config `pool { }` block into the runtime pool config
> (`connect_timeout ← connect_timeout_ms`, `request_timeout ← timeout_ms`,
> `drain_timeout ← drain_timeout_ms`, plus reconnect/max/health fields), and
> `manager.rs` wraps every agent call in `Duration::from_millis(agent.timeout_ms())`.
> So these fields **take effect**; no warning is warranted. Only `chunk-timeout-ms`
> is unconfirmed (not part of that conversion) and would need its own trace before
> any claim. Lesson for a future generic "unenforced-field" lint: prove
> unenforcement with an unfiltered data-flow trace on the shipping branch — a
> narrowed grep is not proof.

## Semantic Diff

`zentinel diff <old> <new>` reports the **behavioral** delta between two
configs — not a textual diff. It answers "what does this config change actually
*do*?" so an operator or CI can gate a deploy on the blast radius. Rules live in
`crates/config/src/validate/diff.rs`.

Each delta is `High` (gates CI — silently breaks traffic or removes a security
control) or `Advisory` (review recommended). Output is a human table or `--json`
(stdout; logs go to stderr). **Exit codes:** `0` clean, `1` load/parse error,
`2` a high-severity change is present.

Detected deltas include:

- **Routes** — added / removed / **became unreachable** (reusing the linter's
  shadowing analysis) / primary upstream changed / **failure-mode flip** (High,
  with direction) / timeout changed / match conditions changed / priority
  changed / filter chain changed (removing an agent filter is High).
- **Upstreams** — added / removed / target set / load-balancing / health check.
- **Listeners** — added / removed / TLS added-or-removed / **TLS minimum
  lowered** / client-auth toggled / address / default-route.
- **Agents** — added / removed / **failure-mode flip** (with direction) /
  transport / type / timeout.
- **Filters** — added / removed / type change / agent-filter failure-mode flip.

**Semantics:**

- Entities match across configs by **id**; a rename reads as remove + add.
- Equality is behavioral, not textual: a route's *match conditions* compare as a
  set (reordering them — and reordering/​re-casing a `method` list — is no delta),
  while a route's *filter chain* compares in order (execution order is
  load-bearing).
- "Became unreachable" inherits the linter's blind spot: only
  strictly-higher-priority shadowing is detected.
- Route-level `failure-mode`/`timeout-secs` are compared; other `policies`
  fields (`rate-limit`, buffering, `max-body-size`) are not yet parsed from KDL,
  so they are not compared.
