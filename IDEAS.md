# Ideas

Backlog of candidate improvements, grounded in the current codebase (indexed 2026-07-24).
Each idea should still pass the Manifesto gate: no ambiguity, fails loudly, doesn't make on-call worse.

## Explainability

### 1. `zentinel explain` — decision trace for a synthetic request
Given a config and a request description (`zentinel explain --config zentinel.kdl --method GET --path /api/users --header host=example.com`), print the full decision path: which route matched and why (priority, what it beat), which filters/agents would fire in order, effective timeouts, failure modes, and upstream selection policy. Pure dry-run over the existing routing engine — no listener needed.
- Directly serves "Security must be explicit — every decision visible and traceable."
- Reuses `crates/proxy` routing + `crates/config`; no new runtime surface.
- Synergy with #5: compile the same engine into `playground-wasm` for a browser route-match simulator.

### 2. Semantic config diff — `zentinel diff old.kdl new.kdl`
Not a text diff: report *behavioral* deltas (routes added/removed/shadowed, timeout changes, failure-mode flips, TLS policy changes, agent wiring changes). Output human table + JSON for CI. Ops can gate deploys on "this change only touches route X".
- Complements existing `test`/`validate`/`lint` subcommands.
- Natural CI gate: fail PRs whose config delta includes severity=high changes (e.g., failure-mode open→closed).

## Security hardening

### 3. Fuzzing targets — ✅ done
Five `cargo-fuzz` targets in the excluded `fuzz/` workspace: `kdl_config`
(`Config::from_kdl`), `agent_request_headers`/`agent_body_chunk`/`agent_response`
(v2 binary frame decoders), `proxy_protocol` (HAProxy v1/v2 header parse +
round-trip). Nightly bounded-time CI in `.github/workflows/fuzz.yml` (03:00 UTC),
KDL corpus seeded from `config/examples/*.kdl`. Remaining candidate if hot-path
normalization ever grows custom parsing: header/path normalization target.

### 4. Supply-chain: SBOM + cargo-vet in release — ✅ done
SBOM turned out to be already shipped: cargo-sbom (CycloneDX 1.5 + SPDX 2.3) in
`_build.yml` attached to GitHub Releases, container SBOM via syft + cosign attest
in `_docker.yml`. Remaining gap closed 2026-08-09: release-blocking `cargo audit`
job in `release.yml` gating `publish-crates` (nothing publishes on a failed
audit); accepted-risk ignores live in `.cargo/audit.toml` with justifications;
weekly `audit.yml` stays advisory (opens issues). `cargo vet` declined:
per-dependency audit curation is ongoing overhead with little marginal value on
top of the RustSec gate + SBOM + cosign signing + SLSA provenance.

## Config quality

### 5. New lint rules (lint infra exists in `crates/config/src/validate`)
Candidate rules — status after investigation (2026-07-25):
- **Unreachable route**: route can never match because a higher-priority route fully shadows its matcher set. — ✅ done (`check_unreachable_routes`).
- **Agent without failure-mode**: agent referenced on a route with no explicit open/closed policy. — ✅ done (`check_agent_filter_failure_modes`).
- **Timeout inversion**: route timeout shorter than upstream connect timeout, or agent timeout ≥ route timeout. — ❌ **both halves not viable as specified**. Route-vs-connect: route `timeout-secs` maps to the upstream *read* timeout (`peer.options.read_timeout`), orthogonal to connect — read < connect is normal (would cry-wolf on `config/examples/api-gateway.kdl`). Agent-vs-route: route `timeout-secs` is read-phase while an agent call is a separate, earlier phase, so "agent ≥ route" isn't a same-budget inversion. (Agent `timeout-ms` and the whole `pool { }` block **are** enforced — see the 5a correction below — so this half fails on the phase mismatch, not on enforcement.)
- **TLS listener without minimum version / weak cipher config.** — ❌ not planned: `TlsVersion` admits only TLS1.2/1.3 (sub-1.2 unrepresentable), and `cipher_suites` is already flagged a runtime no-op by semantic validation (Pingora ignores custom lists), so a per-cipher warning would mislead.
- **Shadow traffic to production upstream**: `ShadowConfig` target overlaps a primary upstream pool. — ✅ done (`check_shadow_upstreams`).
> Net: the three tractable rules already exist; the two remaining candidates are not viable as specified. No new code — see `crates/config/docs/validation.md` § "Lint Rules". Details in each bullet above.
> **Follow-up (5a) — "configured-but-unenforced field" lint — ❌ premise was FALSE for agent fields; correction.** An audit initially concluded the agent `timeout-ms`, `chunk-timeout-ms` and the `pool { }` block were parsed but unenforced, and a warning was drafted. **That was wrong** and was reverted before shipping. The error: a `grep … | grep -iE "agent"` sweep silently dropped the wiring lines (which read `config.timeout_ms` / `p.connect_timeout_ms`, no "agent" token), and a code-graph literal search was capped at 30 results on a stale `main` branch. An unfiltered branch-correct grep found the truth: **`crates/proxy/src/agents/agent_v2.rs:63-79` converts the config `pool { }` block into the runtime `ProtocolPoolConfig`** (`connect_timeout ← connect_timeout_ms`, `request_timeout ← timeout_ms`, `drain_timeout ← drain_timeout_ms`, plus reconnect/max/health fields), and **`manager.rs` wraps every agent call in `Duration::from_millis(agent.timeout_ms())`**. So agent `timeout-ms` and the pool block **are enforced** — no warning is warranted. Only `chunk-timeout-ms` is *unconfirmed* (not mapped in that conversion); it needs verification, not an assertion. Lesson: an empty/narrowed grep is not proof of unenforcement — trace the real data flow, unfiltered, on the shipping branch.
Each rule = one explicit, explainable warning; fits the existing `lint` subcommand and playground `LintWarning` surface.

## Agent ecosystem

### 6. Official agent SDKs (Go first, then Python) — 🚧 Go shipped, Python pending
Go SDK: `sdk/go` (`github.com/zentinelproxy/zentinel/sdk/go`, zero deps) —
v2 UDS framing, handshake + capability negotiation from implemented optional
interfaces, correlation-ID response routing, ping/pong, graceful shutdown.
Agents implement `OnRequestHeaders` and optionally body/response/complete
interfaces; wire shapes golden-tested against serde output. CI job `go-sdk`
(gofmt + vet + test), plus a live-proxy smoke test in tests.yml (real
zentinel binary ↔ Go agent over UDS). Conformance badge: `zentinel agent
conform --socket <path>` (`v2::conformance` in agent-protocol, 6 checks,
`--json` for CI) — the Go example agent passes zentinel-conformance v1 in
tests.yml; the harness also caught the Rust reference server accepting
unknown protocol versions (fixed in `on_handshake` default). Note:
`conformance/` is Gateway API conformance, not agent-wire (the original
premise was wrong). Python SDK: `sdk/python` (`zentinel-agent`, stdlib-only
asyncio, Python 3.10+) — subclass `Agent`, override events; overridden
methods auto-advertised; example agent passes zentinel-conformance v1
(gated in tests.yml, unit tests in ci.yml `python-sdk`). **#6 done** except
deferred transports: gRPC + reverse-connection (YAGNI until a cross-host
agent user shows up).

### 7. Agent starter template repo / `zentinel agent new` — ✅ done
Scaffold generator producing a minimal agent (echo-style, from `agents/echo/`) with Dockerfile, conformance test wiring, and KDL snippet to register it. Lowers the barrier from "read the protocol docs" to "edit one function".
- Implemented as `zentinel agent new <name>` (`crates/proxy/src/agent_scaffold.rs`): generates a self-contained crate (Cargo.toml with published `zentinel-agent-protocol` dep, `src/main.rs` = one `on_request_headers` to edit, `zentinel-agent.toml`, Dockerfile, README with UDS+gRPC KDL register snippets, `.gitignore`). Dual-transport binary (`--socket`/`--grpc`); overwrite-guarded; name-validated. Deps verified to resolve against crates.io (0.6.22).

## Operations

### 8. Runtime config drift check
Admin API already exists (`/api/admin`). Expose loaded-config content hash + load timestamp; add `zentinel validate --against-running <admin-addr>` that compares on-disk config to what the proxy actually runs. Kills the classic "edited the file, forgot to reload" incident class. Calm infrastructure.

### 9. Chaos suite: resource-bound assertions — ✅ done
`tests/chaos/scenarios/resilience/test_resource_bounds.sh` (wired: Makefile
`test-resource-bounds`, runner scenario `resource-bounds`): slow-loris agent
(frozen, never answers), agent endpoint vanishing mid-flight (UDS-delete
analog), restart storm under concurrent load — asserting peak-fd and memory
ceilings against a warmed baseline plus post-fault reclamation, not just
correct request failure. "Bounded by design" is now chaos-verified.

### 10. Benchmark regression gate in CI — ✅ done
`bench.yml` + `scripts/bench-gate.py`: PR merge-base and head benched
back-to-back on the same runner (no stored baseline — cross-runner CPU variance
made that flaky by construction), hard-fail at +20%. Gated: agent-protocol
`full_request_path/json_path` and proxy `route_match/{cache_hit,cache_miss}`
(`crates/proxy/benches/routing.rs` — 50-route table, LRU steady state + full
evaluation). Per-crate path scoping; gate-only PRs bench both; out-of-scope
benches report as skipped.

## Hosting-stack compatibility (Apache, CloudLinux, Imunify360, control panels)

Target: Zentinel as the edge in front of classic shared-hosting stacks (Apache/LiteSpeed on cPanel/Plesk/DirectAdmin, CloudLinux, Imunify360). Core stays small — panel/vendor specifics live in importers, agents, and deployment recipes, per the Manifesto.

### 11. Apache/nginx config importer — `zentinel import apache httpd.conf`
Generate KDL from existing `VirtualHost`/`server` blocks: domains → routes (SNI + Host matching, which Zentinel already supports), `ProxyPass`/`proxy_pass` → upstreams, TLS cert paths → listener config. Directives that don't map (rewrite rules, .htaccess semantics) are *listed explicitly* as "stays on the backend" — no silent drops. Biggest single adoption lever for the hosting world: migration becomes a review of generated config instead of a rewrite.

### 12. PROXY protocol v1/v2 (inbound + outbound) — missing today
- **Outbound to backends**: Apache `mod_remoteip`, LiteSpeed, and Imunify360's greylisting/captcha all key on real client IP. Without PROXY protocol (or trusted XFF), every visitor looks like the proxy and IP-based security behind Zentinel breaks or, worse, blocks everyone.
- **Inbound**: accept PROXY protocol from an upstream LB so Zentinel itself sees real IPs.
Codebase has `ClientIp.forwarded_for` but no PROXY protocol support. This is the prerequisite for the whole compat story — do it first.
- **Status (✅ datapath done, pending fork push):** codec in `zentinel-common::proxy_protocol` (encode/decode, fuzzed). Fork hooks landed on `zentinelproxy/pingora` branch `proxy-protocol-hooks` (`AcceptPreprocessor` pre-TLS accept hook + `PeerOptions.connect_prefix` with reuse-hash isolation). Zentinel wiring: inbound `ProxyProtocolAcceptor` (trusted-CIDR fail-closed, exact-byte reads, peer rewrite feeding logs/rate-limit/geo) + outbound `connect_prefix` emit per upstream (`proxy-protocol "v1"|"v2"`), KDL config on listener and upstream. Operator surface: `explain` shows upstream emission, `lint` warns on trust-all CIDRs. Conformance: `proxy_protocol_e2e_test.rs` asserts LB→Zentinel→backend real-IP propagation + spoof rejection over real sockets (the #16 prerequisite). **#12 complete.**

### 13. ModSecurity-compatible WAF agent (Coraza-based) — ✅ done
`agents/coraza-waf/` — Go agent built on the SDK (#6) embedding
[Coraza](https://coraza.io). Loads SecLang files or directories (OWASP CRS,
Comodo, Imunify360 exports); refuses to start with no rules, a missing path, or
an empty rule directory. Phases 1–5 map onto the v2 events, with phase 2
evaluated at request-headers time whenever no body will arrive so ARGS rules
always fire. Audit records are ModSecurity-native (`SecAuditLogFormat Native` +
serial writer) for existing SIEM/fail2ban pipelines, and each decision carries
matched rule IDs/tags back to the proxy. Bounded by construction: capped
transaction table that never evicts in-flight work (explicit `--overflow
allow|block`), TTL sweeper, body limits with `ProcessPartial`. `--mode
detection` for false-positive tuning; block responses hide the rule ID unless
`--expose-rule-id`. Verified by unit tests, a live-proxy test (SQLi gets 403,
upstream never reached, block appears in the audit log), and
`zentinel agent conform` — all three in CI.
Not covered (deliberately): CRS is not vendored (operators point `--rules` at
the copy they already run), and there is no per-tenant rule scoping yet — that
wants #14's domain→account mapping.

### 14. Control-panel sync tool (cPanel/WHM first; Plesk, DirectAdmin later)
Sidecar (not core) that watches panel account/domain state — e.g. cPanel's `/etc/userdatadomains` or WHM API — and regenerates per-domain routes + upstreams, then triggers the existing graceful reload. Domains added in the panel appear at the edge without manual config. Explicit failure mode: if generation fails validation, keep last-good config and alert — never partially apply.

### 15. Per-tenant rate limiting aligned with CloudLinux LVE
CloudLinux isolates tenants at the kernel level (LVE) *after* the request hits Apache. Zentinel can enforce the same tenancy boundary earlier: rate-limit/concurrency keys derived from the mapped account (via #14's domain→user mapping), so one tenant's traffic spike is shed at the edge instead of consuming Apache slots and LVE budget. Bounded per-tenant, explicit limits in KDL — very on-manifesto.

### 16. Imunify360 coexistence recipe + conformance scenario — ✅ done (recipe + CI conformance)
Recipe: `crates/proxy/docs/imunify360.md` + validated example
`config/examples/imunify360-apache.kdl` — upstream `proxy-protocol "v2"` →
Apache `mod_remoteip RemoteIPProxyProtocol On`, so greylisting/captcha/
blocklists/ModSecurity see real client IPs; ACME HTTP-01 passthrough route for
cPanel AutoSSL; WebSocket routes with long timeouts. Conformance:
`proxy_protocol_e2e_test.rs` CI-asserts the propagation chain + spoof
rejection. Not covered here (deliberately): AutoSSL cert reuse at the edge
(#18), LVE-aligned per-tenant limits (#15), live Apache+Imunify soak (needs
licensed Imunify test box — manual verification steps in the doc).

### 17. Named backend profiles for common stacks — ✅ done
`profile "<name>"` on an upstream (`crates/config/src/profiles.rs`), shipping
`apache-shared-hosting`, `litespeed`, and `php-fpm-behind-apache`. Resolution is
per setting — explicit value > profile > built-in default — and what the profile
contributed is recorded at parse time, so `zentinel explain` prints the full
expansion (`Profile: "apache-shared-hosting" — contributed
connection-pool.idle-timeout=3s, …`) instead of hiding it. `zentinel lint` flags
an upstream that names a profile but overrides every setting it provides;
unknown names are a hard config error listing the valid ones. The Apache
profiles key on recycling pooled connections *before* the backend's
`KeepAliveTimeout` expires, which is the actual fix for graceful-restart 502s.
Used in `config/examples/imunify360-apache.kdl`.
Not covered (deliberately): retries stay a route-level setting, so no profile
touches them; profiles tune `timeouts` and `connection-pool` only, and set no
TLS/HTTP-version/health-check values.

### 18. cPanel/WHM AutoSSL certificate integration — ✅ done
All three gaps closed. **Combined PEM**: `combined-file` on a `tls` block and on
an `sni` block (cPanel's `/var/cpanel/ssl/apache_tls/<domain>/combined`).
**Directory-watch SNI**: `sni-cert-dir "<path>"` scans one subdirectory per
domain, taking hostnames from each certificate's CN/SAN, so a domain the panel
issued for is served after a reload with no config edit (rescan is on reload,
not inotify). A missing directory is a startup error; an empty one warns;
unrelated subdirectories are skipped. **DCV passthrough**: two lint rules — a
listener with panel-managed certs and no route covering
`/.well-known/pki-validation/` or `/.well-known/acme-challenge/`, and a route
serving those paths that runs filters or has the WAF on. Example:
`config/examples/cpanel-autossl.kdl`; recipe section in
`crates/proxy/docs/imunify360.md`.
Design note found while testing: panel certificate stores routinely share a SAN
across certificates (the server hostname on every cert), and a *discovered*
certificate has no config entry to annotate with
`hostnames`/`priority-hostnames`. Overlaps between discovered certificates
therefore resolve to the first in path order (deterministic, logged) instead of
the hard "ambiguous SNI" error, which would have made the feature unusable on a
real box. Explicit `sni` entries still win over discovered ones.

<details>
<summary>Original entry</summary>

### 18. cPanel/WHM AutoSSL certificate integration
Terminate TLS at Zentinel using the certs cPanel AutoSSL already issues, keeping the panel as certificate source-of-truth (users keep their SSL UI). Building blocks exist: `SniCertificate` (per-domain cert/key, SAN auto-extraction) + `CertificateReloader` hot reload — AutoSSL *renewals* rewrite files in place and are picked up without restart. Three gaps to close:
- **Combined-PEM support**: cPanel stores `/var/cpanel/ssl/apache_tls/<domain>/combined` (key + cert + chain in one file); Zentinel expects separate `cert_file`/`key_file`. Accept combined PEM explicitly.
- **Directory-watch SNI mode**: scan a cert directory (one subdir per domain, cPanel layout) so *new* domains get served without a config edit — or lean on the panel sync tool (#14) to regenerate entries.
- **DCV passthrough**: once Zentinel owns :80/:443, AutoSSL domain-validation requests (`/.well-known/pki-validation/`, `/.well-known/acme-challenge/`) must route to Apache untouched and bypass WAF agents, or every renewal fails silently ~90 days after deploy. Bake into recipe #16 and add a lint rule: TLS listener fronting a panel backend without a DCV bypass route.
Note: no TLS passthrough mode exists (verified), so termination at Zentinel is the only option — which is fine, WAF/routing require it anyway.

</details>
