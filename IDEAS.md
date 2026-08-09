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

### 3. Fuzzing targets (none exist today)
`cargo-fuzz` targets for the highest-value parsers:
- KDL config parser (`crates/config`) — untrusted-ish input, complex grammar.
- Agent protocol v2 frame decode (`crates/agent-protocol/src/v2`) — binary wire format, network-facing.
- Any header/path normalization in the request hot path.
Run as scheduled CI job (nightly, bounded time), seed corpus from `config/examples/*.kdl` and conformance fixtures. Security-first proxy without fuzzing is a gap.

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

### 6. Official agent SDKs (Go first, then Python)
The conformance suite is already Go (`conformance/`); the wire knowledge exists. Package it: `zentinel-agent-sdk-go` implementing v2 handshake, framing, drain, health — so third parties write `func OnRequestHeaders(...) Decision` and nothing else. Conformance suite becomes the compliance badge ("passes zentinel-conformance vX"). Grows the external-agent ecosystem, which is the whole architectural bet.

### 7. Agent starter template repo / `zentinel agent new` — ✅ done
Scaffold generator producing a minimal agent (echo-style, from `agents/echo/`) with Dockerfile, conformance test wiring, and KDL snippet to register it. Lowers the barrier from "read the protocol docs" to "edit one function".
- Implemented as `zentinel agent new <name>` (`crates/proxy/src/agent_scaffold.rs`): generates a self-contained crate (Cargo.toml with published `zentinel-agent-protocol` dep, `src/main.rs` = one `on_request_headers` to edit, `zentinel-agent.toml`, Dockerfile, README with UDS+gRPC KDL register snippets, `.gitignore`). Dual-transport binary (`--socket`/`--grpc`); overwrite-guarded; name-validated. Deps verified to resolve against crates.io (0.6.22).

## Operations

### 8. Runtime config drift check
Admin API already exists (`/api/admin`). Expose loaded-config content hash + load timestamp; add `zentinel validate --against-running <admin-addr>` that compares on-disk config to what the proxy actually runs. Kills the classic "edited the file, forgot to reload" incident class. Calm infrastructure.

### 9. Chaos suite: resource-bound assertions
`tests/chaos` already covers agent crash + circuit breaker. Add scenarios asserting *bounded resources* under sustained failure: slow-loris agent (reads headers, never answers), UDS socket deleted mid-flight, agent restart storm. Assert memory/fd ceilings hold, not just that requests fail correctly — "bounded by design" currently isn't chaos-verified.

### 10. Benchmark regression gate in CI
Criterion benches exist (`cargo bench -p zentinel-proxy`). Save a baseline per `main` merge, compare on PRs touching `crates/proxy` hot paths, fail on >N% routing/filtering regression. Turns "production correctness beats feature breadth" into an enforced budget instead of a review-time hope.

## Hosting-stack compatibility (Apache, CloudLinux, Imunify360, control panels)

Target: Zentinel as the edge in front of classic shared-hosting stacks (Apache/LiteSpeed on cPanel/Plesk/DirectAdmin, CloudLinux, Imunify360). Core stays small — panel/vendor specifics live in importers, agents, and deployment recipes, per the Manifesto.

### 11. Apache/nginx config importer — `zentinel import apache httpd.conf`
Generate KDL from existing `VirtualHost`/`server` blocks: domains → routes (SNI + Host matching, which Zentinel already supports), `ProxyPass`/`proxy_pass` → upstreams, TLS cert paths → listener config. Directives that don't map (rewrite rules, .htaccess semantics) are *listed explicitly* as "stays on the backend" — no silent drops. Biggest single adoption lever for the hosting world: migration becomes a review of generated config instead of a rewrite.

### 12. PROXY protocol v1/v2 (inbound + outbound) — missing today
- **Outbound to backends**: Apache `mod_remoteip`, LiteSpeed, and Imunify360's greylisting/captcha all key on real client IP. Without PROXY protocol (or trusted XFF), every visitor looks like the proxy and IP-based security behind Zentinel breaks or, worse, blocks everyone.
- **Inbound**: accept PROXY protocol from an upstream LB so Zentinel itself sees real IPs.
Codebase has `ClientIp.forwarded_for` but no PROXY protocol support. This is the prerequisite for the whole compat story — do it first.
- **Status (✅ datapath done, pending fork push):** codec in `zentinel-common::proxy_protocol` (encode/decode, fuzzed). Fork hooks landed on `zentinelproxy/pingora` branch `proxy-protocol-hooks` (`AcceptPreprocessor` pre-TLS accept hook + `PeerOptions.connect_prefix` with reuse-hash isolation). Zentinel wiring: inbound `ProxyProtocolAcceptor` (trusted-CIDR fail-closed, exact-byte reads, peer rewrite feeding logs/rate-limit/geo) + outbound `connect_prefix` emit per upstream (`proxy-protocol "v1"|"v2"`), KDL config on listener and upstream. Operator surface: `explain` shows upstream emission, `lint` warns on trust-all CIDRs. Conformance: `proxy_protocol_e2e_test.rs` asserts LB→Zentinel→backend real-IP propagation + spoof rejection over real sockets (the #16 prerequisite). **#12 complete.**

### 13. ModSecurity-compatible WAF agent (Coraza-based)
External agent (Go — synergy with SDK idea #6) embedding [Coraza](https://coraza.io) to execute SecLang rulesets: OWASP CRS, Comodo/Imunify360 modsec rule exports, custom vendor rules. Hosting operators keep their existing rule investment while moving WAF enforcement to the edge. Emit ModSecurity audit-log format so existing SIEM/fail2ban pipelines keep working. Fits the architecture exactly: complex WAF logic isolated in a crash-safe external process.

### 14. Control-panel sync tool (cPanel/WHM first; Plesk, DirectAdmin later)
Sidecar (not core) that watches panel account/domain state — e.g. cPanel's `/etc/userdatadomains` or WHM API — and regenerates per-domain routes + upstreams, then triggers the existing graceful reload. Domains added in the panel appear at the edge without manual config. Explicit failure mode: if generation fails validation, keep last-good config and alert — never partially apply.

### 15. Per-tenant rate limiting aligned with CloudLinux LVE
CloudLinux isolates tenants at the kernel level (LVE) *after* the request hits Apache. Zentinel can enforce the same tenancy boundary earlier: rate-limit/concurrency keys derived from the mapped account (via #14's domain→user mapping), so one tenant's traffic spike is shed at the edge instead of consuming Apache slots and LVE budget. Bounded per-tenant, explicit limits in KDL — very on-manifesto.

### 16. Imunify360 coexistence recipe + conformance scenario
Documented, tested deployment: Zentinel → Apache + Imunify360, with #12 wired so greylisting/captcha/blocklists see real client IPs, and WebSocket/ACME paths passing through correctly. Add a `stack`/conformance scenario that asserts real-IP propagation end-to-end. Turns "does it work with Imunify?" from a forum question into a CI-verified yes.

### 17. Named backend profiles for common stacks
Explicit, opt-in KDL presets — `profile "apache-shared-hosting"`, `profile "litespeed"`, `profile "php-fpm-behind-apache"` — bundling tuned retry/keepalive/timeout values (e.g. tolerate Apache graceful-restart connection resets). Rendered into the config visibly by `zentinel explain`/`lint` so nothing is hidden; profiles are shorthand, not magic defaults.

### 18. cPanel/WHM AutoSSL certificate integration
Terminate TLS at Zentinel using the certs cPanel AutoSSL already issues, keeping the panel as certificate source-of-truth (users keep their SSL UI). Building blocks exist: `SniCertificate` (per-domain cert/key, SAN auto-extraction) + `CertificateReloader` hot reload — AutoSSL *renewals* rewrite files in place and are picked up without restart. Three gaps to close:
- **Combined-PEM support**: cPanel stores `/var/cpanel/ssl/apache_tls/<domain>/combined` (key + cert + chain in one file); Zentinel expects separate `cert_file`/`key_file`. Accept combined PEM explicitly.
- **Directory-watch SNI mode**: scan a cert directory (one subdir per domain, cPanel layout) so *new* domains get served without a config edit — or lean on the panel sync tool (#14) to regenerate entries.
- **DCV passthrough**: once Zentinel owns :80/:443, AutoSSL domain-validation requests (`/.well-known/pki-validation/`, `/.well-known/acme-challenge/`) must route to Apache untouched and bypass WAF agents, or every renewal fails silently ~90 days after deploy. Bake into recipe #16 and add a lint rule: TLS listener fronting a panel backend without a DCV bypass route.
Note: no TLS passthrough mode exists (verified), so termination at Zentinel is the only option — which is fine, WAF/routing require it anyway.
