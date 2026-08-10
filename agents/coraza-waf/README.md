# coraza-waf — ModSecurity-compatible WAF agent

Runs SecLang rulesets — OWASP CRS, Comodo, Imunify360 exports, your own
custom rules — at the Zentinel edge, using [Coraza](https://coraza.io) as the
engine and the [Go agent SDK](../../sdk/go) for the wire protocol.

Hosting operators keep the ModSecurity rule investment they already have; the
enforcement point moves from Apache to the proxy, and the audit records stay in
ModSecurity's native format so existing SIEM parsers and fail2ban jails keep
working unchanged.

The WAF runs as a **separate process**. A rule that panics, wedges, or leaks
memory takes down this agent, not the dataplane — the proxy applies the
per-agent `failure-mode` from its own config and keeps serving.

## Build and run

```bash
cd agents/coraza-waf
go build -o coraza-waf .

./coraza-waf \
    --socket /run/zentinel/coraza-waf.sock \
    --rules /etc/modsecurity.d/owasp-crs \
    --rules /etc/modsecurity.d/custom \
    --audit-log /var/log/zentinel/waf-audit.log
```

Rule paths may be files or directories; a directory loads its `*.conf` entries
in lexical order. A missing path, an empty directory, or no `--rules` at all is
a **startup error** — the agent refuses to run as a WAF that inspects nothing.

Without an existing ruleset, start from the bundled
[`rules/zentinel-default.conf`](rules/zentinel-default.conf) (`--rules rules`):
a small high-signal set covering traversal, null bytes, SQLi/XSS via
libinjection, and command injection. It is a starting point, not a substitute
for CRS.

## Register with the proxy

```kdl
agents {
    agent "coraza-waf" {
        type "waf"
        unix-socket "/run/zentinel/coraza-waf.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"
    }
}

filters {
    filter "coraza-waf" {
        type "agent"
        agent "coraza-waf"
    }
}

routes {
    route "app" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "coraza-waf"
    }
}
```

`failure-mode` is the operator's call, and it is the setting that decides what a
dead WAF means: `closed` rejects traffic the WAF could not inspect, `open`
serves it. Nothing about that choice is implied by this agent.

## Inspection depth

| Flag | Effect |
|------|--------|
| `--lifecycle headers` (default in header-only deployments) | Phases 1 and 2 run at request-headers time, transaction closed immediately. No per-request state. |
| `--lifecycle full` (default) | Transaction lives across body and response events so phases 2–5 run. Bounded by `--max-transactions` and `--transaction-ttl`. |
| `--request-body` (default on) | Inspects request bodies. **Also register `request_body` in the KDL `events` list**, or the body phase never receives data. |
| `--response-body` (default off) | Inspects response bodies (phase 4). Requires `response_body` in `events`. |

Phase 2 is where CRS inspects `ARGS`, so it is evaluated at request-headers
time whenever no request body will arrive. Query-string rules fire in every
mode; only rules that read body content need the body events.

If `--lifecycle full` is used but the proxy never sends `request_complete`,
transactions are reclaimed by the TTL sweeper, which logs a loud warning
naming the likely misconfiguration.

## Bounded by construction

- `--max-transactions` (default 10000) caps the in-flight transaction table.
  When it is full, **nothing in flight is evicted** — evicting a live
  transaction would silently stop inspecting a request mid-flight. The new
  request gets `--overflow allow` (default, fail-open) or `--overflow block`,
  always with a `waf_overflow` reason code and a warning log.
- `--transaction-ttl` (default 60s) reclaims transactions whose request never
  completed (client aborts, upstream hangs).
- `--body-limit` (default 1 MiB) caps buffered body bytes per direction; the
  limit action is `ProcessPartial`, so oversized bodies are inspected up to the
  limit rather than passed through unexamined.

## Audit logging

`--audit-log <path>` enables Coraza's audit engine with
`SecAuditLogFormat Native` + `SecAuditLogType Serial` — byte-compatible with
ModSecurity's serial audit log:

```
--a1b2c3-A--
[11/Aug/2026:02:25:46 +0000] req-abc123 203.0.113.7 51234
--a1b2c3-B--
GET /search?q=1'+OR+'1'='1'-- HTTP/1.1
...
--a1b2c3-H--
[client "203.0.113.7"] Coraza: Access denied (phase 2). [id "100010"] [msg "SQL injection in ARGS:q"] [tag "attack-sqli"]
```

Parts are selectable with `--audit-parts` (default `ABCFHZ`). Set your own
`SecAuditLog*` directives in a rule file to override any of it.

Independently of the audit log, every decision carries structured metadata back
to the proxy — matched rule IDs, rule tags, and a `waf_deny` / `waf_detected`
reason code — so Zentinel's own access logs and metrics show why a request was
blocked without parsing the audit file.

## Rolling out safely

```bash
./coraza-waf --mode detection --rules /etc/modsecurity.d/owasp-crs ...
```

`--mode detection` runs the full ruleset and reports every match (logs, audit
records, response metadata) while allowing traffic — the standard way to
measure false positives before enforcing. Switch to `--mode blocking` when the
noise is gone.

Block responses do **not** reveal which rule fired. `--expose-rule-id` adds
`X-Zentinel-WAF-Rule` for debugging; leave it off in production, since it hands
an attacker a rule-by-rule evasion oracle.

## Testing

```bash
go test ./...                              # unit + live-proxy smoke test
cargo build --bin zentinel                 # needed by the smoke test
```

The live-proxy test runs a real `zentinel` binary with this agent in front of a
test upstream and asserts a SQLi request gets a 403 while the upstream stays
untouched. It skips when no proxy binary is present (`ZENTINEL_BIN` overrides
the path).

## Conformance

The agent passes **zentinel-conformance v1**:

```bash
./coraza-waf --socket /tmp/waf.sock --rules rules &
zentinel agent conform --socket /tmp/waf.sock
```

## Interop notes

- **Imunify360 / Apache**: see [`crates/proxy/docs/imunify360.md`](../../crates/proxy/docs/imunify360.md)
  for running Zentinel in front of Apache with real client IPs. ModSecurity
  rule sets exported by the panel load here directly with `--rules`.
- **Coraza operators**: `@detectSQLi`, `@detectXSS`, `@rx`, `@pm`, and the rest
  of the Coraza operator set are supported as in upstream Coraza. Directives
  Coraza does not implement (`SecRemoteRules`, Lua) fail at startup with the
  offending file and line.
