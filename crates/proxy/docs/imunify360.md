# Imunify360 / Apache Coexistence

Deployment recipe for running Zentinel as the public edge in front of Apache
with Imunify360 (IDEAS #16). The whole problem reduces to one property:
**Imunify360's IP-based protections (greylisting, captcha, blocklists,
ModSecurity collections) only work if Apache sees the real client address.**
A plain reverse proxy hands Apache `127.0.0.1` for every request and silently
disables all of them.

## Architecture

```
client ──HTTPS──▶ Zentinel (0.0.0.0:443, TLS edge)
                     │  PROXY protocol v2 (real client IP in TCP preface)
                     ▼
                  Apache + mod_remoteip + Imunify360 (127.0.0.1:8080)
```

- Zentinel terminates TLS and does routing/limits; Apache keeps the WAF role.
- The upstream sets `proxy-protocol "v2"`; Apache's `mod_remoteip` restores
  the client address before any Imunify hook runs. No `X-Forwarded-For`
  trust chains, no per-vhost log rewrites — the address is correct at the
  connection level.

## Zentinel side

Full working config: [`config/examples/imunify360-apache.kdl`](../../../config/examples/imunify360-apache.kdl).
The load-bearing lines:

```kdl
upstreams {
    upstream "apache" {
        target "127.0.0.1:8080"
        proxy-protocol "v2"
    }
}
```

Plus two routes that make hosting stacks work:

- **`/.well-known/acme-challenge/` → Apache** (priority high): cPanel
  AutoSSL / certbot on the Apache host keeps answering its own HTTP-01
  challenges. If Zentinel's own `acme { }` block is enabled, Zentinel answers
  its challenges internally before routing, so the passthrough only carries
  Apache-side issuance. Deeper AutoSSL integration is IDEAS #18.
- **WebSocket routes** with `websocket { enabled #true }` and long timeouts:
  the upgrade request carries the real client IP via the PROXY header like
  any other connection.

## Apache side (2.4.31+)

```apache
LoadModule remoteip_module modules/mod_remoteip.so
RemoteIPProxyProtocol On
Listen 127.0.0.1:8080
```

After this, `%a` in `LogFormat`, `REMOTE_ADDR` in ModSecurity, and
Imunify360's greylist/captcha decisions all use the true client IP.

**Warning:** `RemoteIPProxyProtocol On` makes the PROXY preface *mandatory* on
that listener — a bare `curl 127.0.0.1:8080` will be rejected. Health-check
traffic from Zentinel carries the preface, so Zentinel's `health-check` block
works; other local tooling must go through Zentinel or a separate
non-PROXY listener.

## Trade-off

With `proxy-protocol` set, pooled upstream connections are keyed per client
identity (a pooled connection carries one client's preface and may not be
reused for another). Cross-client connection reuse to Apache is lost; on
loopback the extra connect cost is negligible. `zentinel explain` surfaces
this on the matched route:

```
Upstream: "apache"  [RoundRobin, 1 target(s)]
PROXY protocol: emits v2 header on new connections (backend sees real client IP; per-client connection pooling)
```

## Verification

- **CI:** `crates/proxy/tests/proxy_protocol_e2e_test.rs` asserts the full
  propagation chain over real sockets — trusted-LB inject → Zentinel peer
  rewrite → backend decode — plus spoof rejection from untrusted sources.
- **Config:** `zentinel test --config imunify360-apache.kdl`, then
  `zentinel explain --config ... --method GET --path /index.php --header
  host=example.com` — the matched route must show the PROXY protocol line.
- **Live:** `curl https://edge.example.com/` from an external host, then
  check the Apache access log — the logged address must be the client's, not
  `127.0.0.1`. Imunify360's dashboard incident list should attribute events
  to the same address.

## Status / limits

- Greylisting, captcha, blocklists, ModSecurity: covered by real-IP
  propagation (above). Apache keeps the WAF role in this recipe. To move rule
  enforcement to the edge instead — same SecLang rules, same native audit-log
  format — run the Coraza agent (`agents/coraza-waf/README.md`) pointed at the
  panel's exported rule directory; the two can also run side by side while you
  compare verdicts.
- cPanel AutoSSL certificate *reuse* at the Zentinel edge: supported — point
  the TLS listener at the panel's certificate store and keep the validation
  paths flowing to Apache:

  ```kdl
  tls {
      combined-file "/var/cpanel/ssl/apache_tls/server.example.com/combined"
      sni-cert-dir "/var/cpanel/ssl/apache_tls"
  }
  ```

  cPanel stays the certificate source of truth (users keep the SSL/TLS UI),
  hostnames come from each certificate's CN/SAN, and a reload picks up domains
  the panel added. **The validation route is not optional:** AutoSSL proves
  domain control over plain HTTP, so `/.well-known/pki-validation/` (Sectigo,
  which AutoSSL uses) and `/.well-known/acme-challenge/` must reach Apache
  with no filters and no WAF — otherwise renewals fail silently about 90 days
  after deployment. `zentinel lint` warns about both mistakes. Full example:
  `config/examples/cpanel-autossl.kdl`.
- Per-tenant LVE-aligned rate limiting: IDEAS #15.
