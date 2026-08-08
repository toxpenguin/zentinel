# Config Import (`zentinel import`)

Converts foreign proxy configurations into Zentinel KDL. Currently supports
**Apache httpd** only.

```bash
# Emit KDL to stdout (report goes to stderr, so stdout is pipeable)
zentinel import apache httpd.conf

# Write to a file
zentinel import apache httpd.conf -o zentinel.kdl
```

Implementation: `crates/proxy/src/import.rs`.

## What is imported

The mapped set is deliberately small and explicit:

| Apache | Zentinel |
|--------|----------|
| `<VirtualHost addr>` | Listener (vhosts grouped by normalized address) + routes |
| `ServerName` / `ServerAlias` | `host` match condition (one route per hostname) |
| `ProxyPass path url` | Upstream (deduplicated by target) + route with `path-prefix` |
| `SSLCertificateFile` / `SSLCertificateKeyFile` | Listener `tls` block; additional TLS vhosts on the same address become `sni` certificate blocks |

Details:

- `*`, `_default_`, and hostname addresses bind to `0.0.0.0`; a missing port
  defaults to 80 (443 when certificates are present). Assumptions are reported.
- `https://` ProxyPass targets get `tls { sni "<host>" }` on the upstream.
- Route priority is emitted as `50 + path-prefix length` so longer (more
  specific) prefixes are evaluated before shorter ones.
- An explicit `system` block is emitted (`worker-threads 0`,
  `max-connections 10000`) because the config parser requires one.

## What is not imported (and how you find out)

**Nothing is silently dropped.** Every directive outside the mapped set is
collected with its source line number and:

1. embedded as `// NOT IMPORTED` comments in the generated KDL header, and
2. printed to stderr as a report.

This includes: `RewriteRule`, `ProxyPassReverse`, `DocumentRoot`, directives
outside `<VirtualHost>` (e.g. `Listen`, `ServerRoot`), nested sections
(`<Directory>`, `<Location>`, `<IfModule>` — skipped wholesale, including
everything inside), non-http(s) ProxyPass targets (`balancer://`, `unix:`,
`ws://`), ProxyPass options (`retry=`, `timeout=`), and ProxyPass exclusions
(`!`).

Apache path substitution (`ProxyPass /api http://b/app` rewrites `/api/x` to
`/app/x`) is **not** replicated — Zentinel forwards the original request path.
Any ProxyPass whose target path differs from its match prefix is flagged in
the report.

## Output guarantees

Generated KDL is gated before it is shown: it must round-trip through
`Config::from_kdl` and pass `Config::validate`, otherwise the command fails
with an importer-bug error instead of emitting broken config. Inputs larger
than 4 MiB are refused.

Errors (exit non-zero): unreadable input, no `<VirtualHost>` blocks, unclosed
sections, stray closing tags, malformed mapped directives (e.g. `ProxyPass`
with fewer than two arguments), invalid ports, and a certificate file without
its key (or vice versa).
