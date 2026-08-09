# PROXY protocol codec (`proxy_protocol`)

Encode/decode for the HAProxy [PROXY protocol][spec] — the small header that lets
a receiver recover the **real client endpoint** of a proxied connection instead
of seeing the proxy's own address.

Zentinel needs this in both directions:

- **Inbound** — accept a PROXY header from an upstream load balancer so Zentinel
  itself recovers the real client IP.
- **Outbound** — emit a PROXY header to backends (Apache `mod_remoteip`,
  LiteSpeed, Imunify360 greylisting/captcha) so IP-based security *behind*
  Zentinel keeps working. Without it every visitor looks like the proxy, and
  IP-keyed rules either break or block everyone.

[spec]: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

## Scope: codec only

This module is the **pure codec** — `bytes ↔ struct`, no I/O, no datapath wiring.
It has no runtime dependencies (pure `std`), so it also compiles into the
WASM playground.

Reading the header off an accepted L4 stream (inbound) and writing it before the
upstream request (outbound) both happen at Pingora's listener/connector layer,
via two fork hooks (`AcceptPreprocessor`, `PeerOptions.connect_prefix`) — see
"Datapath (shipped)" below for the wiring and the operator-facing config.

Keeping the codec standalone also makes it exhaustively testable and fuzzable in
isolation — it is a network-facing binary parser, the same criterion that gets
the agent v2 frame decoder fuzzed (`fuzz/fuzz_targets/proxy_protocol.rs`).

## API

```rust
use zentinel_common::proxy_protocol::{parse, ProxyHeader, Transport};

// Decode. Auto-detects v1 vs v2 from the leading byte. Returns the header and
// the number of bytes consumed — resume the real payload at input[consumed..].
let (header, consumed) = parse(input)?;

// Encode.
let v2: Vec<u8> = header.encode_v2();          // always representable
let v1: Vec<u8> = header.encode_v1()?;         // TCP-only; errs on Dgram
```

`ProxyHeader` models the two cases Zentinel acts on:

| Variant | Meaning |
|---------|---------|
| `Local` | No endpoint conveyed — use the raw socket peer. Covers v2 `LOCAL`, v1 `UNKNOWN`, and `AF_UNSPEC`. |
| `Proxy { transport, source, destination }` | Real endpoints; `source`/`destination` share an address family (both IPv4 or both IPv6). |

### `parse` return contract

`consumed` is the exact header length; `input[consumed..]` is untouched (the HTTP
request, typically). Callers on a streaming socket loop on
`ProxyProtocolError::Incomplete { needed }` — read at least `needed` more bytes
and retry.

## Wire formats

**v1 (text)** — one CRLF-terminated ASCII line, max 107 bytes:

```
PROXY TCP4 192.0.2.1 203.0.113.7 56324 443\r\n
PROXY TCP6 2001:db8::1 2001:db8::2 4321 443\r\n
PROXY UNKNOWN\r\n
```

**v2 (binary)** — 12-byte signature + 1 byte version/command + 1 byte
family/transport + 2-byte big-endian address-block length, then the address
block:

| Family | Block | Layout |
|--------|-------|--------|
| `AF_INET` (0x1) | 12 B | src IPv4 (4) · dst IPv4 (4) · src port (2) · dst port (2) |
| `AF_INET6` (0x2) | 36 B | src IPv6 (16) · dst IPv6 (16) · src port (2) · dst port (2) |

The length field may exceed the fixed address portion; trailing **TLV** bytes are
consumed and skipped (counted in `consumed`), not parsed.

## Error model (fail loudly)

Every malformed input maps to a specific `ProxyProtocolError` variant — never a
panic, never a silent fallback:

- `Incomplete { needed }` — partial but valid so far; read more.
- `NotProxyProtocol` — the bytes are not a PROXY header at all.
- `InvalidSignature`, `UnsupportedVersion`, `InvalidCommand`,
  `UnsupportedTransport`, `TruncatedAddressBlock` — present but malformed v2.
- `V1LineTooLong`, `MalformedV1(..)` — malformed v1.
- `V1Unrepresentable`, `MixedAddressFamily` — encode-time constraints.

### Out of scope

`AF_UNIX` (v2) decodes to `UnsupportedAddressFamily` rather than a value — path
endpoints do not map to a client IP, and no shared-hosting front-end fronts
Zentinel over an `AF_UNIX` PROXY header. It is rejected explicitly, not silently
dropped.

## Bounds

- v1 lines are capped at `V1_MAX_LEN` (107 B); a longer line without CRLF is
  rejected as `V1LineTooLong` rather than buffered unbounded.
- v2 total header length is `16 + len`, where `len` is a `u16` — a hard ceiling.
  Only the fixed inet portion is read; the rest (TLVs) is skipped, never
  allocated.

## Datapath (shipped)

Wired via two fork hooks (`zentinelproxy/pingora` branch `proxy-protocol-hooks`:
`AcceptPreprocessor` + `PeerOptions.connect_prefix`):

1. **Inbound** — `zentinel_proxy::proxy_protocol::ProxyProtocolAcceptor`
   implements the fork's accept-time preprocessor: runs per connection before
   TLS and buffering, enforces the listener's trusted-source CIDR list
   (fail-closed: untrusted peer, garbage, or a stalled header all drop the
   connection), decodes with `parse` using exact-byte reads (v2 length hints
   are exact; v1 is read byte-wise to CRLF), and sets the fork's
   `peer_addr_override` so `session.client_addr()` — and everything built on
   it: logs, rate limiting, geo filtering — sees the real client.

   ```kdl
   listener "https" {
       address "0.0.0.0:443"
       proxy-protocol {
           trusted "10.0.0.0/8"      // required, non-empty
           header-timeout-ms 2000    // default
       }
   }
   ```

2. **Outbound** — `encode_upstream_prefix` builds the header from the
   downstream connection's (possibly rewritten) endpoints; it is handed to the
   fork as `PeerOptions.connect_prefix`, written once per **new** connection
   before any TLS. The prefix participates in the connection reuse hash, so a
   pooled connection never carries another client's identity — the cost is
   per-client-connection pooling, the same trade HAProxy's `send-proxy` makes.
   Unavailable or mixed-family endpoints degrade to a LOCAL/UNKNOWN header,
   never a fabricated address.

   ```kdl
   upstream "apache" {
       target "10.0.1.5:80"
       proxy-protocol "v2"   // or "v1"
   }
   ```

## Operator surface

- `zentinel explain` shows the matched route's upstream PROXY emission
  (version + pooling implication) in text and JSON reports.
- `zentinel lint` warns when a listener's `trusted` list contains
  `0.0.0.0/0` or `::/0` — any client that can reach the listener could
  spoof its address; only safe on isolated networks.

## Conformance

`crates/proxy/tests/proxy_protocol_e2e_test.rs` asserts real-IP propagation
end-to-end over real sockets (the property IDEAS #16 depends on): a client
address carried in by a trusted LB's PROXY v2 header is what Zentinel reports
for the connection *and* what the backend decodes from Zentinel's emitted
header (v1 and v2), with application bytes intact — plus the security half:
the same wire bytes from an untrusted source drop the connection and leave
the socket peer address untouched.

## Deployment recipe

Zentinel → Apache + Imunify360 coexistence (the motivating use case, IDEAS
#16): `crates/proxy/docs/imunify360.md` + validated example
`config/examples/imunify360-apache.kdl`.
