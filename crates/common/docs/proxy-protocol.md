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
upstream request (outbound) both require a hook at Pingora's listener/connector
layer. The Zentinel `zentinelproxy/pingora` fork exposes no such hook today
(`connected_to_upstream` hands back only a `RawFd`, and `ConnectionFilter` is
accept/reject only), so datapath integration is a **separate slice** against the
fork. Until that lands there is deliberately **no operator-facing config** — an
accepted-but-ignored `proxy-protocol` option would be a silent failure (backends
still see the proxy IP while the config validates clean), which the Manifesto
forbids.

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

## Next slice (datapath, requires the fork)

1. **Inbound**: a listener-level decode that peeks the accepted stream, calls
   `parse`, rewrites the connection's reported peer to `source`, and hands the
   remaining bytes to the HTTP reader. Populates `ClientIp` (`types.rs`).
2. **Outbound**: a connector-level emit that writes `encode_v1`/`encode_v2`
   before the request on a **new** (non-reused, non-TLS) upstream connection —
   once per connection.
3. **Config**: `proxy-protocol` on listener (accept + trusted-source
   allow-list) and on upstream (emit v1|v2), surfaced by `explain`/`lint`.
   Lands only once 1–2 make it non-silent.
