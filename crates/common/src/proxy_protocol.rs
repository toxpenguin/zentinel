//! HAProxy PROXY protocol (v1 text + v2 binary) header codec.
//!
//! The PROXY protocol prepends a small header to a proxied connection so the
//! receiver learns the *real* client endpoint instead of seeing the proxy's own
//! address. Zentinel needs both directions:
//!
//! - **Inbound**: accept a PROXY header from an upstream load balancer so the
//!   proxy itself recovers the real client IP.
//! - **Outbound**: emit a PROXY header to backends (Apache `mod_remoteip`,
//!   LiteSpeed, Imunify360 greylisting/captcha) so IP-based security behind
//!   Zentinel keeps working instead of seeing every visitor as the proxy.
//!
//! This module is the **pure codec only** — encode/decode of the header bytes,
//! with no I/O and no datapath wiring. Reading the header off an accepted L4
//! stream (inbound) and writing it before the upstream request (outbound) both
//! require a hook at Pingora's listener/connector layer; that lands as a
//! separate slice against the `zentinelproxy/pingora` fork. Keeping the codec
//! standalone means it is exhaustively testable and fuzzable in isolation (it is
//! a network-facing binary parser — the same reason the agent v2 frame decoder
//! is fuzzed).
//!
//! Reference: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//!
//! # Example
//!
//! ```
//! use zentinel_common::proxy_protocol::{ProxyHeader, Transport, parse};
//! use std::net::SocketAddr;
//!
//! let src: SocketAddr = "192.0.2.1:56324".parse().unwrap();
//! let dst: SocketAddr = "203.0.113.7:443".parse().unwrap();
//! let hdr = ProxyHeader::Proxy { transport: Transport::Stream, source: src, destination: dst };
//!
//! // A v2 header round-trips through parse().
//! let bytes = hdr.encode_v2();
//! let (decoded, consumed) = parse(&bytes).unwrap();
//! assert_eq!(decoded, hdr);
//! assert_eq!(consumed, bytes.len());
//! ```

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use thiserror::Error;

/// The 12-byte v2 signature block (`\r\n\r\n\0\r\nQUIT\n`).
pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Fixed v2 header size: signature (12) + version/command (1) +
/// family/transport (1) + address-block length (2).
const V2_HEADER_LEN: usize = 16;

/// Maximum length of a v1 header line, including the trailing `\r\n`.
///
/// Per the specification the longest possible v1 line is exactly 107 bytes
/// (`PROXY TCP6 <39-byte src> <39-byte dst> <5> <5>\r\n`). A line longer than
/// this is malformed and is rejected loudly rather than buffered unbounded.
pub const V1_MAX_LEN: usize = 107;

/// The ASCII prefix that starts every v1 header.
const V1_PREFIX: &[u8] = b"PROXY ";

/// Transport protocol carried by a proxied connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Connection-oriented (TCP).
    Stream,
    /// Datagram (UDP).
    Dgram,
}

/// A decoded PROXY protocol header.
///
/// Only the two cases Zentinel acts on are modelled: a real proxied
/// TCP/UDP connection over IPv4/IPv6, and the "no endpoint information"
/// case (v2 `LOCAL`, v1 `UNKNOWN`, or `AF_UNSPEC`) in which the receiver
/// must fall back to the raw socket peer address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyHeader {
    /// No client endpoint conveyed — use the real socket peer address.
    ///
    /// Emitted by health checks and by senders that cannot determine the
    /// original connection (v2 `LOCAL` command, v1 `PROXY UNKNOWN`, or a v2
    /// `AF_UNSPEC` address family).
    Local,

    /// Real source and destination endpoints of a proxied connection.
    ///
    /// `source` is the original client; `destination` is the address the
    /// client connected to. Both are guaranteed to share an address family
    /// (both IPv4 or both IPv6).
    Proxy {
        /// TCP (`Stream`) or UDP (`Dgram`).
        transport: Transport,
        /// Original client endpoint.
        source: SocketAddr,
        /// Endpoint the client originally connected to.
        destination: SocketAddr,
    },
}

/// Errors produced while decoding or encoding a PROXY protocol header.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProxyProtocolError {
    /// More bytes are required before the header can be decoded. The reader
    /// should read at least `needed` additional bytes and retry.
    ///
    /// `needed` is a lower bound (the true requirement may be larger once the
    /// length field is known); it is never zero.
    #[error("incomplete PROXY header: need at least {needed} more byte(s)")]
    Incomplete {
        /// Minimum number of additional bytes required.
        needed: usize,
    },

    /// The input does not begin with a v1 (`PROXY `) or v2 (signature) prefix.
    #[error("not a PROXY protocol header")]
    NotProxyProtocol,

    /// The bytes started like a v2 header but the 12-byte signature did not match.
    #[error("invalid v2 signature")]
    InvalidSignature,

    /// The v2 version nibble was not `2`.
    #[error("unsupported PROXY version: {0}")]
    UnsupportedVersion(u8),

    /// The v2 command nibble was neither `LOCAL` (0) nor `PROXY` (1).
    #[error("invalid v2 command: 0x{0:x}")]
    InvalidCommand(u8),

    /// The v2 address family was not one this codec decodes (`AF_UNIX` is out
    /// of scope for real-client-IP recovery).
    #[error("unsupported address family: 0x{0:x}")]
    UnsupportedAddressFamily(u8),

    /// The v2 transport-protocol nibble was not `STREAM` (1) or `DGRAM` (2).
    #[error("unsupported transport protocol: 0x{0:x}")]
    UnsupportedTransport(u8),

    /// The declared address block is too short for the stated family.
    #[error("truncated address block: have {have}, need {need} for this family")]
    TruncatedAddressBlock {
        /// Bytes actually present in the declared block.
        have: usize,
        /// Bytes required for the family's fixed address portion.
        need: usize,
    },

    /// A v1 line exceeded the 107-byte maximum without a terminating `\r\n`.
    #[error("v1 header line exceeds {V1_MAX_LEN} bytes")]
    V1LineTooLong,

    /// A v1 header was structurally malformed (wrong field count, bad protocol
    /// token, unparseable address or port).
    #[error("malformed v1 header: {0}")]
    MalformedV1(&'static str),

    /// Encoding to v1 was requested for a header v1 cannot express (a `Dgram`
    /// transport — v1 is TCP-only).
    #[error("cannot encode {0} as PROXY v1 (v1 is TCP-only)")]
    V1Unrepresentable(&'static str),

    /// A proxied header held a mixed-family source/destination pair, which the
    /// wire format cannot represent.
    #[error("source and destination address families differ")]
    MixedAddressFamily,
}

/// Decode a PROXY protocol header from the front of `input`.
///
/// Auto-detects v1 vs v2 from the leading bytes. On success returns the decoded
/// header together with the number of bytes it consumed — the caller resumes
/// reading the real payload (e.g. the HTTP request) at `input[consumed..]`.
///
/// # Errors
///
/// Returns [`ProxyProtocolError::Incomplete`] when `input` is a valid but
/// partial header (read more and retry), [`ProxyProtocolError::NotProxyProtocol`]
/// when the bytes are not a PROXY header at all, or a specific variant for a
/// header that is present but malformed.
pub fn parse(input: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    let Some(&first) = input.first() else {
        return Err(ProxyProtocolError::Incomplete { needed: 1 });
    };

    match first {
        // v2 headers begin with the signature, whose first byte is 0x0D.
        0x0D => parse_v2(input),
        // v1 headers begin with the ASCII text "PROXY ".
        b'P' => parse_v1(input),
        _ => Err(ProxyProtocolError::NotProxyProtocol),
    }
}

// ---------------------------------------------------------------------------
// v1 (human-readable text)
// ---------------------------------------------------------------------------

fn parse_v1(input: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    // Confirm the prefix as far as we can see it.
    let check = V1_PREFIX.len().min(input.len());
    if input[..check] != V1_PREFIX[..check] {
        return Err(ProxyProtocolError::NotProxyProtocol);
    }

    // Locate the terminating CRLF within the permitted line length.
    let search = input.len().min(V1_MAX_LEN);
    let mut crlf: Option<usize> = None;
    let mut i = 1;
    while i < search {
        if input[i - 1] == b'\r' && input[i] == b'\n' {
            crlf = Some(i - 1);
            break;
        }
        i += 1;
    }

    let Some(cr) = crlf else {
        // No CRLF yet. Either we need more bytes, or the line is already too long.
        if input.len() >= V1_MAX_LEN {
            return Err(ProxyProtocolError::V1LineTooLong);
        }
        return Err(ProxyProtocolError::Incomplete {
            needed: V1_MAX_LEN - input.len(),
        });
    };

    let consumed = cr + 2; // include the CRLF
    let line = &input[V1_PREFIX.len()..cr]; // bytes after "PROXY ", before CRLF

    // The line body must be valid ASCII; PROXY v1 is a strict subset.
    let line =
        std::str::from_utf8(line).map_err(|_| ProxyProtocolError::MalformedV1("non-ASCII"))?;

    let mut fields = line.split(' ');
    let proto = fields
        .next()
        .ok_or(ProxyProtocolError::MalformedV1("missing protocol"))?;

    let header = match proto {
        "UNKNOWN" => {
            // Everything after UNKNOWN (up to the CRLF) is ignored by spec.
            ProxyHeader::Local
        }
        "TCP4" | "TCP6" => {
            let is_v6 = proto == "TCP6";
            let src_ip = fields
                .next()
                .ok_or(ProxyProtocolError::MalformedV1("missing source address"))?;
            let dst_ip = fields
                .next()
                .ok_or(ProxyProtocolError::MalformedV1("missing dest address"))?;
            let src_port = fields
                .next()
                .ok_or(ProxyProtocolError::MalformedV1("missing source port"))?;
            let dst_port = fields
                .next()
                .ok_or(ProxyProtocolError::MalformedV1("missing dest port"))?;
            if fields.next().is_some() {
                return Err(ProxyProtocolError::MalformedV1("trailing fields"));
            }

            let source = parse_v1_endpoint(src_ip, src_port, is_v6)?;
            let destination = parse_v1_endpoint(dst_ip, dst_port, is_v6)?;
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source,
                destination,
            }
        }
        _ => return Err(ProxyProtocolError::MalformedV1("unknown protocol token")),
    };

    Ok((header, consumed))
}

fn parse_v1_endpoint(ip: &str, port: &str, is_v6: bool) -> Result<SocketAddr, ProxyProtocolError> {
    let port: u16 = port
        .parse()
        .map_err(|_| ProxyProtocolError::MalformedV1("invalid port"))?;
    if is_v6 {
        let ip: Ipv6Addr = ip
            .parse()
            .map_err(|_| ProxyProtocolError::MalformedV1("invalid IPv6 address"))?;
        Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| ProxyProtocolError::MalformedV1("invalid IPv4 address"))?;
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

// ---------------------------------------------------------------------------
// v2 (binary)
// ---------------------------------------------------------------------------

fn parse_v2(input: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    if input.len() < V2_HEADER_LEN {
        // Validate the partial signature so a non-v2 stream fails fast rather
        // than blocking on more bytes it will never satisfy.
        let seen = input.len().min(V2_SIGNATURE.len());
        if input[..seen] != V2_SIGNATURE[..seen] {
            return Err(ProxyProtocolError::InvalidSignature);
        }
        return Err(ProxyProtocolError::Incomplete {
            needed: V2_HEADER_LEN - input.len(),
        });
    }

    if input[..V2_SIGNATURE.len()] != V2_SIGNATURE {
        return Err(ProxyProtocolError::InvalidSignature);
    }

    let ver_cmd = input[12];
    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(ProxyProtocolError::UnsupportedVersion(version));
    }
    let command = ver_cmd & 0x0F;

    let fam_proto = input[13];
    let family = fam_proto >> 4;
    let proto = fam_proto & 0x0F;

    let addr_len = u16::from_be_bytes([input[14], input[15]]) as usize;
    let total = V2_HEADER_LEN + addr_len;
    if input.len() < total {
        return Err(ProxyProtocolError::Incomplete {
            needed: total - input.len(),
        });
    }
    let addr_block = &input[V2_HEADER_LEN..total];

    // LOCAL command: the receiver must use the real socket peer regardless of
    // any address block present. AF_UNSPEC likewise conveys nothing.
    if command == 0x00 || family == 0x00 {
        // Still validate the command nibble is a known value.
        if command > 0x01 {
            return Err(ProxyProtocolError::InvalidCommand(command));
        }
        return Ok((ProxyHeader::Local, total));
    }
    if command != 0x01 {
        return Err(ProxyProtocolError::InvalidCommand(command));
    }

    let transport = match proto {
        0x01 => Transport::Stream,
        0x02 => Transport::Dgram,
        other => return Err(ProxyProtocolError::UnsupportedTransport(other)),
    };

    let (source, destination) = match family {
        0x01 => decode_inet4(addr_block)?,
        0x02 => decode_inet6(addr_block)?,
        other => return Err(ProxyProtocolError::UnsupportedAddressFamily(other)),
    };

    Ok((
        ProxyHeader::Proxy {
            transport,
            source,
            destination,
        },
        total,
    ))
}

fn decode_inet4(block: &[u8]) -> Result<(SocketAddr, SocketAddr), ProxyProtocolError> {
    const NEED: usize = 12; // 4 + 4 + 2 + 2
    if block.len() < NEED {
        return Err(ProxyProtocolError::TruncatedAddressBlock {
            have: block.len(),
            need: NEED,
        });
    }
    let src_ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
    let dst_ip = Ipv4Addr::new(block[4], block[5], block[6], block[7]);
    let src_port = u16::from_be_bytes([block[8], block[9]]);
    let dst_port = u16::from_be_bytes([block[10], block[11]]);
    Ok((
        SocketAddr::V4(SocketAddrV4::new(src_ip, src_port)),
        SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
    ))
}

fn decode_inet6(block: &[u8]) -> Result<(SocketAddr, SocketAddr), ProxyProtocolError> {
    const NEED: usize = 36; // 16 + 16 + 2 + 2
    if block.len() < NEED {
        return Err(ProxyProtocolError::TruncatedAddressBlock {
            have: block.len(),
            need: NEED,
        });
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&block[0..16]);
    dst.copy_from_slice(&block[16..32]);
    let src_port = u16::from_be_bytes([block[32], block[33]]);
    let dst_port = u16::from_be_bytes([block[34], block[35]]);
    Ok((
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(src), src_port, 0, 0)),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(dst), dst_port, 0, 0)),
    ))
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

impl ProxyHeader {
    /// Encode this header in the v2 binary format.
    ///
    /// Always representable — v2 expresses `LOCAL`, TCP and UDP over IPv4/IPv6.
    ///
    /// # Panics
    ///
    /// Never panics. A mixed-family `Proxy` pair is impossible to construct via
    /// [`parse`] and is treated as `LOCAL` on encode (see [`Self::try_encode_v2`]
    /// for the checked variant).
    #[must_use]
    pub fn encode_v2(&self) -> Vec<u8> {
        self.try_encode_v2().unwrap_or_else(|_| encode_v2_local())
    }

    /// Encode this header in the v2 binary format, erroring on a mixed-family pair.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::MixedAddressFamily`] if `source` and
    /// `destination` are not the same address family.
    pub fn try_encode_v2(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        let ProxyHeader::Proxy {
            transport,
            source,
            destination,
        } = self
        else {
            return Ok(encode_v2_local());
        };

        let proto = match transport {
            Transport::Stream => 0x01u8,
            Transport::Dgram => 0x02u8,
        };

        let mut out = Vec::with_capacity(V2_HEADER_LEN + 36);
        out.extend_from_slice(&V2_SIGNATURE);
        out.push(0x21); // version 2, command PROXY

        match (source, destination) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => {
                out.push(0x10 | proto); // AF_INET
                out.extend_from_slice(&12u16.to_be_bytes());
                out.extend_from_slice(&s.ip().octets());
                out.extend_from_slice(&d.ip().octets());
                out.extend_from_slice(&s.port().to_be_bytes());
                out.extend_from_slice(&d.port().to_be_bytes());
            }
            (SocketAddr::V6(s), SocketAddr::V6(d)) => {
                out.push(0x20 | proto); // AF_INET6
                out.extend_from_slice(&36u16.to_be_bytes());
                out.extend_from_slice(&s.ip().octets());
                out.extend_from_slice(&d.ip().octets());
                out.extend_from_slice(&s.port().to_be_bytes());
                out.extend_from_slice(&d.port().to_be_bytes());
            }
            _ => return Err(ProxyProtocolError::MixedAddressFamily),
        }

        Ok(out)
    }

    /// Encode this header in the v1 text format.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::V1Unrepresentable`] for a `Dgram`
    /// transport — v1 is TCP-only — and [`ProxyProtocolError::MixedAddressFamily`]
    /// for a mixed-family source/destination pair.
    pub fn encode_v1(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        match self {
            ProxyHeader::Local => Ok(b"PROXY UNKNOWN\r\n".to_vec()),
            ProxyHeader::Proxy {
                transport: Transport::Dgram,
                ..
            } => Err(ProxyProtocolError::V1Unrepresentable("Dgram")),
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source,
                destination,
            } => {
                let line = match (source, destination) {
                    (SocketAddr::V4(s), SocketAddr::V4(d)) => format!(
                        "PROXY TCP4 {} {} {} {}\r\n",
                        s.ip(),
                        d.ip(),
                        s.port(),
                        d.port()
                    ),
                    (SocketAddr::V6(s), SocketAddr::V6(d)) => format!(
                        "PROXY TCP6 {} {} {} {}\r\n",
                        s.ip(),
                        d.ip(),
                        s.port(),
                        d.port()
                    ),
                    _ => return Err(ProxyProtocolError::MixedAddressFamily),
                };
                Ok(line.into_bytes())
            }
        }
    }
}

/// The canonical v2 `LOCAL` header: signature + version 2 / command LOCAL,
/// `AF_UNSPEC` / `UNSPEC` transport, zero-length address block.
#[must_use]
fn encode_v2_local() -> Vec<u8> {
    let mut out = Vec::with_capacity(V2_HEADER_LEN);
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(0x20); // version 2, command LOCAL
    out.push(0x00); // AF_UNSPEC, UNSPEC transport
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // --- v1 decode ---------------------------------------------------------

    #[test]
    fn v1_tcp4_decodes() {
        let input = b"PROXY TCP4 192.0.2.1 203.0.113.7 56324 443\r\nGET / HTTP/1.1\r\n";
        let (hdr, consumed) = parse(input).unwrap();
        assert_eq!(
            hdr,
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source: sa("192.0.2.1:56324"),
                destination: sa("203.0.113.7:443"),
            }
        );
        // Consumed exactly the header line; the HTTP request remains.
        assert_eq!(&input[consumed..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn v1_tcp6_decodes() {
        let input = b"PROXY TCP6 2001:db8::1 2001:db8::2 4321 443\r\n";
        let (hdr, consumed) = parse(input).unwrap();
        assert_eq!(
            hdr,
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source: sa("[2001:db8::1]:4321"),
                destination: sa("[2001:db8::2]:443"),
            }
        );
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn v1_unknown_is_local() {
        let input = b"PROXY UNKNOWN\r\n";
        let (hdr, consumed) = parse(input).unwrap();
        assert_eq!(hdr, ProxyHeader::Local);
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn v1_unknown_with_trailing_is_ignored() {
        // Spec: after UNKNOWN, receivers ignore up to the CRLF.
        let input = b"PROXY UNKNOWN 65535 65535 65535 65535\r\n";
        let (hdr, _) = parse(input).unwrap();
        assert_eq!(hdr, ProxyHeader::Local);
    }

    #[test]
    fn v1_partial_line_is_incomplete() {
        let input = b"PROXY TCP4 192.0.2.1 203.0.113.7 56324 44";
        assert!(matches!(
            parse(input),
            Err(ProxyProtocolError::Incomplete { .. })
        ));
    }

    #[test]
    fn v1_line_too_long() {
        // 107+ bytes with no CRLF.
        let mut input = b"PROXY TCP4 ".to_vec();
        input.extend(std::iter::repeat_n(b'9', V1_MAX_LEN));
        assert_eq!(parse(&input), Err(ProxyProtocolError::V1LineTooLong));
    }

    #[test]
    fn v1_bad_port_rejected() {
        let input = b"PROXY TCP4 192.0.2.1 203.0.113.7 99999 443\r\n";
        assert!(matches!(
            parse(input),
            Err(ProxyProtocolError::MalformedV1(_))
        ));
    }

    #[test]
    fn v1_bad_ip_rejected() {
        let input = b"PROXY TCP4 not.an.ip 203.0.113.7 100 443\r\n";
        assert!(matches!(
            parse(input),
            Err(ProxyProtocolError::MalformedV1(_))
        ));
    }

    #[test]
    fn v1_trailing_fields_rejected() {
        let input = b"PROXY TCP4 192.0.2.1 203.0.113.7 100 443 extra\r\n";
        assert!(matches!(
            parse(input),
            Err(ProxyProtocolError::MalformedV1(_))
        ));
    }

    // --- v2 decode ---------------------------------------------------------

    #[test]
    fn v2_inet4_round_trips() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: sa("192.0.2.1:56324"),
            destination: sa("203.0.113.7:443"),
        };
        let bytes = hdr.encode_v2();
        let (decoded, consumed) = parse(&bytes).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn v2_inet6_round_trips() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Dgram,
            source: sa("[2001:db8::1]:4321"),
            destination: sa("[2001:db8::2]:443"),
        };
        let bytes = hdr.encode_v2();
        let (decoded, consumed) = parse(&bytes).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn v2_local_round_trips() {
        let bytes = ProxyHeader::Local.encode_v2();
        let (decoded, consumed) = parse(&bytes).unwrap();
        assert_eq!(decoded, ProxyHeader::Local);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn v2_trailing_payload_boundary() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: sa("10.0.0.1:1000"),
            destination: sa("10.0.0.2:2000"),
        };
        let mut bytes = hdr.encode_v2();
        let header_len = bytes.len();
        bytes.extend_from_slice(b"POST /x");
        let (decoded, consumed) = parse(&bytes).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(consumed, header_len);
        assert_eq!(&bytes[consumed..], b"POST /x");
    }

    #[test]
    fn v2_tlv_bytes_are_skipped() {
        // A well-formed INET4 header whose length claims 4 extra TLV bytes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&V2_SIGNATURE);
        bytes.push(0x21); // v2, PROXY
        bytes.push(0x11); // AF_INET, STREAM
        bytes.extend_from_slice(&(12u16 + 4).to_be_bytes());
        bytes.extend_from_slice(&[192, 0, 2, 1, 203, 0, 113, 7]);
        bytes.extend_from_slice(&56324u16.to_be_bytes());
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes.extend_from_slice(&[0xEE; 4]); // TLV padding
        let (decoded, consumed) = parse(&bytes).unwrap();
        assert_eq!(
            decoded,
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source: sa("192.0.2.1:56324"),
                destination: sa("203.0.113.7:443"),
            }
        );
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn v2_partial_header_is_incomplete() {
        let full = ProxyHeader::Local.encode_v2();
        for cut in 1..full.len() {
            match parse(&full[..cut]) {
                Err(ProxyProtocolError::Incomplete { needed }) => assert!(needed > 0),
                other => panic!("expected Incomplete at cut {cut}, got {other:?}"),
            }
        }
    }

    #[test]
    fn v2_partial_address_block_is_incomplete() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: sa("192.0.2.1:1"),
            destination: sa("203.0.113.7:2"),
        };
        let full = hdr.encode_v2();
        // Truncate inside the address block (past the 16-byte fixed header).
        let (_, needed) = match parse(&full[..V2_HEADER_LEN + 4]) {
            Err(ProxyProtocolError::Incomplete { needed }) => ((), needed),
            other => panic!("expected Incomplete, got {other:?}"),
        };
        assert!(needed > 0);
    }

    #[test]
    fn v2_bad_signature_rejected() {
        let mut bytes = ProxyHeader::Local.encode_v2();
        bytes[5] = 0xFF; // corrupt inside the signature
        assert_eq!(parse(&bytes), Err(ProxyProtocolError::InvalidSignature));
    }

    #[test]
    fn v2_short_bad_signature_fails_fast() {
        // Starts with 0x0D but diverges from the signature before 16 bytes.
        let bytes = [0x0D, 0x0A, 0xFF, 0xFF];
        assert_eq!(parse(&bytes), Err(ProxyProtocolError::InvalidSignature));
    }

    #[test]
    fn v2_unsupported_version_rejected() {
        let mut bytes = ProxyHeader::Local.encode_v2();
        bytes[12] = 0x30; // version 3
        assert_eq!(
            parse(&bytes),
            Err(ProxyProtocolError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn v2_unix_family_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&V2_SIGNATURE);
        bytes.push(0x21); // v2, PROXY
        bytes.push(0x31); // AF_UNIX, STREAM
        bytes.extend_from_slice(&216u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 216]);
        assert_eq!(
            parse(&bytes),
            Err(ProxyProtocolError::UnsupportedAddressFamily(0x3))
        );
    }

    #[test]
    fn v2_bad_transport_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&V2_SIGNATURE);
        bytes.push(0x21);
        bytes.push(0x13); // AF_INET, transport 3 (invalid)
        bytes.extend_from_slice(&12u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        assert_eq!(
            parse(&bytes),
            Err(ProxyProtocolError::UnsupportedTransport(3))
        );
    }

    #[test]
    fn v2_local_command_ignores_addresses() {
        // LOCAL with an INET address block present -> Local (addresses ignored).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&V2_SIGNATURE);
        bytes.push(0x20); // v2, LOCAL
        bytes.push(0x11); // AF_INET, STREAM
        bytes.extend_from_slice(&12u16.to_be_bytes());
        bytes.extend_from_slice(&[192, 0, 2, 1, 203, 0, 113, 7]);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        let (hdr, consumed) = parse(&bytes).unwrap();
        assert_eq!(hdr, ProxyHeader::Local);
        assert_eq!(consumed, bytes.len());
    }

    // --- detection / boundaries -------------------------------------------

    #[test]
    fn non_proxy_bytes_rejected() {
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\n"),
            Err(ProxyProtocolError::NotProxyProtocol)
        );
    }

    #[test]
    fn empty_input_is_incomplete() {
        assert_eq!(
            parse(b""),
            Err(ProxyProtocolError::Incomplete { needed: 1 })
        );
    }

    #[test]
    fn v1_prefix_lookalike_is_incomplete() {
        // "P" alone can't yet be distinguished from a valid "PROXY " start.
        assert!(matches!(
            parse(b"PRO"),
            Err(ProxyProtocolError::Incomplete { .. })
        ));
    }

    // --- encode edge cases -------------------------------------------------

    #[test]
    fn encode_v1_dgram_unrepresentable() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Dgram,
            source: sa("192.0.2.1:1"),
            destination: sa("203.0.113.7:2"),
        };
        assert_eq!(
            hdr.encode_v1(),
            Err(ProxyProtocolError::V1Unrepresentable("Dgram"))
        );
    }

    #[test]
    fn encode_v1_local_is_unknown() {
        assert_eq!(
            ProxyHeader::Local.encode_v1().unwrap(),
            b"PROXY UNKNOWN\r\n"
        );
    }

    #[test]
    fn try_encode_v2_mixed_family_errors() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: sa("192.0.2.1:1"),
            destination: sa("[2001:db8::2]:2"),
        };
        assert_eq!(
            hdr.try_encode_v2(),
            Err(ProxyProtocolError::MixedAddressFamily)
        );
        // The infallible wrapper degrades to LOCAL rather than panicking.
        let bytes = hdr.encode_v2();
        assert_eq!(parse(&bytes).unwrap().0, ProxyHeader::Local);
    }

    #[test]
    fn v1_round_trips_through_encode_parse() {
        let hdr = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: sa("198.51.100.9:40000"),
            destination: sa("203.0.113.1:80"),
        };
        let bytes = hdr.encode_v1().unwrap();
        let (decoded, consumed) = parse(&bytes).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(consumed, bytes.len());
    }

    // --- fuzz-adjacent: never panic on arbitrary bytes ---------------------

    #[test]
    fn arbitrary_prefixes_never_panic() {
        for b in 0u16..=255 {
            let b = b as u8;
            let _ = parse(&[b]);
            let _ = parse(&[b, 0x00, 0x01, 0x02]);
            let _ = parse(&[b; 20]);
        }
    }
}
