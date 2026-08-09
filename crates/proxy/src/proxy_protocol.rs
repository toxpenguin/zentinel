//! Inbound PROXY protocol (v1/v2) acceptance.
//!
//! Listeners with a `proxy-protocol` block sit behind an L4 load balancer
//! (HAProxy, AWS NLB, ...) that prepends a PROXY header carrying the original
//! client address. This module implements Pingora's [`AcceptPreprocessor`]:
//! it runs per-connection, before TLS and before any buffering, decodes the
//! header with [`zentinel_common::proxy_protocol::parse`], and rewrites the
//! connection's reported peer address so logging, rate limiting, and geo
//! filtering all see the real client.
//!
//! # Security
//!
//! The header is only honored when the connection's *socket* peer is inside
//! the listener's `trusted` CIDR list. Everything else fails closed:
//! - untrusted peer → connection dropped (header would be spoofable)
//! - missing/garbage/malformed header on a PROXY listener → connection dropped
//! - header not complete within `header-timeout-ms` → connection dropped
//!
//! One acceptor serves all listeners of the proxy service; connections on
//! listeners without a `proxy-protocol` block pass through untouched.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora_core::listeners::AcceptPreprocessor;
use pingora_core::protocols::l4::socket::SocketAddr as L4SocketAddr;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::GetSocketDigest;
use pingora_core::{Error, ErrorType};
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};
use zentinel_common::net::Cidr;
use zentinel_common::proxy_protocol::{parse, ProxyHeader, ProxyProtocolError};
use zentinel_config::ListenerConfig;

/// Decoded per-listener acceptance rule.
#[derive(Debug)]
struct Rule {
    /// Listener id, for logs.
    listener_id: String,
    /// The bind IP when the listener binds a specific address; `None` for
    /// wildcard binds (`0.0.0.0` / `::`), which match any local IP on the port.
    bind_ip: Option<std::net::IpAddr>,
    /// Socket peers allowed to send a PROXY header.
    trusted: Vec<Cidr>,
    /// Deadline for the complete header.
    header_timeout: Duration,
}

/// Accept-time PROXY protocol decoder for all PROXY-enabled listeners.
///
/// Built once at startup from the listener configs; installed on the proxy
/// service via `Listeners::set_accept_preprocessor`.
#[derive(Debug, Default)]
pub struct ProxyProtocolAcceptor {
    /// Rules keyed by listener port. A port carries multiple rules only when
    /// several listeners bind the same port on different IPs.
    rules: HashMap<u16, Vec<Rule>>,
}

impl ProxyProtocolAcceptor {
    /// Build an acceptor from all listeners that enable `proxy-protocol`.
    ///
    /// Returns `Ok(None)` when no listener enables it (nothing to install).
    ///
    /// # Errors
    ///
    /// Returns an error when a PROXY-enabled listener's address or trusted
    /// CIDRs fail to parse — config validation should have caught both, so
    /// this failing means the config was not validated.
    pub fn from_listeners(listeners: &[ListenerConfig]) -> anyhow::Result<Option<Self>> {
        let mut rules: HashMap<u16, Vec<Rule>> = HashMap::new();

        for listener in listeners {
            let Some(pp) = &listener.proxy_protocol else {
                continue;
            };

            let addr: SocketAddr = listener.address.parse().map_err(|e| {
                anyhow::anyhow!(
                    "listener '{}': proxy-protocol requires a numeric bind address, \
                     got '{}': {}",
                    listener.id,
                    listener.address,
                    e
                )
            })?;

            let trusted = pp
                .trusted
                .iter()
                .map(|s| {
                    s.parse::<Cidr>().map_err(|e| {
                        anyhow::anyhow!(
                            "listener '{}': invalid trusted CIDR '{}': {}",
                            listener.id,
                            s,
                            e
                        )
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            rules.entry(addr.port()).or_default().push(Rule {
                listener_id: listener.id.clone(),
                bind_ip: (!addr.ip().is_unspecified()).then(|| addr.ip()),
                trusted,
                header_timeout: Duration::from_millis(pp.header_timeout_ms),
            });
        }

        if rules.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self { rules }))
        }
    }

    /// Find the rule for a connection's local (accept-side) address.
    ///
    /// Exact bind-IP rules win over wildcard-bind rules on the same port.
    fn rule_for(&self, local: &SocketAddr) -> Option<&Rule> {
        let candidates = self.rules.get(&local.port())?;
        candidates
            .iter()
            .find(|r| r.bind_ip == Some(local.ip()))
            .or_else(|| candidates.iter().find(|r| r.bind_ip.is_none()))
    }
}

/// Read a complete PROXY header from the stream without consuming a single
/// byte past it.
///
/// v2 is binary with exact length information, so the codec's
/// `Incomplete { needed }` hints are exact reads. v1 is a CRLF-terminated
/// text line whose `needed` hint is only an upper bound, so it is read one
/// byte at a time (bounded at 107 bytes by the codec). There is no buffered
/// look-ahead at this point in the connection, which is what makes exact-byte
/// consumption possible.
async fn read_header(stream: &mut L4Stream) -> Result<ProxyHeader, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(16);
    loop {
        match parse(&buf) {
            Ok((header, consumed)) => {
                debug_assert_eq!(consumed, buf.len(), "header reads must be exact");
                return Ok(header);
            }
            Err(ProxyProtocolError::Incomplete { needed }) => {
                let take = if buf.first() == Some(&b'P') {
                    1
                } else {
                    needed
                };
                let start = buf.len();
                buf.resize(start + take, 0);
                stream
                    .read_exact(&mut buf[start..])
                    .await
                    .map_err(|e| format!("connection closed mid-header: {e}"))?;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn abort(reason: &'static str, context: String) -> Box<Error> {
    Error::explain(ErrorType::Custom(reason), context)
}

/// Encode the PROXY header prefix for a new upstream connection.
///
/// `client`/`server` are the downstream connection's peer address (already
/// rewritten if inbound PROXY acceptance ran) and local address. When either
/// endpoint is unavailable, or the two are of mixed address families (which
/// the wire format cannot express), a LOCAL/UNKNOWN header is sent instead —
/// the backend then falls back to the socket peer, and is never handed a
/// fabricated client address.
pub fn encode_upstream_prefix(
    version: zentinel_config::ProxyProtocolVersion,
    client: Option<SocketAddr>,
    server: Option<SocketAddr>,
) -> bytes::Bytes {
    // Canonicalize v4-mapped v6 (`::ffff:a.b.c.d`) so a dual-stack listener
    // and a v4 destination still form a same-family TCP4 pair.
    let canonical = |addr: SocketAddr| SocketAddr::new(addr.ip().to_canonical(), addr.port());
    let client = client.map(canonical);
    let server = server.map(canonical);

    let header = match (client, server) {
        (Some(source), Some(destination)) if source.is_ipv4() == destination.is_ipv4() => {
            ProxyHeader::Proxy {
                transport: zentinel_common::proxy_protocol::Transport::Stream,
                source,
                destination,
            }
        }
        _ => {
            debug!(
                client = ?client,
                server = ?server,
                "PROXY emit: endpoints unavailable or mixed-family, sending LOCAL header"
            );
            ProxyHeader::Local
        }
    };

    let encoded = match version {
        zentinel_config::ProxyProtocolVersion::V1 => header
            .encode_v1()
            // Unreachable: Stream transport + same-family pair is always
            // v1-representable. Fall back to UNKNOWN rather than panic.
            .unwrap_or_else(|_| b"PROXY UNKNOWN\r\n".to_vec()),
        zentinel_config::ProxyProtocolVersion::V2 => header.encode_v2(),
    };
    bytes::Bytes::from(encoded)
}

#[async_trait]
impl AcceptPreprocessor for ProxyProtocolAcceptor {
    async fn preprocess(&self, stream: &mut L4Stream) -> pingora_core::Result<()> {
        let Some(digest) = stream.get_socket_digest() else {
            // Accepted TCP/UDS streams always carry a digest; without one we
            // cannot verify trust, so only non-PROXY traffic may proceed.
            return Ok(());
        };

        // UDS listeners have no inet local address and never match a rule.
        let Some(local) = digest.local_addr().and_then(|a| a.as_inet()).copied() else {
            return Ok(());
        };
        let Some(rule) = self.rule_for(&local) else {
            return Ok(());
        };

        let Some(peer) = digest.peer_addr().and_then(|a| a.as_inet()).copied() else {
            return Err(abort(
                "proxy_protocol_no_peer",
                format!(
                    "listener '{}': cannot verify PROXY trust without a peer address",
                    rule.listener_id
                ),
            ));
        };

        if !rule.trusted.iter().any(|c| c.contains(peer.ip())) {
            warn!(
                listener_id = %rule.listener_id,
                peer = %peer,
                "Dropping connection: PROXY protocol required but peer is not a trusted source"
            );
            return Err(abort(
                "proxy_protocol_untrusted",
                format!(
                    "listener '{}': peer {} not in trusted CIDRs",
                    rule.listener_id, peer
                ),
            ));
        }

        let header = tokio::time::timeout(rule.header_timeout, read_header(stream))
            .await
            .map_err(|_| {
                warn!(
                    listener_id = %rule.listener_id,
                    peer = %peer,
                    timeout_ms = rule.header_timeout.as_millis() as u64,
                    "Dropping connection: PROXY header not received in time"
                );
                abort(
                    "proxy_protocol_timeout",
                    format!(
                        "listener '{}': PROXY header from {} incomplete after {:?}",
                        rule.listener_id, peer, rule.header_timeout
                    ),
                )
            })?
            .map_err(|e| {
                warn!(
                    listener_id = %rule.listener_id,
                    peer = %peer,
                    error = %e,
                    "Dropping connection: invalid PROXY header"
                );
                abort(
                    "proxy_protocol_invalid",
                    format!(
                        "listener '{}': invalid PROXY header from {}: {}",
                        rule.listener_id, peer, e
                    ),
                )
            })?;

        match header {
            ProxyHeader::Local => {
                // Health checks etc.: keep the real socket peer address.
                debug!(
                    listener_id = %rule.listener_id,
                    peer = %peer,
                    "PROXY LOCAL header accepted; keeping socket peer address"
                );
            }
            ProxyHeader::Proxy { source, .. } => {
                // set() only fails if already set; preprocess runs once per
                // connection, before anything else can touch the override.
                let _ = digest.peer_addr_override.set(L4SocketAddr::Inet(source));
                debug!(
                    listener_id = %rule.listener_id,
                    proxy_peer = %peer,
                    client = %source,
                    "PROXY header accepted; client address rewritten"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use zentinel_common::proxy_protocol::Transport;
    use zentinel_config::{ListenerProtocol, ProxyProtocolConfig};

    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;

    fn listener(id: &str, address: &str, pp: Option<ProxyProtocolConfig>) -> ListenerConfig {
        ListenerConfig {
            id: id.to_string(),
            address: address.to_string(),
            protocol: ListenerProtocol::Http,
            tls: None,
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            proxy_protocol: pp,
        }
    }

    fn pp_config(trusted: &[&str], timeout_ms: u64) -> ProxyProtocolConfig {
        ProxyProtocolConfig {
            trusted: trusted.iter().map(|s| s.to_string()).collect(),
            header_timeout_ms: timeout_ms,
        }
    }

    /// Accept one connection on an ephemeral port; return the acceptor built
    /// for that port, the server-side L4 stream (digest attached, like
    /// Pingora's accept path does), and the client socket.
    async fn accept_pair(
        trusted: &[&str],
        timeout_ms: u64,
    ) -> (ProxyProtocolAcceptor, L4Stream, tokio::net::TcpStream) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = tcp.local_addr().expect("local addr").port();

        let acceptor = ProxyProtocolAcceptor::from_listeners(&[listener(
            "test",
            &format!("127.0.0.1:{port}"),
            Some(pp_config(trusted, timeout_ms)),
        )])
        .expect("build acceptor")
        .expect("acceptor must be Some for PROXY-enabled listener");

        let client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (server, peer_addr) = tcp.accept().await.expect("accept");

        let mut stream: L4Stream = server.into();
        let digest = pingora_core::protocols::SocketDigest::from_raw_fd(stream.as_raw_fd());
        digest
            .peer_addr
            .set(Some(L4SocketAddr::Inet(peer_addr)))
            .expect("fresh digest");
        stream.set_socket_digest(digest);

        (acceptor, stream, client)
    }

    fn client_source() -> SocketAddr {
        "203.0.113.7:51234".parse().expect("test addr")
    }

    #[tokio::test]
    async fn v2_header_from_trusted_peer_rewrites_client_address() {
        let (acceptor, mut stream, mut client) = accept_pair(&["127.0.0.0/8"], 2000).await;

        let header = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: client_source(),
            destination: "10.0.0.1:443".parse().expect("test addr"),
        };
        let mut bytes = header.encode_v2();
        bytes.extend_from_slice(b"GET");
        client.write_all(&bytes).await.expect("client write");

        acceptor
            .preprocess(&mut stream)
            .await
            .expect("trusted v2 header must be accepted");

        let digest = stream.get_socket_digest().expect("digest");
        assert_eq!(
            digest.peer_addr().and_then(|a| a.as_inet()).copied(),
            Some(client_source())
        );

        // Application bytes after the header remain unread on the stream.
        let mut app = [0u8; 3];
        stream.read_exact(&mut app).await.expect("read app bytes");
        assert_eq!(&app, b"GET");
    }

    #[tokio::test]
    async fn v1_header_consumes_exactly_through_crlf() {
        let (acceptor, mut stream, mut client) = accept_pair(&["127.0.0.0/8"], 2000).await;

        client
            .write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\nGET")
            .await
            .expect("client write");

        acceptor
            .preprocess(&mut stream)
            .await
            .expect("trusted v1 header must be accepted");

        let digest = stream.get_socket_digest().expect("digest");
        assert_eq!(
            digest.peer_addr().and_then(|a| a.as_inet()).copied(),
            Some(client_source())
        );

        let mut app = [0u8; 3];
        stream.read_exact(&mut app).await.expect("read app bytes");
        assert_eq!(&app, b"GET");
    }

    #[tokio::test]
    async fn untrusted_peer_is_dropped_before_reading() {
        let (acceptor, mut stream, mut client) = accept_pair(&["10.0.0.0/8"], 2000).await;

        // Even a valid header must not be honored from an untrusted peer.
        client
            .write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\n")
            .await
            .expect("client write");

        let err = acceptor
            .preprocess(&mut stream)
            .await
            .expect_err("untrusted peer must be rejected");
        assert!(err.to_string().contains("proxy_protocol_untrusted"));
    }

    #[tokio::test]
    async fn garbage_first_bytes_drop_the_connection() {
        let (acceptor, mut stream, mut client) = accept_pair(&["127.0.0.0/8"], 2000).await;

        client
            .write_all(b"GET / HTTP/1.1\r\n")
            .await
            .expect("client write");

        let err = acceptor
            .preprocess(&mut stream)
            .await
            .expect_err("non-PROXY bytes on a PROXY listener must be rejected");
        assert!(err.to_string().contains("proxy_protocol_invalid"));
    }

    #[tokio::test]
    async fn local_header_keeps_socket_peer_address() {
        let (acceptor, mut stream, mut client) = accept_pair(&["127.0.0.0/8"], 2000).await;

        client
            .write_all(b"PROXY UNKNOWN\r\n")
            .await
            .expect("client write");

        acceptor
            .preprocess(&mut stream)
            .await
            .expect("LOCAL/UNKNOWN header must be accepted");

        let digest = stream.get_socket_digest().expect("digest");
        let peer = digest
            .peer_addr()
            .and_then(|a| a.as_inet())
            .copied()
            .expect("peer");
        assert_eq!(
            peer.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().expect("ip")
        );
    }

    #[tokio::test]
    async fn stalled_header_times_out() {
        let (acceptor, mut stream, client) = accept_pair(&["127.0.0.0/8"], 100).await;

        // Send only the start of a v2 signature, then stall (keep the socket open).
        let (read_half, mut write_half) = client.into_split();
        write_half
            .write_all(&[0x0D, 0x0A])
            .await
            .expect("client write");

        let err = acceptor
            .preprocess(&mut stream)
            .await
            .expect_err("stalled header must time out");
        assert!(err.to_string().contains("proxy_protocol_timeout"));

        // Both halves stay open until here so the server sees a stall, not EOF.
        drop(read_half);
        drop(write_half);
    }

    #[tokio::test]
    async fn listener_without_rule_is_untouched() {
        // Build the acceptor for a *different* port than the accepted socket.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = tcp.local_addr().expect("local addr").port();
        let other_port = if port == 1 { 2 } else { port - 1 };

        let acceptor = ProxyProtocolAcceptor::from_listeners(&[listener(
            "other",
            &format!("127.0.0.1:{other_port}"),
            Some(pp_config(&["10.0.0.0/8"], 2000)),
        )])
        .expect("build acceptor")
        .expect("acceptor present");

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (server, peer_addr) = tcp.accept().await.expect("accept");
        let mut stream: L4Stream = server.into();
        let digest = pingora_core::protocols::SocketDigest::from_raw_fd(stream.as_raw_fd());
        digest
            .peer_addr
            .set(Some(L4SocketAddr::Inet(peer_addr)))
            .expect("fresh digest");
        stream.set_socket_digest(digest);

        client.write_all(b"GET").await.expect("client write");

        acceptor
            .preprocess(&mut stream)
            .await
            .expect("non-PROXY listener must pass through");

        // Bytes still there: preprocessor must not have consumed anything.
        let mut app = [0u8; 3];
        stream.read_exact(&mut app).await.expect("read app bytes");
        assert_eq!(&app, b"GET");
    }

    #[test]
    fn upstream_prefix_v2_round_trips_through_codec() {
        let client: SocketAddr = "203.0.113.7:51234".parse().expect("addr");
        let server: SocketAddr = "10.0.0.1:8080".parse().expect("addr");
        let prefix = encode_upstream_prefix(
            zentinel_config::ProxyProtocolVersion::V2,
            Some(client),
            Some(server),
        );

        let (header, consumed) = parse(&prefix).expect("prefix must decode");
        assert_eq!(consumed, prefix.len());
        assert_eq!(
            header,
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source: client,
                destination: server,
            }
        );
    }

    #[test]
    fn upstream_prefix_v1_is_text_form() {
        let prefix = encode_upstream_prefix(
            zentinel_config::ProxyProtocolVersion::V1,
            Some("203.0.113.7:51234".parse().expect("addr")),
            Some("10.0.0.1:8080".parse().expect("addr")),
        );
        assert_eq!(
            &prefix[..],
            b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 8080\r\n"
        );
    }

    #[test]
    fn upstream_prefix_missing_endpoint_falls_back_to_local() {
        let prefix = encode_upstream_prefix(
            zentinel_config::ProxyProtocolVersion::V2,
            None,
            Some("10.0.0.1:8080".parse().expect("addr")),
        );
        let (header, _) = parse(&prefix).expect("prefix must decode");
        assert_eq!(header, ProxyHeader::Local);

        let v1 = encode_upstream_prefix(zentinel_config::ProxyProtocolVersion::V1, None, None);
        assert_eq!(&v1[..], b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn upstream_prefix_mixed_family_falls_back_to_local() {
        let prefix = encode_upstream_prefix(
            zentinel_config::ProxyProtocolVersion::V2,
            Some("203.0.113.7:51234".parse().expect("addr")),
            Some("[2001:db8::1]:8080".parse().expect("addr")),
        );
        let (header, _) = parse(&prefix).expect("prefix must decode");
        assert_eq!(header, ProxyHeader::Local);
    }

    #[test]
    fn upstream_prefix_canonicalizes_v4_mapped_client() {
        let prefix = encode_upstream_prefix(
            zentinel_config::ProxyProtocolVersion::V2,
            Some("[::ffff:203.0.113.7]:51234".parse().expect("addr")),
            Some("10.0.0.1:8080".parse().expect("addr")),
        );
        let (header, _) = parse(&prefix).expect("prefix must decode");
        assert_eq!(
            header,
            ProxyHeader::Proxy {
                transport: Transport::Stream,
                source: "203.0.113.7:51234".parse().expect("addr"),
                destination: "10.0.0.1:8080".parse().expect("addr"),
            }
        );
    }

    #[test]
    fn from_listeners_returns_none_without_proxy_protocol() {
        let acceptor =
            ProxyProtocolAcceptor::from_listeners(&[listener("plain", "0.0.0.0:8080", None)])
                .expect("build");
        assert!(acceptor.is_none());
    }

    #[test]
    fn exact_bind_ip_rule_wins_over_wildcard() {
        let acceptor = ProxyProtocolAcceptor::from_listeners(&[
            listener(
                "wild",
                "0.0.0.0:8080",
                Some(pp_config(&["10.0.0.0/8"], 2000)),
            ),
            listener(
                "exact",
                "192.0.2.1:8080",
                Some(pp_config(&["172.16.0.0/12"], 2000)),
            ),
        ])
        .expect("build")
        .expect("present");

        let exact = acceptor
            .rule_for(&"192.0.2.1:8080".parse().expect("addr"))
            .expect("rule");
        assert_eq!(exact.listener_id, "exact");

        let wild = acceptor
            .rule_for(&"192.0.2.99:8080".parse().expect("addr"))
            .expect("rule");
        assert_eq!(wild.listener_id, "wild");

        assert!(acceptor
            .rule_for(&"192.0.2.1:9999".parse().expect("addr"))
            .is_none());
    }
}
