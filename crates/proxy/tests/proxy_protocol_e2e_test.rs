//! Real-IP propagation conformance: LB → Zentinel → backend.
//!
//! Asserts the property IDEAS #16 (Imunify360/Apache coexistence) depends on:
//! a client address carried in by a trusted load balancer's PROXY header is
//! the address Zentinel reports for the connection, and the address Zentinel
//! forwards in the PROXY header it emits to the backend — end to end over
//! real sockets, both protocol versions.
//!
//! The chain mirrors production exactly at the seams Zentinel owns:
//! - inbound: `ProxyProtocolAcceptor::preprocess` runs against an accepted
//!   L4 stream with its socket digest attached, exactly as the Pingora fork
//!   invokes it before TLS/buffering;
//! - outbound: `encode_upstream_prefix` output is written to the backend
//!   socket before application bytes, exactly as the fork's connector writes
//!   `PeerOptions.connect_prefix`.

#[cfg(unix)]
mod e2e {
    use std::net::SocketAddr;
    use std::os::unix::io::AsRawFd;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use pingora_core::listeners::AcceptPreprocessor;
    use pingora_core::protocols::l4::socket::SocketAddr as L4SocketAddr;
    use pingora_core::protocols::l4::stream::Stream as L4Stream;
    use pingora_core::protocols::{GetSocketDigest, SocketDigest};
    use zentinel_common::proxy_protocol::{parse, ProxyHeader, ProxyProtocolError, Transport};
    use zentinel_config::{ListenerConfig, ListenerProtocol, ProxyProtocolConfig};
    use zentinel_proxy::proxy_protocol::{encode_upstream_prefix, ProxyProtocolAcceptor};

    /// The original client as the load balancer saw it.
    fn original_client() -> SocketAddr {
        "203.0.113.7:51234".parse().expect("test addr")
    }

    fn listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "edge".to_string(),
            address: address.to_string(),
            protocol: ListenerProtocol::Http,
            tls: None,
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            proxy_protocol: Some(ProxyProtocolConfig {
                trusted: vec!["127.0.0.0/8".to_string()],
                header_timeout_ms: 2000,
            }),
        }
    }

    /// Accept one connection and attach a socket digest the way Pingora's
    /// accept path does.
    async fn accept_with_digest(listener: &tokio::net::TcpListener) -> L4Stream {
        let (server, peer_addr) = listener.accept().await.expect("accept");
        let mut stream: L4Stream = server.into();
        let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
        digest
            .peer_addr
            .set(Some(L4SocketAddr::Inet(peer_addr)))
            .expect("fresh digest");
        stream.set_socket_digest(digest);
        stream
    }

    /// Read a PROXY header from the backend side of the wire, tolerant of
    /// arbitrary read chunking, and return it with any application bytes
    /// that followed.
    async fn backend_read_header(
        stream: &mut tokio::net::TcpStream,
        expected_app: usize,
    ) -> (ProxyHeader, Vec<u8>) {
        let mut buf = Vec::new();
        loop {
            match parse(&buf) {
                Ok((header, consumed)) => {
                    let mut app = buf[consumed..].to_vec();
                    while app.len() < expected_app {
                        let mut chunk = [0u8; 256];
                        let n = stream.read(&mut chunk).await.expect("backend read");
                        assert!(n > 0, "connection closed before app bytes arrived");
                        app.extend_from_slice(&chunk[..n]);
                    }
                    return (header, app);
                }
                Err(ProxyProtocolError::Incomplete { .. }) => {
                    let mut chunk = [0u8; 256];
                    let n = stream.read(&mut chunk).await.expect("backend read");
                    assert!(n > 0, "connection closed mid-header");
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) => panic!("backend received invalid PROXY header: {e}"),
            }
        }
    }

    /// Full chain for one protocol version pair (inbound always v2 here —
    /// what AWS NLB/HAProxy send-proxy-v2 emit; outbound version varies).
    async fn propagate(outbound: zentinel_config::ProxyProtocolVersion) {
        // --- Edge: Zentinel's PROXY-enabled listener --------------------
        let edge = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind edge");
        let edge_port = edge.local_addr().expect("edge addr").port();

        let acceptor = ProxyProtocolAcceptor::from_listeners(&[listener_config(&format!(
            "127.0.0.1:{edge_port}"
        ))])
        .expect("build acceptor")
        .expect("acceptor present");

        // --- LB: trusted peer prepending the original client ------------
        let mut lb = tokio::net::TcpStream::connect(("127.0.0.1", edge_port))
            .await
            .expect("lb connect");
        let header = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: original_client(),
            destination: "10.0.0.1:443".parse().expect("test addr"),
        };
        let mut wire = header.encode_v2();
        wire.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        lb.write_all(&wire).await.expect("lb write");

        // --- Zentinel inbound: preprocess rewrites the peer -------------
        let mut downstream = accept_with_digest(&edge).await;
        acceptor
            .preprocess(&mut downstream)
            .await
            .expect("trusted PROXY header accepted");

        let digest = downstream.get_socket_digest().expect("digest");
        let client_addr = digest
            .peer_addr()
            .and_then(|a| a.as_inet())
            .copied()
            .expect("client addr");
        assert_eq!(
            client_addr,
            original_client(),
            "session must report the LB-conveyed client, not the LB socket"
        );
        let local_addr = digest
            .local_addr()
            .and_then(|a| a.as_inet())
            .copied()
            .expect("local addr");

        // --- Zentinel outbound: emit toward the backend -----------------
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_addr = backend.local_addr().expect("backend addr");

        let prefix = encode_upstream_prefix(outbound, Some(client_addr), Some(local_addr));

        // Mirror the fork's connector: prefix first, flush, then app bytes.
        let mut upstream_conn = tokio::net::TcpStream::connect(backend_addr)
            .await
            .expect("connect backend");
        upstream_conn
            .write_all(&prefix)
            .await
            .expect("write prefix");
        upstream_conn.flush().await.expect("flush prefix");
        upstream_conn.write_all(b"GET").await.expect("write app");

        // --- Backend: decodes the header, sees the original client -----
        let (mut backend_conn, _) = backend.accept().await.expect("backend accept");
        let (header, app) = backend_read_header(&mut backend_conn, 3).await;

        match header {
            ProxyHeader::Proxy {
                transport,
                source,
                destination,
            } => {
                assert_eq!(transport, Transport::Stream);
                assert_eq!(
                    source,
                    original_client(),
                    "backend must see the original client address end-to-end"
                );
                assert_eq!(destination, local_addr);
            }
            ProxyHeader::Local => panic!("backend received LOCAL, expected client endpoints"),
        }
        assert_eq!(
            &app, b"GET",
            "application bytes must follow the header intact"
        );
    }

    #[tokio::test]
    async fn real_client_ip_propagates_lb_to_backend_v2() {
        propagate(zentinel_config::ProxyProtocolVersion::V2).await;
    }

    #[tokio::test]
    async fn real_client_ip_propagates_lb_to_backend_v1() {
        propagate(zentinel_config::ProxyProtocolVersion::V1).await;
    }

    /// The security half of the conformance story: the same wire bytes from
    /// an untrusted source must not rewrite the client address.
    #[tokio::test]
    async fn untrusted_lb_cannot_inject_client_address() {
        let edge = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind edge");
        let edge_port = edge.local_addr().expect("edge addr").port();

        let mut config = listener_config(&format!("127.0.0.1:{edge_port}"));
        config.proxy_protocol = Some(ProxyProtocolConfig {
            // Loopback is NOT trusted here, so the test connection is hostile.
            trusted: vec!["198.51.100.0/24".to_string()],
            header_timeout_ms: 2000,
        });
        let acceptor = ProxyProtocolAcceptor::from_listeners(&[config])
            .expect("build acceptor")
            .expect("acceptor present");

        let mut attacker = tokio::net::TcpStream::connect(("127.0.0.1", edge_port))
            .await
            .expect("connect");
        let header = ProxyHeader::Proxy {
            transport: Transport::Stream,
            source: "198.51.100.99:443".parse().expect("test addr"),
            destination: "10.0.0.1:443".parse().expect("test addr"),
        };
        attacker
            .write_all(&header.encode_v2())
            .await
            .expect("attacker write");

        let mut downstream = accept_with_digest(&edge).await;
        let err = acceptor
            .preprocess(&mut downstream)
            .await
            .expect_err("spoofed header from untrusted source must drop the connection");
        assert!(err.to_string().contains("proxy_protocol_untrusted"));

        // And the reported peer is still the real socket peer.
        let digest = downstream.get_socket_digest().expect("digest");
        let peer = digest
            .peer_addr()
            .and_then(|a| a.as_inet())
            .copied()
            .expect("peer");
        assert!(peer.ip().is_loopback(), "peer must remain the socket peer");
    }
}
