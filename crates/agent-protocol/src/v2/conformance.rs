//! Agent conformance harness (`zentinel agent conform`).
//!
//! Language-agnostic compliance checks for v2 agents over the binary UDS
//! transport: the harness connects to a **running agent's socket** exactly
//! like the proxy does and verifies the protocol contract — handshake,
//! decision shape, correlation-ID routing, ping/pong, and resilience to
//! malformed payloads. An agent that passes every check can claim
//! "passes zentinel-conformance v{`CONFORMANCE_VERSION`}" regardless of
//! implementation language.
//!
//! Each check uses a fresh connection so one failure cannot cascade into
//! unrelated checks, and every read is bounded by [`IO_TIMEOUT`] — a hung
//! agent fails loudly instead of hanging the harness.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;

use crate::protocol::PROTOCOL_VERSION;
use crate::{AgentResponse, RequestHeadersEvent, RequestMetadata};

use super::uds::{
    read_message, write_message, MessageType, UdsHandshakeRequest, UdsHandshakeResponse,
};

/// Version of this check suite. Bump when checks are added or tightened so
/// "passes zentinel-conformance vX" stays meaningful.
pub const CONFORMANCE_VERSION: u32 = 1;

/// Per-operation I/O bound. An agent that cannot answer within this is
/// non-conformant by definition (the proxy's default call timeout is 1s).
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a single conformance check.
#[derive(Debug, Serialize)]
pub struct CheckResult {
    /// Stable check identifier.
    pub name: &'static str,
    /// What the check verifies.
    pub description: &'static str,
    /// Whether the agent passed.
    pub passed: bool,
    /// Failure detail (empty when passed).
    pub detail: String,
}

/// Full conformance report.
#[derive(Debug, Serialize)]
pub struct ConformanceReport {
    /// Suite version (see [`CONFORMANCE_VERSION`]).
    pub conformance_version: u32,
    /// Socket the agent was probed on.
    pub socket: String,
    /// Individual check outcomes.
    pub checks: Vec<CheckResult>,
    /// True when every check passed.
    pub passed: bool,
}

impl ConformanceReport {
    /// Render a human-readable report.
    #[must_use]
    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Zentinel agent conformance v{} — {}",
            self.conformance_version, self.socket
        );
        for c in &self.checks {
            let mark = if c.passed { "PASS" } else { "FAIL" };
            let _ = writeln!(out, "  [{mark}] {} — {}", c.name, c.description);
            if !c.passed {
                let _ = writeln!(out, "         {}", c.detail);
            }
        }
        let _ = writeln!(
            out,
            "{}",
            if self.passed {
                format!(
                    "Result: PASS — agent passes zentinel-conformance v{}",
                    self.conformance_version
                )
            } else {
                "Result: FAIL".to_string()
            }
        );
        out
    }
}

/// Run the full conformance suite against the agent listening on `socket`.
///
/// Never returns an error for agent misbehavior — that is what failed checks
/// are for. The socket being unreachable is reported as a failed first check.
pub async fn run(socket: &Path) -> ConformanceReport {
    let mut checks = Vec::new();

    checks.push(check_handshake(socket).await);
    checks.push(check_version_rejection(socket).await);
    checks.push(check_decision_shape(socket).await);
    checks.push(check_correlation_routing(socket).await);
    checks.push(check_ping_pong(socket).await);
    checks.push(check_malformed_payload(socket).await);

    let passed = checks.iter().all(|c| c.passed);
    ConformanceReport {
        conformance_version: CONFORMANCE_VERSION,
        socket: socket.display().to_string(),
        checks,
        passed,
    }
}

// ─── Connection plumbing ─────────────────────────────────────────────────────

type Reader = BufReader<tokio::net::unix::OwnedReadHalf>;
type Writer = BufWriter<tokio::net::unix::OwnedWriteHalf>;

async fn connect(socket: &Path) -> Result<(Reader, Writer), String> {
    let stream = tokio::time::timeout(IO_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect failed: {e}"))?;
    let (r, w) = stream.into_split();
    Ok((BufReader::new(r), BufWriter::new(w)))
}

async fn send(writer: &mut Writer, msg_type: MessageType, payload: &[u8]) -> Result<(), String> {
    tokio::time::timeout(IO_TIMEOUT, write_message(writer, msg_type, payload))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|e| format!("write failed: {e}"))
}

async fn recv(reader: &mut Reader) -> Result<(MessageType, Vec<u8>), String> {
    tokio::time::timeout(IO_TIMEOUT, read_message(reader))
        .await
        .map_err(|_| format!("no reply within {IO_TIMEOUT:?}"))?
        .map_err(|e| format!("read failed: {e}"))
}

fn handshake_request(versions: Vec<u32>) -> Vec<u8> {
    serde_json::to_vec(&UdsHandshakeRequest {
        supported_versions: versions,
        proxy_id: "zentinel-conformance".to_string(),
        proxy_version: env!("CARGO_PKG_VERSION").to_string(),
        config: None,
        supported_encodings: vec![],
    })
    .expect("handshake serializes")
}

/// Connect and complete a successful v2 handshake.
async fn connect_and_handshake(socket: &Path) -> Result<(Reader, Writer), String> {
    let (mut reader, mut writer) = connect(socket).await?;
    send(
        &mut writer,
        MessageType::HandshakeRequest,
        &handshake_request(vec![PROTOCOL_VERSION]),
    )
    .await?;
    let (msg_type, payload) = recv(&mut reader).await?;
    if msg_type != MessageType::HandshakeResponse {
        return Err(format!("expected HandshakeResponse, got {msg_type:?}"));
    }
    let resp: UdsHandshakeResponse =
        serde_json::from_slice(&payload).map_err(|e| format!("handshake decode: {e}"))?;
    if !resp.success {
        return Err(format!("handshake rejected: {:?}", resp.error));
    }
    Ok((reader, writer))
}

fn test_event(correlation_id: &str) -> Vec<u8> {
    serde_json::to_vec(&RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: correlation_id.to_string(),
            request_id: correlation_id.to_string(),
            client_ip: "203.0.113.7".to_string(),
            client_port: 443,
            server_name: None,
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            traceparent: None,
        },
        method: "GET".to_string(),
        uri: "/conformance".to_string(),
        headers: std::collections::HashMap::new(),
    })
    .expect("event serializes")
}

fn response_cid(resp: &AgentResponse) -> Option<&str> {
    resp.audit
        .custom
        .get("correlation_id")
        .and_then(|v| v.as_str())
}

// ─── Checks ──────────────────────────────────────────────────────────────────

fn result(
    name: &'static str,
    description: &'static str,
    outcome: Result<(), String>,
) -> CheckResult {
    match outcome {
        Ok(()) => CheckResult {
            name,
            description,
            passed: true,
            detail: String::new(),
        },
        Err(detail) => CheckResult {
            name,
            description,
            passed: false,
            detail,
        },
    }
}

async fn check_handshake(socket: &Path) -> CheckResult {
    let outcome = async {
        let (mut reader, mut writer) = connect(socket).await?;
        send(
            &mut writer,
            MessageType::HandshakeRequest,
            &handshake_request(vec![PROTOCOL_VERSION]),
        )
        .await?;
        let (msg_type, payload) = recv(&mut reader).await?;
        if msg_type != MessageType::HandshakeResponse {
            return Err(format!(
                "expected HandshakeResponse (0x02), got {msg_type:?}"
            ));
        }
        let resp: UdsHandshakeResponse = serde_json::from_slice(&payload)
            .map_err(|e| format!("response not valid JSON: {e}"))?;
        if !resp.success {
            return Err(format!(
                "success=false for supported version: {:?}",
                resp.error
            ));
        }
        if resp.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "protocol_version={}, want {PROTOCOL_VERSION}",
                resp.protocol_version
            ));
        }
        let caps = &resp.capabilities;
        if caps.agent_id.is_empty() || caps.name.is_empty() || caps.version.is_empty() {
            return Err("capabilities agent_id/name/version must be non-empty".to_string());
        }
        if !caps.supported_events.contains(&1) {
            return Err(format!(
                "supported_events {:?} must include 1 (RequestHeaders)",
                caps.supported_events
            ));
        }
        Ok(())
    }
    .await;
    result(
        "handshake",
        "valid handshake response with well-formed capabilities",
        outcome,
    )
}

async fn check_version_rejection(socket: &Path) -> CheckResult {
    let outcome = async {
        let (mut reader, mut writer) = connect(socket).await?;
        send(
            &mut writer,
            MessageType::HandshakeRequest,
            &handshake_request(vec![99]),
        )
        .await?;
        let (msg_type, payload) = recv(&mut reader).await?;
        if msg_type != MessageType::HandshakeResponse {
            return Err(format!("expected HandshakeResponse, got {msg_type:?}"));
        }
        let resp: UdsHandshakeResponse = serde_json::from_slice(&payload)
            .map_err(|e| format!("response not valid JSON: {e}"))?;
        if resp.success {
            return Err("accepted unknown protocol version 99".to_string());
        }
        if resp.error.as_deref().unwrap_or("").is_empty() {
            return Err("rejection must carry an error message".to_string());
        }
        Ok(())
    }
    .await;
    result(
        "version_rejection",
        "unknown protocol version is rejected with an error",
        outcome,
    )
}

async fn check_decision_shape(socket: &Path) -> CheckResult {
    let outcome = async {
        let (mut reader, mut writer) = connect_and_handshake(socket).await?;
        send(
            &mut writer,
            MessageType::RequestHeaders,
            &test_event("conform-decision"),
        )
        .await?;
        let (msg_type, payload) = recv(&mut reader).await?;
        if msg_type != MessageType::AgentResponse {
            return Err(format!("expected AgentResponse (0x20), got {msg_type:?}"));
        }
        let resp: AgentResponse = serde_json::from_slice(&payload)
            .map_err(|e| format!("response does not deserialize as AgentResponse: {e}"))?;
        if resp.version != PROTOCOL_VERSION {
            return Err(format!("version={}, want {PROTOCOL_VERSION}", resp.version));
        }
        Ok(())
    }
    .await;
    result(
        "decision_shape",
        "RequestHeaders is answered with a well-formed AgentResponse",
        outcome,
    )
}

async fn check_correlation_routing(socket: &Path) -> CheckResult {
    let outcome = async {
        let (mut reader, mut writer) = connect_and_handshake(socket).await?;
        for cid in ["conform-cid-1", "conform-cid-2"] {
            send(&mut writer, MessageType::RequestHeaders, &test_event(cid)).await?;
            let (_, payload) = recv(&mut reader).await?;
            let resp: AgentResponse =
                serde_json::from_slice(&payload).map_err(|e| format!("response decode: {e}"))?;
            match response_cid(&resp) {
                Some(got) if got == cid => {}
                other => {
                    return Err(format!(
                        "audit.custom.correlation_id = {other:?}, want {cid:?} \
                         (the proxy routes responses by it; without it every \
                         in-flight request on the connection stalls)"
                    ));
                }
            }
        }
        Ok(())
    }
    .await;
    result(
        "correlation_routing",
        "responses echo the request correlation_id in audit.custom",
        outcome,
    )
}

async fn check_ping_pong(socket: &Path) -> CheckResult {
    let outcome = async {
        let (mut reader, mut writer) = connect_and_handshake(socket).await?;
        let payload = br#"{"seq":42}"#;
        send(&mut writer, MessageType::Ping, payload).await?;
        let (msg_type, echoed) = recv(&mut reader).await?;
        if msg_type != MessageType::Pong {
            return Err(format!("expected Pong (0x42), got {msg_type:?}"));
        }
        if echoed != payload {
            return Err("pong must echo the ping payload".to_string());
        }
        Ok(())
    }
    .await;
    result(
        "ping_pong",
        "ping is answered with an echoing pong",
        outcome,
    )
}

async fn check_malformed_payload(socket: &Path) -> CheckResult {
    let outcome = async {
        let (mut reader, mut writer) = connect_and_handshake(socket).await?;
        // Garbage payload on a valid frame: the agent may answer or drop it,
        // but must not crash, hang, or close the connection.
        send(
            &mut writer,
            MessageType::RequestHeaders,
            b"\x00not json\xff",
        )
        .await?;

        send(
            &mut writer,
            MessageType::RequestHeaders,
            &test_event("conform-after-garbage"),
        )
        .await?;
        // Accept up to two responses (one may be a default answer to the
        // garbage frame); the valid request's cid must appear.
        for _ in 0..2 {
            let (msg_type, payload) = recv(&mut reader).await?;
            if msg_type != MessageType::AgentResponse {
                continue;
            }
            if let Ok(resp) = serde_json::from_slice::<AgentResponse>(&payload) {
                if response_cid(&resp) == Some("conform-after-garbage") {
                    return Ok(());
                }
            }
        }
        Err("agent stopped answering after a malformed payload".to_string())
    }
    .await;
    result(
        "malformed_payload",
        "a malformed event payload does not wedge the connection",
        outcome,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::server::AgentHandlerV2;
    use crate::v2::uds_server::UdsAgentServerV2;
    use crate::v2::AgentCapabilities;
    use async_trait::async_trait;

    struct ReferenceAgent;

    #[async_trait]
    impl AgentHandlerV2 for ReferenceAgent {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::new("ref-agent", "Reference Agent", "1.0.0")
        }

        async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
            AgentResponse::default_allow()
        }
    }

    #[tokio::test]
    async fn reference_rust_agent_passes_conformance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("ref.sock");
        let server = UdsAgentServerV2::new("ref-agent", &socket, Box::new(ReferenceAgent));
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Wait for the socket to exist.
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let report = run(&socket).await;
        assert!(
            report.passed,
            "reference agent must pass its own conformance suite:\n{}",
            report.render_text()
        );
        assert_eq!(report.checks.len(), 6);
    }

    #[tokio::test]
    async fn unreachable_socket_fails_all_checks() {
        let report = run(Path::new("/nonexistent/agent.sock")).await;
        assert!(!report.passed);
        assert!(report.checks.iter().all(|c| !c.passed));
    }
}
