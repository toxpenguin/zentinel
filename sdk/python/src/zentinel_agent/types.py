"""Wire types for the Zentinel agent protocol v2.

JSON field names mirror the serde output of the Rust implementation in
``crates/agent-protocol/src/protocol.rs`` exactly; the golden tests in
``tests/test_wire.py`` pin the shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 2

# ============================================================================
# Decisions — serde externally-tagged snake_case
# ============================================================================


@dataclass(frozen=True)
class Decision:
    """Agent verdict. Build with :func:`allow`, :func:`block`,
    :func:`redirect`, or :func:`challenge`."""

    _wire: Any  # "allow" | {"block": {...}} | {"redirect": {...}} | {"challenge": {...}}

    def to_wire(self) -> Any:
        return self._wire

    @property
    def is_allow(self) -> bool:
        return self._wire == "allow"


def allow() -> Decision:
    """Let the request/response continue unmodified."""
    return Decision("allow")


def block(status: int, body: str | None = None,
          headers: dict[str, str] | None = None) -> Decision:
    """Return ``status`` with an optional body instead of proxying."""
    wire: dict[str, Any] = {"status": status, "body": body}
    if headers is not None:
        wire["headers"] = headers
    return Decision({"block": wire})


def redirect(url: str, status: int = 302) -> Decision:
    """Redirect the client."""
    return Decision({"redirect": {"url": url, "status": status}})


def challenge(challenge_type: str, params: dict[str, str] | None = None) -> Decision:
    """Ask the proxy to run a challenge flow (captcha, OTP, ...)."""
    return Decision({"challenge": {"challenge_type": challenge_type,
                                   "params": params or {}}})


# ============================================================================
# Header operations — serde externally-tagged snake_case
# ============================================================================


@dataclass(frozen=True)
class HeaderOp:
    """One header mutation. Build with :func:`set_header`,
    :func:`add_header`, or :func:`remove_header`."""

    _wire: dict[str, Any]

    def to_wire(self) -> dict[str, Any]:
        return self._wire


def set_header(name: str, value: str) -> HeaderOp:
    """Replace (or create) a header."""
    return HeaderOp({"set": {"name": name, "value": value}})


def add_header(name: str, value: str) -> HeaderOp:
    """Append a header value."""
    return HeaderOp({"add": {"name": name, "value": value}})


def remove_header(name: str) -> HeaderOp:
    """Delete a header."""
    return HeaderOp({"remove": {"name": name}})


# ============================================================================
# Events (proxy → agent)
# ============================================================================


@dataclass
class RequestMetadata:
    correlation_id: str = ""
    request_id: str = ""
    client_ip: str = ""
    client_port: int = 0
    server_name: str | None = None
    protocol: str = ""
    tls_version: str | None = None
    tls_cipher: str | None = None
    route_id: str | None = None
    upstream_id: str | None = None
    timestamp: str = ""
    traceparent: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RequestMetadata":
        return cls(**{k: d.get(k, v) for k, v in _defaults(cls).items()})


@dataclass
class RequestHeadersEvent:
    metadata: RequestMetadata
    method: str = ""
    uri: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        """First value of a (lowercase) header name, or None."""
        values = self.headers.get(name)
        return values[0] if values else None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RequestHeadersEvent":
        return cls(
            metadata=RequestMetadata.from_dict(d.get("metadata", {})),
            method=d.get("method", ""),
            uri=d.get("uri", ""),
            headers=d.get("headers", {}),
        )


@dataclass
class RequestBodyChunkEvent:
    correlation_id: str = ""
    data: str = ""  # base64
    is_last: bool = False
    total_size: int | None = None
    chunk_index: int = 0
    bytes_received: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RequestBodyChunkEvent":
        return cls(**{k: d.get(k, v) for k, v in _defaults(cls).items()})


@dataclass
class ResponseHeadersEvent:
    correlation_id: str = ""
    status: int = 0
    headers: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ResponseHeadersEvent":
        return cls(
            correlation_id=d.get("correlation_id", ""),
            status=d.get("status", 0),
            headers=d.get("headers", {}),
        )


@dataclass
class ResponseBodyChunkEvent:
    correlation_id: str = ""
    data: str = ""  # base64
    is_last: bool = False
    total_size: int | None = None
    chunk_index: int = 0
    bytes_sent: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ResponseBodyChunkEvent":
        return cls(**{k: d.get(k, v) for k, v in _defaults(cls).items()})


@dataclass
class RequestCompleteEvent:
    correlation_id: str = ""
    status: int = 0
    duration_ms: int = 0
    request_body_size: int = 0
    response_body_size: int = 0
    upstream_attempts: int = 0
    error: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RequestCompleteEvent":
        return cls(**{k: d.get(k, v) for k, v in _defaults(cls).items()})


def _defaults(cls: type) -> dict[str, Any]:
    """Field-name → default map for simple flat dataclasses."""
    import dataclasses

    out: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        if f.default is not dataclasses.MISSING:
            out[f.name] = f.default
        elif f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
            out[f.name] = f.default_factory()  # type: ignore[misc]
    return out


# ============================================================================
# Response (agent → proxy)
# ============================================================================


@dataclass
class AuditMetadata:
    tags: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    confidence: float | None = None
    reason_codes: list[str] = field(default_factory=list)
    custom: dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        return {
            "tags": self.tags,
            "rule_ids": self.rule_ids,
            "confidence": self.confidence,
            "reason_codes": self.reason_codes,
            "custom": self.custom,
        }


@dataclass
class Response:
    """Agent answer to any event. Build with :func:`respond` or
    :func:`allow_response`; chain ``add_request_header`` etc."""

    decision: Decision = field(default_factory=allow)
    request_headers: list[HeaderOp] = field(default_factory=list)
    response_headers: list[HeaderOp] = field(default_factory=list)
    routing_metadata: dict[str, str] = field(default_factory=dict)
    audit: AuditMetadata = field(default_factory=AuditMetadata)
    needs_more: bool = False

    def add_request_header(self, op: HeaderOp) -> "Response":
        self.request_headers.append(op)
        return self

    def add_response_header(self, op: HeaderOp) -> "Response":
        self.response_headers.append(op)
        return self

    def with_audit(self, audit: AuditMetadata) -> "Response":
        self.audit = audit
        return self

    def to_wire(self) -> dict[str, Any]:
        return {
            "version": PROTOCOL_VERSION,
            "decision": self.decision.to_wire(),
            "request_headers": [op.to_wire() for op in self.request_headers],
            "response_headers": [op.to_wire() for op in self.response_headers],
            "routing_metadata": self.routing_metadata,
            "audit": self.audit.to_wire(),
            "needs_more": self.needs_more,
        }


def respond(decision: Decision) -> Response:
    """A response carrying ``decision``."""
    return Response(decision=decision)


def allow_response() -> Response:
    """Shorthand for ``respond(allow())``."""
    return Response()
