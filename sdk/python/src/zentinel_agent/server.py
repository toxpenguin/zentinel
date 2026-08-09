"""Asyncio Unix-socket server for the Zentinel agent protocol v2.

Framing, handshake, capability negotiation, correlation-ID routing, and
ping/pong are handled here; an agent subclasses :class:`Agent` and overrides
the event methods it cares about. Wire behavior mirrors the Rust reference
server (``crates/agent-protocol/src/v2/uds_server.rs``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import struct
from typing import Any

from .types import (
    PROTOCOL_VERSION,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    Response,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent,
    allow_response,
)

log = logging.getLogger("zentinel_agent")

# Mirrors MAX_UDS_MESSAGE_SIZE in the Rust implementation.
MAX_MESSAGE_SIZE = 16 * 1024 * 1024

# Message type bytes (crates/agent-protocol/src/v2/uds.rs MessageType).
MSG_HANDSHAKE_REQUEST = 0x01
MSG_HANDSHAKE_RESPONSE = 0x02
MSG_REQUEST_HEADERS = 0x10
MSG_REQUEST_BODY_CHUNK = 0x11
MSG_RESPONSE_HEADERS = 0x12
MSG_RESPONSE_BODY_CHUNK = 0x13
MSG_REQUEST_COMPLETE = 0x14
MSG_AGENT_RESPONSE = 0x20
MSG_CANCEL = 0x40
MSG_PING = 0x41
MSG_PONG = 0x42

# Event ids for capabilities.supported_events
# (crates/agent-protocol/src/v2/server.rs event_type_to_i32).
_EVENT_IDS = {
    "on_request_headers": 1,
    "on_request_body_chunk": 2,
    "on_response_headers": 3,
    "on_response_body_chunk": 4,
    "on_request_complete": 5,
}


class Agent:
    """Base agent: override the event methods you need. Every method
    defaults to Allow, matching the Rust trait defaults; only overridden
    methods are advertised in the handshake (``on_request_headers`` is
    always advertised — it is the protocol's mandatory event)."""

    async def on_request_headers(self, event: RequestHeadersEvent) -> Response:
        return allow_response()

    async def on_request_body_chunk(self, event: RequestBodyChunkEvent) -> Response:
        return allow_response()

    async def on_response_headers(self, event: ResponseHeadersEvent) -> Response:
        return allow_response()

    async def on_response_body_chunk(self, event: ResponseBodyChunkEvent) -> Response:
        return allow_response()

    async def on_request_complete(self, event: RequestCompleteEvent) -> Response:
        return allow_response()


class Server:
    """Serves one :class:`Agent` on a Unix domain socket."""

    def __init__(
        self,
        agent: Agent,
        *,
        name: str,
        version: str,
        agent_id: str | None = None,
        max_body_size: int = 10 * 1024 * 1024,
        max_concurrency: int = 64,
    ) -> None:
        if not name or not version:
            raise ValueError("name and version are required")
        self._agent = agent
        self._name = name
        self._version = version
        self._agent_id = agent_id or name
        self._max_body_size = max_body_size
        self._max_concurrency = max_concurrency

    # ── Capabilities ────────────────────────────────────────────────────

    def _overridden(self, method: str) -> bool:
        return getattr(type(self._agent), method) is not getattr(Agent, method)

    def _capabilities(self) -> dict[str, Any]:
        events = [1]  # RequestHeaders is mandatory
        streaming = False
        for method, event_id in _EVENT_IDS.items():
            if event_id != 1 and self._overridden(method):
                events.append(event_id)
                if event_id in (2, 4):
                    streaming = True
        return {
            "agent_id": self._agent_id,
            "name": self._name,
            "version": self._version,
            "supported_events": events,
            "features": {
                "streaming_body": streaming,
                "websocket": False,
                "guardrails": False,
                "config_push": False,
                "metrics_export": False,
                "concurrent_requests": self._max_concurrency,
                "cancellation": False,
                "flow_control": False,
                "health_reporting": False,
            },
            "limits": {
                "max_body_size": self._max_body_size,
                "max_concurrency": self._max_concurrency,
                "preferred_chunk_size": 64 * 1024,
            },
        }

    # ── Serving ─────────────────────────────────────────────────────────

    async def serve(self, socket_path: str) -> None:
        """Bind ``socket_path`` and serve until cancelled. A stale socket
        file is removed first (the standard UDS restart dance)."""
        with contextlib.suppress(FileNotFoundError):
            os.remove(socket_path)

        server = await asyncio.start_unix_server(self._handle_connection, path=socket_path)
        log.info("agent listening on %s (%s)", socket_path, self._agent_id)
        async with server:
            await server.serve_forever()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._serve_connection(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass  # proxy closed the connection — normal lifecycle
        except Exception:  # noqa: BLE001 — one bad connection must not kill the server
            log.exception("connection error")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # ── Handshake (always JSON) ─────────────────────────────────────
        msg_type, payload = await _read_message(reader)
        if msg_type != MSG_HANDSHAKE_REQUEST:
            raise ValueError(f"expected HandshakeRequest (0x01), got 0x{msg_type:02x}")
        request = json.loads(payload)
        offered = request.get("supported_versions", [])
        success = PROTOCOL_VERSION in offered

        response: dict[str, Any] = {
            "protocol_version": PROTOCOL_VERSION,
            "capabilities": self._capabilities(),
            "success": success,
            "error": None if success else (
                f"agent speaks protocol v{PROTOCOL_VERSION}, proxy offered {offered}"
            ),
            # This SDK speaks JSON; the proxy always supports it.
            "encoding": "json",
        }
        await _write_message(writer, MSG_HANDSHAKE_RESPONSE, _to_json(response))
        if not success:
            return
        log.debug("handshake complete with %s", request.get("proxy_id", "?"))

        # ── Event loop ──────────────────────────────────────────────────
        while True:
            msg_type, payload = await _read_message(reader)
            if msg_type == MSG_PING:
                await _write_message(writer, MSG_PONG, payload)
            elif msg_type == MSG_CANCEL:
                # Sequential dispatch: nothing in flight to stop.
                continue
            elif msg_type in _DISPATCH:
                method, event_cls, cid_key = _DISPATCH[msg_type]
                await self._dispatch(writer, payload, method, event_cls, cid_key)
            else:
                log.debug("ignoring unhandled message type 0x%02x", msg_type)

    async def _dispatch(
        self,
        writer: asyncio.StreamWriter,
        payload: bytes,
        method: str,
        event_cls: type,
        cid_key: str,
    ) -> None:
        correlation_id = ""
        try:
            data = json.loads(payload)
            correlation_id = _extract_cid(data, cid_key)
            event = event_cls.from_dict(data)
            response: Response = await getattr(self._agent, method)(event)
            if response is None:
                response = allow_response()
        except Exception:  # noqa: BLE001 — a handler bug answers Allow, never wedges the wire
            log.exception("handler %s failed; answering allow", method)
            response = allow_response()

        wire = response.to_wire()
        # The proxy's multiplexing client routes responses by this.
        wire["audit"]["custom"]["correlation_id"] = correlation_id
        await _write_message(writer, MSG_AGENT_RESPONSE, _to_json(wire))


_DISPATCH: dict[int, tuple[str, type, str]] = {
    MSG_REQUEST_HEADERS: ("on_request_headers", RequestHeadersEvent, "metadata"),
    MSG_REQUEST_BODY_CHUNK: ("on_request_body_chunk", RequestBodyChunkEvent, "correlation_id"),
    MSG_RESPONSE_HEADERS: ("on_response_headers", ResponseHeadersEvent, "correlation_id"),
    MSG_RESPONSE_BODY_CHUNK: ("on_response_body_chunk", ResponseBodyChunkEvent, "correlation_id"),
    MSG_REQUEST_COMPLETE: ("on_request_complete", RequestCompleteEvent, "correlation_id"),
}


def _extract_cid(data: dict[str, Any], cid_key: str) -> str:
    if cid_key == "metadata":
        return data.get("metadata", {}).get("correlation_id", "")
    return data.get(cid_key, "")


def _to_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


# ============================================================================
# Framing: 4-byte big-endian length (includes type byte) + type + payload
# ============================================================================


async def _write_message(writer: asyncio.StreamWriter, msg_type: int, payload: bytes) -> None:
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {len(payload)} > {MAX_MESSAGE_SIZE}")
    writer.write(struct.pack(">IB", len(payload) + 1, msg_type) + payload)
    await writer.drain()


async def _read_message(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await reader.readexactly(4)
    total_len = struct.unpack(">I", header)[0]
    if total_len == 0:
        raise ValueError("zero-length message")
    if total_len > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {total_len} > {MAX_MESSAGE_SIZE}")
    type_byte = (await reader.readexactly(1))[0]
    payload = await reader.readexactly(total_len - 1)
    return type_byte, payload


def run(agent: Agent, socket_path: str, **kwargs: Any) -> None:
    """Blocking convenience entry point: serve ``agent`` until Ctrl-C."""
    server = Server(agent, **kwargs)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(server.serve(socket_path))
