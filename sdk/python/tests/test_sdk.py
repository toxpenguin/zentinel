"""SDK tests: wire-shape goldens (must match Rust serde output) plus an
in-process handshake/event round-trip over a real Unix socket.

Run: python3 -m unittest discover -s tests   (from sdk/python)
"""

import asyncio
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import zentinel_agent as za  # noqa: E402
from zentinel_agent import server as srv  # noqa: E402


class TestWireShapes(unittest.TestCase):
    def test_decisions_match_serde(self):
        cases = [
            (za.allow(), "allow"),
            (za.block(403, "denied"), {"block": {"status": 403, "body": "denied"}}),
            (za.block(429), {"block": {"status": 429, "body": None}}),
            (za.redirect("https://example.com/login", 302),
             {"redirect": {"url": "https://example.com/login", "status": 302}}),
            (za.challenge("captcha", {"type": "recaptcha"}),
             {"challenge": {"challenge_type": "captcha",
                            "params": {"type": "recaptcha"}}}),
        ]
        for decision, want in cases:
            self.assertEqual(decision.to_wire(), want)

    def test_header_ops_match_serde(self):
        self.assertEqual(za.set_header("X-A", "1").to_wire(),
                         {"set": {"name": "X-A", "value": "1"}})
        self.assertEqual(za.add_header("X-B", "2").to_wire(),
                         {"add": {"name": "X-B", "value": "2"}})
        self.assertEqual(za.remove_header("X-C").to_wire(),
                         {"remove": {"name": "X-C"}})

    def test_response_wire_has_required_fields(self):
        wire = za.allow_response().to_wire()
        self.assertEqual(wire["version"], 2)
        self.assertEqual(wire["decision"], "allow")
        for key in ("request_headers", "response_headers", "routing_metadata",
                    "audit", "needs_more"):
            self.assertIn(key, wire)


class EchoTestAgent(za.Agent):
    async def on_request_headers(self, event):
        if event.header("x-blocked"):
            return za.respond(za.block(403, "blocked by test agent"))
        return za.allow_response().add_request_header(
            za.set_header("X-Test-Agent", "py-sdk"))


class TestServerRoundTrip(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # /tmp, not tempfile default dirs: macOS caps sun_path at 104 bytes.
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="zapy")
        self.socket = str(Path(self._dir.name) / "agent.sock")
        server = za.Server(EchoTestAgent(), name="py-test", version="1.0.0")
        self._task = asyncio.create_task(server.serve(self.socket))
        for _ in range(100):
            if Path(self.socket).exists():
                break
            await asyncio.sleep(0.01)
        self.reader, self.writer = await asyncio.open_unix_connection(self.socket)

    async def asyncTearDown(self):
        self.writer.close()
        self._task.cancel()
        self._dir.cleanup()

    async def send(self, msg_type, payload):
        raw = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
        self.writer.write(struct.pack(">IB", len(raw) + 1, msg_type) + raw)
        await self.writer.drain()

    async def recv(self):
        header = await asyncio.wait_for(self.reader.readexactly(4), 5)
        total = struct.unpack(">I", header)[0]
        body = await asyncio.wait_for(self.reader.readexactly(total), 5)
        return body[0], body[1:]

    async def handshake(self, versions=(2,)):
        await self.send(srv.MSG_HANDSHAKE_REQUEST, {
            "supported_versions": list(versions),
            "proxy_id": "test-proxy", "proxy_version": "0.0.0", "config": None,
        })
        msg_type, payload = await self.recv()
        self.assertEqual(msg_type, srv.MSG_HANDSHAKE_RESPONSE)
        return json.loads(payload)

    async def test_handshake_capabilities(self):
        resp = await self.handshake()
        self.assertTrue(resp["success"])
        self.assertEqual(resp["protocol_version"], 2)
        self.assertEqual(resp["encoding"], "json")
        self.assertEqual(resp["capabilities"]["supported_events"], [1])
        self.assertEqual(resp["capabilities"]["agent_id"], "py-test")

    async def test_handshake_rejects_unknown_version(self):
        resp = await self.handshake(versions=(99,))
        self.assertFalse(resp["success"])
        self.assertTrue(resp["error"])

    async def test_request_headers_round_trip(self):
        await self.handshake()
        await self.send(srv.MSG_REQUEST_HEADERS, {
            "metadata": {"correlation_id": "cid-1", "request_id": "r1",
                         "client_ip": "203.0.113.7", "client_port": 1,
                         "protocol": "HTTP/1.1", "timestamp": "t"},
            "method": "GET", "uri": "/x",
            "headers": {"host": ["example.com"]},
        })
        msg_type, payload = await self.recv()
        self.assertEqual(msg_type, srv.MSG_AGENT_RESPONSE)
        resp = json.loads(payload)
        self.assertEqual(resp["version"], 2)
        self.assertEqual(resp["decision"], "allow")
        self.assertEqual(resp["audit"]["custom"]["correlation_id"], "cid-1")
        self.assertEqual(resp["request_headers"],
                         [{"set": {"name": "X-Test-Agent", "value": "py-sdk"}}])

    async def test_block_decision_on_wire(self):
        await self.handshake()
        await self.send(srv.MSG_REQUEST_HEADERS, {
            "metadata": {"correlation_id": "cid-2"},
            "method": "GET", "uri": "/x",
            "headers": {"x-blocked": ["1"]},
        })
        _, payload = await self.recv()
        resp = json.loads(payload)
        self.assertEqual(resp["decision"],
                         {"block": {"status": 403, "body": "blocked by test agent"}})

    async def test_ping_pong_echo(self):
        await self.handshake()
        await self.send(srv.MSG_PING, b'{"seq":7}')
        msg_type, payload = await self.recv()
        self.assertEqual(msg_type, srv.MSG_PONG)
        self.assertEqual(payload, b'{"seq":7}')

    async def test_malformed_payload_answers_allow(self):
        await self.handshake()
        await self.send(srv.MSG_REQUEST_HEADERS, b"\x00not json\xff")
        msg_type, payload = await self.recv()
        self.assertEqual(msg_type, srv.MSG_AGENT_RESPONSE)
        self.assertEqual(json.loads(payload)["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
