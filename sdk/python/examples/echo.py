"""Minimal Zentinel agent built on the Python SDK. Echoes request info back
as headers — the Python counterpart of sdk/go/examples/echo.

Run:

    python3 examples/echo.py --socket /tmp/echo-agent.sock
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import zentinel_agent as za  # noqa: E402


class EchoAgent(za.Agent):
    async def on_request_headers(self, event: za.RequestHeadersEvent) -> za.Response:
        return (
            za.allow_response()
            .add_request_header(za.set_header("X-Echo-Agent", "py-echo/1.0"))
            .add_request_header(za.set_header("X-Echo-Method", event.method))
            .add_request_header(za.set_header("X-Echo-Path", event.uri))
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/tmp/echo-agent.sock")
    args = parser.parse_args()
    za.run(EchoAgent(), args.socket, name="py-echo", version="1.0.0")
