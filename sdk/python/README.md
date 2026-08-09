# Zentinel Agent SDK for Python

Write a [Zentinel](https://zentinelproxy.io) external agent as one class.
The SDK implements the agent side of the v2 protocol over Unix domain
sockets — framing, handshake, capability negotiation, correlation-ID
routing, ping/pong — on asyncio, with no third-party dependencies.

```python
import zentinel_agent as za


class MyAgent(za.Agent):
    async def on_request_headers(self, event: za.RequestHeadersEvent) -> za.Response:
        if not event.header("x-api-key"):
            return za.respond(za.block(401, "missing API key"))
        return za.allow_response().add_request_header(
            za.set_header("X-Validated-By", "my-agent"))


if __name__ == "__main__":
    za.run(MyAgent(), "/run/zentinel/my-agent.sock", name="my-agent", version="1.0.0")
```

Register in Zentinel's KDL config:

```kdl
agents {
    agent "my-agent" {
        type "auth"
        unix-socket "/run/zentinel/my-agent.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"
    }
}
```

## More events

Override any of these on your `Agent` subclass; overridden methods are
advertised automatically during the handshake, everything else answers
Allow (matching the Rust reference server's defaults):

| Method | Event |
|--------|-------|
| `on_request_body_chunk` | Request body chunks (base64 `data`) |
| `on_response_headers` | Upstream response headers |
| `on_response_body_chunk` | Response body chunks |
| `on_request_complete` | End-of-exchange audit event |

## Decisions

```python
za.allow()
za.block(403, "denied")            # custom status + body
za.redirect("https://sso.example.com/login", 302)
za.challenge("captcha", {"type": "recaptcha"})
```

## Conformance

The SDK's example agent passes **zentinel-conformance v1**:

```bash
python3 examples/echo.py --socket /tmp/echo.sock &
zentinel agent conform --socket /tmp/echo.sock
```

## Testing

```bash
python3 -m unittest discover -s tests
```

## Scope

Same as the Go SDK (`sdk/go`): UDS transport, JSON encoding, sequential
per-connection dispatch (the proxy pools connections for parallelism).
Wire contract source of truth: `crates/agent-protocol` (Rust).
Requires Python 3.10+.
