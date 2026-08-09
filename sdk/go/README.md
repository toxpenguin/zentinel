# Zentinel Agent SDK for Go

Write a [Zentinel](https://zentinelproxy.io) external agent as one function.
The SDK implements the agent side of the v2 protocol over Unix domain
sockets — framing, handshake, capability negotiation, correlation-ID
routing, ping/pong — so an agent is just event callbacks.

```go
package main

import (
    "context"
    "log"

    zentinelagent "github.com/zentinelproxy/zentinel/sdk/go"
)

type myAgent struct{}

func (myAgent) OnRequestHeaders(_ context.Context, e *zentinelagent.RequestHeadersEvent) *zentinelagent.Response {
    if e.Header("x-api-key") == "" {
        return zentinelagent.NewResponse(zentinelagent.Block(401, "missing API key"))
    }
    return zentinelagent.AllowResponse().
        AddRequestHeader(zentinelagent.SetHeader("X-Validated-By", "my-agent"))
}

func main() {
    srv, err := zentinelagent.NewServer(zentinelagent.Config{
        Name:    "my-agent",
        Version: "1.0.0",
    }, myAgent{})
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(srv.ListenAndServe(context.Background(), "/run/zentinel/my-agent.sock"))
}
```

Register in Zentinel's KDL config:

```kdl
agents {
    agent "my-agent" {
        type "auth"
        transport {
            unix-socket "/run/zentinel/my-agent.sock"
        }
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"
    }
}
```

## More events

`OnRequestHeaders` is mandatory. Implement any of these optional interfaces
on the same type to receive more events (advertised automatically during
the handshake); anything you don't implement is answered with Allow:

| Interface | Event |
|-----------|-------|
| `RequestBodyHandler` | Request body chunks (base64 `Data`) |
| `ResponseHeadersHandler` | Upstream response headers |
| `ResponseBodyHandler` | Response body chunks |
| `CompleteHandler` | End-of-exchange audit event |

## Decisions

```go
zentinelagent.Allow()
zentinelagent.Block(403, "denied")            // custom status + body
zentinelagent.Redirect("https://sso.example.com/login", 302)
zentinelagent.Challenge("captcha", map[string]string{"type": "recaptcha"})
```

## Wire compatibility

The wire contract is defined by the Rust implementation in
`crates/agent-protocol` (binary UDS transport: 4-byte big-endian length,
1-byte message type, JSON payload; 16 MB frame cap). This SDK pins to
protocol v2 and negotiates JSON encoding. Golden tests in `server_test.go`
assert the exact serde JSON shapes for decisions and header operations.

No third-party dependencies.

## Scope

- Transport: Unix domain socket (the recommended same-host deployment).
  gRPC and reverse-connection transports are not yet covered.
- Concurrency: events on one connection are handled sequentially (the
  proxy pools multiple connections per agent for parallelism), matching
  the Rust `UdsAgentServerV2` reference server.
