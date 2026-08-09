// Minimal Zentinel agent built on the Go SDK. Echoes request info back as
// headers — the Go counterpart of the Rust reference agent in agents/echo.
//
// Run:
//
//	go run ./examples/echo --socket /tmp/echo-agent.sock
package main

import (
	"context"
	"flag"
	"log"

	zentinelagent "github.com/zentinelproxy/zentinel/sdk/go"
)

type echoAgent struct{}

func (echoAgent) OnRequestHeaders(_ context.Context, e *zentinelagent.RequestHeadersEvent) *zentinelagent.Response {
	return zentinelagent.AllowResponse().
		AddRequestHeader(zentinelagent.SetHeader("X-Echo-Agent", "go-echo/1.0")).
		AddRequestHeader(zentinelagent.SetHeader("X-Echo-Method", e.Method)).
		AddRequestHeader(zentinelagent.SetHeader("X-Echo-Path", e.URI))
}

func main() {
	socket := flag.String("socket", "/tmp/echo-agent.sock", "Unix socket to listen on")
	flag.Parse()

	srv, err := zentinelagent.NewServer(zentinelagent.Config{
		Name:    "go-echo",
		Version: "1.0.0",
	}, echoAgent{})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.ListenAndServe(context.Background(), *socket))
}
