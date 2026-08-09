package zentinelagent

// Live-proxy smoke test: runs a real `zentinel` binary against an in-process
// SDK agent and asserts the agent's decisions take effect on real HTTP
// traffic. This is the check the golden-shape tests cannot make — that the
// SDK interoperates with the shipping proxy, not with our reading of it.
//
// Skips (loudly) when no proxy binary is available. Point ZENTINEL_BIN at a
// binary, or `cargo build --bin zentinel` first for the default path.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func findZentinel(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("ZENTINEL_BIN"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("ZENTINEL_BIN=%s: %v", bin, err)
		}
		return bin
	}
	for _, rel := range []string{"../../target/debug/zentinel", "../../target/release/zentinel"} {
		if abs, err := filepath.Abs(rel); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Skip("no zentinel binary (set ZENTINEL_BIN or cargo build --bin zentinel)")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestLiveProxyEndToEnd(t *testing.T) {
	bin := findZentinel(t)

	// ── Upstream that records what the proxy forwarded ──────────────────
	var lastAgentHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAgentHeader = r.Header.Get("X-Test-Agent")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	// ── In-process SDK agent ────────────────────────────────────────────
	sockDir, err := os.MkdirTemp("/tmp", "zalive")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	socket := filepath.Join(sockDir, "agent.sock")

	srv, err := NewServer(Config{Name: "live-test-agent", Version: "1.0.0"}, headersOnly{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe(t.Context(), socket) }()

	// ── Proxy config ────────────────────────────────────────────────────
	listenPort := freePort(t)
	config := fmt.Sprintf(`
system { worker-threads 0 }
listeners {
    listener "test" {
        address "127.0.0.1:%d"
        protocol "http"
    }
}
agents {
    agent "go-agent" {
        type "auth"
        unix-socket %q
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
    }
}
filters {
    filter "go-agent" {
        type "agent"
        agent "go-agent"
    }
}
upstreams {
    upstream "backend" {
        target %q
    }
}
routes {
    route "all" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "go-agent"
    }
}
`, listenPort, socket, upstream.Listener.Addr().String())

	configPath := filepath.Join(sockDir, "zentinel.kdl")
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	// ── Start the real proxy ────────────────────────────────────────────
	proxy := exec.Command(bin, "--config", configPath)
	proxy.Stdout = os.Stderr
	proxy.Stderr = os.Stderr
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = proxy.Process.Kill()
		_, _ = proxy.Process.Wait()
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", listenPort)
	client := &http.Client{Timeout: 3 * time.Second}

	// Wait until the proxy answers (fresh debug binary can be slow to boot).
	var resp *http.Response
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(base + "/allowed")
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("proxy never became ready: %v", err)
	}

	// ── Allow path: agent header mutation must reach the upstream ───────
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream-ok" {
		t.Fatalf("allow path: status=%d body=%q, want 200 upstream-ok", resp.StatusCode, body)
	}
	if lastAgentHeader != "go-sdk" {
		t.Errorf("upstream saw X-Test-Agent=%q, want go-sdk (agent mutation lost)", lastAgentHeader)
	}

	// ── Block path: agent decision must produce the 403 ─────────────────
	req, _ := http.NewRequest("GET", base+"/blocked", nil)
	req.Header.Set("X-Blocked", "1")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("block path: status=%d, want 403", resp.StatusCode)
	}
	if string(body) != "blocked by test agent" {
		t.Errorf("block body=%q, want agent-provided body", body)
	}
}
