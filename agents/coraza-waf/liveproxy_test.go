package main

// Live-proxy smoke test: runs a real `zentinel` binary in front of a test
// upstream with this agent enforcing the shipped starter ruleset, then throws
// real HTTP at it. Unit tests prove the rules fire; this proves the block
// actually reaches the client and the clean request actually reaches the
// backend.
//
// Skips (loudly) when no proxy binary is available. Point ZENTINEL_BIN at a
// binary, or `cargo build --bin zentinel` first for the default path.

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	za "github.com/zentinelproxy/zentinel/sdk/go"
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

func TestLiveProxyBlocksAttacksAndPassesCleanTraffic(t *testing.T) {
	bin := findZentinel(t)

	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.WriteHeader(200)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	// ── Agent: shipped starter rules, audit log to a temp file ──────────
	// /tmp, not t.TempDir(): macOS caps sun_path at 104 bytes.
	dir, err := os.MkdirTemp("/tmp", "zwaf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "waf.sock")
	auditLog := filepath.Join(dir, "audit.log")

	cfg := DefaultConfig()
	cfg.RuleFiles = []string{"rules"}
	cfg.AuditLog = auditLog
	cfg.Lifecycle = LifecycleHeaders // proxy below only sends request_headers

	agent, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	srv, err := za.NewServer(za.Config{Name: "coraza-waf", Version: version}, agent)
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
    agent "coraza-waf" {
        type "waf"
        unix-socket %q
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
    }
}
filters {
    filter "coraza-waf" {
        type "agent"
        agent "coraza-waf"
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
        filters "coraza-waf"
    }
}
`, listenPort, socket, upstream.Listener.Addr().String())

	configPath := filepath.Join(dir, "zentinel.kdl")
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

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

	var resp *http.Response
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(base + "/index.html")
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("proxy never became ready: %v", err)
	}

	// ── Clean request reaches the upstream ──────────────────────────────
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream-ok" {
		t.Fatalf("clean request: status=%d body=%q, want 200 upstream-ok", resp.StatusCode, body)
	}
	hitsBeforeAttack := upstreamHits

	// ── SQLi in the query string is blocked before the upstream ─────────
	resp, err = client.Get(base + "/search?q=1%27%20OR%20%271%27%3D%271%27--")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("SQLi request: status=%d, want 403", resp.StatusCode)
	}
	if string(body) != cfg.BlockBody {
		t.Errorf("block body=%q, want %q", body, cfg.BlockBody)
	}
	if upstreamHits != hitsBeforeAttack {
		t.Errorf("upstream was reached %d extra times during the attack, want 0",
			upstreamHits-hitsBeforeAttack)
	}

	// ── The block is on record in ModSecurity-native format ─────────────
	raw, err := os.ReadFile(auditLog)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if !containsAll(string(raw), `[id "100010"]`, "-A--", "-H--") {
		t.Errorf("audit log does not record the SQLi block:\n%s", raw)
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}
