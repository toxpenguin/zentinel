package zentinelagent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── Wire-shape goldens (must match Rust serde output) ──────────────────────

func TestDecisionMarshalMatchesSerde(t *testing.T) {
	cases := []struct {
		name string
		d    Decision
		want string
	}{
		{"allow", Allow(), `"allow"`},
		{"block", Block(403, "denied"), `{"block":{"status":403,"body":"denied"}}`},
		{"block_no_body", Block(429, ""), `{"block":{"status":429,"body":null}}`},
		{"redirect", Redirect("https://example.com/login", 302),
			`{"redirect":{"url":"https://example.com/login","status":302}}`},
		{"challenge", Challenge("captcha", map[string]string{"type": "recaptcha"}),
			`{"challenge":{"challenge_type":"captcha","params":{"type":"recaptcha"}}}`},
	}
	for _, tc := range cases {
		got, err := json.Marshal(tc.d)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
		// Round-trip.
		var back Decision
		if err := json.Unmarshal(got, &back); err != nil {
			t.Errorf("%s: unmarshal: %v", tc.name, err)
		}
	}
}

func TestHeaderOpMarshalMatchesSerde(t *testing.T) {
	cases := []struct {
		op   HeaderOp
		want string
	}{
		{SetHeader("X-A", "1"), `{"set":{"name":"X-A","value":"1"}}`},
		{AddHeader("X-B", "2"), `{"add":{"name":"X-B","value":"2"}}`},
		{RemoveHeader("X-C"), `{"remove":{"name":"X-C"}}`},
	}
	for _, tc := range cases {
		got, err := json.Marshal(tc.op)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("got %s want %s", got, tc.want)
		}
	}
}

// ─── Proxy-side test client ─────────────────────────────────────────────────

type testProxy struct {
	t    *testing.T
	conn net.Conn
}

func dialAgent(t *testing.T, socket string) *testProxy {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &testProxy{t: t, conn: conn}
}

func (p *testProxy) send(msgType byte, payload any) {
	p.t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[:4], uint32(len(raw)+1))
	header[4] = msgType
	if _, err := p.conn.Write(append(header, raw...)); err != nil {
		p.t.Fatal(err)
	}
}

func (p *testProxy) recv() (byte, []byte) {
	p.t.Helper()
	msgType, payload, err := readMessage(p.conn)
	if err != nil {
		p.t.Fatalf("read: %v", err)
	}
	return msgType, payload
}

func (p *testProxy) handshake() handshakeResponse {
	p.t.Helper()
	p.send(msgHandshakeRequest, map[string]any{
		"supported_versions": []uint32{2},
		"proxy_id":           "test-proxy",
		"proxy_version":      "0.0.0",
		"config":             nil,
	})
	msgType, payload := p.recv()
	if msgType != msgHandshakeResponse {
		p.t.Fatalf("expected HandshakeResponse, got 0x%02x", msgType)
	}
	var resp handshakeResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		p.t.Fatal(err)
	}
	return resp
}

// ─── Test agents ────────────────────────────────────────────────────────────

// headersOnly implements just the mandatory interface.
type headersOnly struct{}

func (headersOnly) OnRequestHeaders(_ context.Context, e *RequestHeadersEvent) *Response {
	if e.Header("x-blocked") != "" {
		return NewResponse(Block(403, "blocked by test agent"))
	}
	return AllowResponse().AddRequestHeader(SetHeader("X-Test-Agent", "go-sdk"))
}

func startAgent(t *testing.T, handler Handler) string {
	t.Helper()
	// Not t.TempDir(): macOS caps sun_path at 104 bytes and Go's test temp
	// dirs blow past it, failing dial with EINVAL.
	dir, err := os.MkdirTemp("/tmp", "za")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")
	srv, err := NewServer(Config{Name: "test-agent", Version: "1.0.0"}, handler)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx, socket) }()
	return socket
}

// ─── End-to-end tests ───────────────────────────────────────────────────────

func TestHandshakeAdvertisesCapabilities(t *testing.T) {
	proxy := dialAgent(t, startAgent(t, headersOnly{}))
	resp := proxy.handshake()

	if !resp.Success {
		t.Fatalf("handshake failed: %v", resp.Error)
	}
	if resp.ProtocolVersion != 2 {
		t.Errorf("protocol_version = %d, want 2", resp.ProtocolVersion)
	}
	if resp.Encoding != "json" {
		t.Errorf("encoding = %q, want json", resp.Encoding)
	}
	if len(resp.Capabilities.SupportedEvents) != 1 ||
		resp.Capabilities.SupportedEvents[0] != eventRequestHeaders {
		t.Errorf("supported_events = %v, want [1]", resp.Capabilities.SupportedEvents)
	}
}

func TestRequestHeadersRoundTrip(t *testing.T) {
	proxy := dialAgent(t, startAgent(t, headersOnly{}))
	proxy.handshake()

	proxy.send(msgRequestHeaders, map[string]any{
		"metadata": map[string]any{
			"correlation_id": "cid-123",
			"request_id":     "r1",
			"client_ip":      "203.0.113.7",
			"client_port":    51234,
			"protocol":       "HTTP/1.1",
			"timestamp":      "2026-08-09T00:00:00Z",
		},
		"method":  "GET",
		"uri":     "/api/users",
		"headers": map[string][]string{"host": {"example.com"}},
	})

	msgType, payload := proxy.recv()
	if msgType != msgAgentResponse {
		t.Fatalf("expected AgentResponse, got 0x%02x", msgType)
	}
	var resp struct {
		Version        uint32     `json:"version"`
		Decision       Decision   `json:"decision"`
		RequestHeaders []HeaderOp `json:"request_headers"`
		Audit          struct {
			Custom map[string]any `json:"custom"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Version != 2 {
		t.Errorf("version = %d, want 2", resp.Version)
	}
	if !resp.Decision.IsAllow() {
		t.Error("expected allow decision")
	}
	if got := resp.Audit.Custom["correlation_id"]; got != "cid-123" {
		t.Errorf("correlation_id = %v, want cid-123 (response routing breaks without it)", got)
	}
	if len(resp.RequestHeaders) != 1 {
		t.Errorf("request_headers = %v, want one set op", resp.RequestHeaders)
	}
}

func TestBlockDecisionOnWire(t *testing.T) {
	proxy := dialAgent(t, startAgent(t, headersOnly{}))
	proxy.handshake()

	proxy.send(msgRequestHeaders, map[string]any{
		"metadata": map[string]any{
			"correlation_id": "cid-block", "request_id": "r2",
			"client_ip": "203.0.113.7", "client_port": 1,
			"protocol": "HTTP/1.1", "timestamp": "2026-08-09T00:00:00Z",
		},
		"method":  "GET",
		"uri":     "/admin",
		"headers": map[string][]string{"x-blocked": {"1"}},
	})

	_, payload := proxy.recv()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	// The proxy's Rust deserializer needs the externally-tagged form.
	want := `{"block":{"status":403,"body":"blocked by test agent"}}`
	if string(raw["decision"]) != want {
		t.Errorf("decision on wire = %s, want %s", raw["decision"], want)
	}
}

func TestUnimplementedEventAnswersAllow(t *testing.T) {
	proxy := dialAgent(t, startAgent(t, headersOnly{}))
	proxy.handshake()

	// headersOnly does not implement RequestBodyHandler.
	proxy.send(msgRequestBodyChunk, map[string]any{
		"correlation_id": "cid-body",
		"data":           "aGVsbG8=",
		"is_last":        true,
		"total_size":     nil,
	})

	msgType, payload := proxy.recv()
	if msgType != msgAgentResponse {
		t.Fatalf("expected AgentResponse, got 0x%02x", msgType)
	}
	var resp struct {
		Decision Decision `json:"decision"`
		Audit    struct {
			Custom map[string]any `json:"custom"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Decision.IsAllow() {
		t.Error("unimplemented event must default to allow")
	}
	if got := resp.Audit.Custom["correlation_id"]; got != "cid-body" {
		t.Errorf("correlation_id = %v, want cid-body", got)
	}
}

func TestPingPong(t *testing.T) {
	proxy := dialAgent(t, startAgent(t, headersOnly{}))
	proxy.handshake()

	proxy.send(msgPing, map[string]any{"seq": 7})
	msgType, payload := proxy.recv()
	if msgType != msgPong {
		t.Fatalf("expected Pong, got 0x%02x", msgType)
	}
	if string(payload) != `{"seq":7}` {
		t.Errorf("pong must echo ping payload, got %s", payload)
	}
}

func TestHandshakeRejectsUnknownVersion(t *testing.T) {
	proxy := dialAgent(t, startAgent(t, headersOnly{}))
	proxy.send(msgHandshakeRequest, map[string]any{
		"supported_versions": []uint32{99},
		"proxy_id":           "test-proxy",
		"proxy_version":      "0.0.0",
		"config":             nil,
	})
	_, payload := proxy.recv()
	var resp handshakeResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Success {
		t.Error("handshake must fail for unsupported version")
	}
	if resp.Error == nil {
		t.Error("failed handshake must carry an error message")
	}
}
