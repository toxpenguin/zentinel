package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	za "github.com/zentinelproxy/zentinel/sdk/go"
)

// testRules exercises one rule per phase so each handler can be tested in
// isolation without depending on CRS being installed.
const testRules = `
SecRule REQUEST_HEADERS:x-trip "@streq boom" \
    "id:900001,phase:1,deny,status:403,log,msg:'header trip',tag:'test/header'"
SecRule REQUEST_HEADERS:x-redirect "@streq yes" \
    "id:900002,phase:1,log,msg:'redirect trip',redirect:https://example.com/denied"
SecRule ARGS "@detectSQLi" \
    "id:900003,phase:2,deny,status:403,log,msg:'sqli in %{MATCHED_VAR_NAME}',tag:'test/sqli'"
SecRule ARGS_POST:evil "@streq 1" \
    "id:900004,phase:2,deny,status:403,log,msg:'body trip',tag:'test/body'"
SecRule RESPONSE_HEADERS:x-leak "@streq secret" \
    "id:900005,phase:3,deny,status:502,log,msg:'response trip',tag:'test/response'"
`

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestAgent(t *testing.T, mutate func(*Config)) *Agent {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Directives = testRules
	cfg.Lifecycle = LifecycleHeaders
	if mutate != nil {
		mutate(&cfg)
	}
	agent, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("building agent: %v", err)
	}
	t.Cleanup(agent.Close)
	return agent
}

func headersEvent(cid, method, uri string, headers map[string][]string) *za.RequestHeadersEvent {
	if headers == nil {
		headers = map[string][]string{"host": {"example.com"}}
	}
	return &za.RequestHeadersEvent{
		Metadata: za.RequestMetadata{
			CorrelationID: cid,
			RequestID:     "req-" + cid,
			ClientIP:      "203.0.113.7",
			ClientPort:    51234,
			Protocol:      "HTTP/1.1",
			Timestamp:     "2026-08-11T00:00:00Z",
		},
		Method:  method,
		URI:     uri,
		Headers: headers,
	}
}

// decisionJSON renders the decision exactly as it goes on the wire, which is
// also what the proxy parses.
func decisionJSON(t *testing.T, resp *za.Response) string {
	t.Helper()
	raw, err := json.Marshal(resp.Decision)
	if err != nil {
		t.Fatalf("marshalling decision: %v", err)
	}
	return string(raw)
}

func TestCleanRequestIsAllowed(t *testing.T) {
	agent := newTestAgent(t, nil)

	resp := agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-1", "GET", "/index.html?page=2", nil))

	if got := decisionJSON(t, resp); got != `"allow"` {
		t.Fatalf("decision = %s, want allow", got)
	}
	if n := agent.inFlight(); n != 0 {
		t.Fatalf("in-flight transactions = %d, want 0 in headers lifecycle", n)
	}
}

func TestPhase1HeaderRuleBlocks(t *testing.T) {
	agent := newTestAgent(t, nil)

	resp := agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-2", "GET", "/", map[string][]string{
			"host":   {"example.com"},
			"x-trip": {"boom"},
		}))

	want := `{"block":{"status":403,"body":"Request blocked by WAF."}}`
	if got := decisionJSON(t, resp); got != want {
		t.Fatalf("decision = %s, want %s", got, want)
	}
	if len(resp.Audit.RuleIDs) != 1 || resp.Audit.RuleIDs[0] != "900001" {
		t.Fatalf("audit rule ids = %v, want [900001]", resp.Audit.RuleIDs)
	}
	if resp.Audit.Custom["waf_action"] != "deny" {
		t.Fatalf("audit action = %v, want deny", resp.Audit.Custom["waf_action"])
	}
}

// Query-string rules live in phase 2 (that is where CRS puts ARGS checks), so
// headers-lifecycle inspection must still evaluate that phase.
func TestQueryStringSQLiIsBlockedWithoutBodyEvents(t *testing.T) {
	agent := newTestAgent(t, nil)

	resp := agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-3", "GET", "/search?q=1'%20OR%20'1'='1'--", nil))

	if resp.Decision.IsAllow() {
		t.Fatalf("SQLi in query string was allowed: %s", decisionJSON(t, resp))
	}
	if !contains(resp.Audit.Tags, "test/sqli") {
		t.Fatalf("audit tags = %v, want test/sqli", resp.Audit.Tags)
	}
}

func TestDetectionModeAllowsButReportsMatches(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) { c.Mode = ModeDetection })

	resp := agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-4", "GET", "/", map[string][]string{
			"host":   {"example.com"},
			"x-trip": {"boom"},
		}))

	if got := decisionJSON(t, resp); got != `"allow"` {
		t.Fatalf("decision = %s, want allow in detection mode", got)
	}
	if !contains(resp.Audit.RuleIDs, "900001") {
		t.Fatalf("audit rule ids = %v, want 900001 reported", resp.Audit.RuleIDs)
	}
	if !contains(resp.Audit.ReasonCodes, "waf_detected") {
		t.Fatalf("reason codes = %v, want waf_detected", resp.Audit.ReasonCodes)
	}
}

func TestRequestBodyRuleBlocksOnLastChunk(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) {
		c.Lifecycle = LifecycleFull
		c.RequestBody = true
	})
	ctx := context.Background()

	resp := agent.OnRequestHeaders(ctx, headersEvent("cid-5", "POST", "/submit",
		map[string][]string{
			"host":         {"example.com"},
			"content-type": {"application/x-www-form-urlencoded"},
		}))
	if !resp.Decision.IsAllow() {
		t.Fatalf("headers blocked unexpectedly: %s", decisionJSON(t, resp))
	}
	if !resp.NeedsMore {
		t.Fatal("needs_more = false, want true when request-body inspection is on")
	}

	resp = agent.OnRequestBodyChunk(ctx, &za.RequestBodyChunkEvent{
		CorrelationID: "cid-5",
		Data:          base64.StdEncoding.EncodeToString([]byte("evil=1")),
		IsLast:        true,
		ChunkIndex:    0,
		BytesReceived: 6,
	})

	want := `{"block":{"status":403,"body":"Request blocked by WAF."}}`
	if got := decisionJSON(t, resp); got != want {
		t.Fatalf("decision = %s, want %s", got, want)
	}
	if n := agent.inFlight(); n != 0 {
		t.Fatalf("in-flight transactions = %d, want 0 after a block", n)
	}
}

func TestResponseHeaderRuleBlocks(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) { c.Lifecycle = LifecycleFull })
	ctx := context.Background()

	if resp := agent.OnRequestHeaders(ctx, headersEvent("cid-6", "GET", "/", nil)); !resp.Decision.IsAllow() {
		t.Fatalf("headers blocked unexpectedly: %s", decisionJSON(t, resp))
	}

	resp := agent.OnResponseHeaders(ctx, &za.ResponseHeadersEvent{
		CorrelationID: "cid-6",
		Status:        200,
		Headers:       map[string][]string{"x-leak": {"secret"}},
	})

	want := `{"block":{"status":502,"body":"Request blocked by WAF."}}`
	if got := decisionJSON(t, resp); got != want {
		t.Fatalf("decision = %s, want %s", got, want)
	}
}

func TestRedirectActionMapsToRedirectDecision(t *testing.T) {
	agent := newTestAgent(t, nil)

	resp := agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-7", "GET", "/", map[string][]string{
			"host":       {"example.com"},
			"x-redirect": {"yes"},
		}))

	want := `{"redirect":{"url":"https://example.com/denied","status":302}}`
	if got := decisionJSON(t, resp); got != want {
		t.Fatalf("decision = %s, want %s", got, want)
	}
}

func TestBlockHidesRuleIDUnlessOptedIn(t *testing.T) {
	tripped := map[string][]string{"host": {"example.com"}, "x-trip": {"boom"}}

	agent := newTestAgent(t, nil)
	resp := agent.OnRequestHeaders(context.Background(), headersEvent("cid-8", "GET", "/", tripped))
	if strings.Contains(decisionJSON(t, resp), "X-Zentinel-WAF-Rule") {
		t.Fatalf("block response leaked the rule id by default: %s", decisionJSON(t, resp))
	}

	loud := newTestAgent(t, func(c *Config) { c.ExposeRuleID = true })
	resp = loud.OnRequestHeaders(context.Background(), headersEvent("cid-9", "GET", "/", tripped))
	if !strings.Contains(decisionJSON(t, resp), `"X-Zentinel-WAF-Rule":"900001"`) {
		t.Fatalf("--expose-rule-id did not add the header: %s", decisionJSON(t, resp))
	}
}

func TestTransactionTableFullAppliesOverflowPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy Overflow
		want   string
	}{
		{OverflowAllow, `"allow"`},
		{OverflowBlock, `{"block":{"status":403,"body":"Request blocked by WAF."}}`},
	} {
		t.Run(string(tc.policy), func(t *testing.T) {
			agent := newTestAgent(t, func(c *Config) {
				c.Lifecycle = LifecycleFull
				c.MaxTransactions = 1
				c.Overflow = tc.policy
			})
			ctx := context.Background()

			if resp := agent.OnRequestHeaders(ctx, headersEvent("first", "GET", "/", nil)); !resp.Decision.IsAllow() {
				t.Fatalf("first request blocked: %s", decisionJSON(t, resp))
			}
			resp := agent.OnRequestHeaders(ctx, headersEvent("second", "GET", "/", nil))

			if got := decisionJSON(t, resp); got != tc.want {
				t.Fatalf("overflow decision = %s, want %s", got, tc.want)
			}
			if !contains(resp.Audit.ReasonCodes, "waf_overflow") {
				t.Fatalf("reason codes = %v, want waf_overflow", resp.Audit.ReasonCodes)
			}
			// The first request keeps its transaction: overflow never evicts
			// work that is still in flight.
			if n := agent.inFlight(); n != 1 {
				t.Fatalf("in-flight transactions = %d, want 1", n)
			}
		})
	}
}

func TestExpiredTransactionsAreSwept(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) {
		c.Lifecycle = LifecycleFull
		c.TransactionTTL = 30 * time.Second
	})

	agent.OnRequestHeaders(context.Background(), headersEvent("cid-10", "GET", "/", nil))
	if n := agent.inFlight(); n != 1 {
		t.Fatalf("in-flight transactions = %d, want 1", n)
	}

	if n := agent.sweep(time.Now().Add(10 * time.Second)); n != 0 {
		t.Fatalf("swept %d transactions before the TTL elapsed, want 0", n)
	}
	if n := agent.sweep(time.Now().Add(45 * time.Second)); n != 1 {
		t.Fatalf("swept %d transactions after the TTL, want 1", n)
	}
	if n := agent.inFlight(); n != 0 {
		t.Fatalf("in-flight transactions = %d after sweep, want 0", n)
	}
}

func TestRequestCompleteReleasesTransaction(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) { c.Lifecycle = LifecycleFull })
	ctx := context.Background()

	agent.OnRequestHeaders(ctx, headersEvent("cid-11", "GET", "/", nil))
	resp := agent.OnRequestComplete(ctx, &za.RequestCompleteEvent{
		CorrelationID: "cid-11",
		Status:        200,
		DurationMs:    3,
	})

	if !resp.Decision.IsAllow() {
		t.Fatalf("request_complete returned %s, want allow", decisionJSON(t, resp))
	}
	if n := agent.inFlight(); n != 0 {
		t.Fatalf("in-flight transactions = %d, want 0", n)
	}
}

func TestEventWithoutTransactionIsAllowed(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) { c.Lifecycle = LifecycleFull })

	resp := agent.OnRequestBodyChunk(context.Background(), &za.RequestBodyChunkEvent{
		CorrelationID: "never-seen",
		Data:          base64.StdEncoding.EncodeToString([]byte("evil=1")),
		IsLast:        true,
	})

	if !resp.Decision.IsAllow() {
		t.Fatalf("orphan chunk returned %s, want allow", decisionJSON(t, resp))
	}
	if agent.stats.orphan.Load() != 1 {
		t.Fatalf("orphan counter = %d, want 1", agent.stats.orphan.Load())
	}
}

func TestUndecodableBodyChunkDoesNotBreakTheRequest(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) { c.Lifecycle = LifecycleFull })
	ctx := context.Background()

	agent.OnRequestHeaders(ctx, headersEvent("cid-12", "POST", "/submit", nil))
	resp := agent.OnRequestBodyChunk(ctx, &za.RequestBodyChunkEvent{
		CorrelationID: "cid-12",
		Data:          "!!! not base64 !!!",
		IsLast:        false,
	})

	if !resp.Decision.IsAllow() {
		t.Fatalf("decision = %s, want allow", decisionJSON(t, resp))
	}
	if !resp.NeedsMore {
		t.Fatal("needs_more = false, want true for a non-final chunk")
	}
}

func TestAuditLogIsWrittenInModSecurityNativeFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	agent := newTestAgent(t, func(c *Config) { c.AuditLog = path })

	agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-13", "GET", "/", map[string][]string{
			"host":   {"example.com"},
			"x-trip": {"boom"},
		}))

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	log := string(raw)
	// Native format frames every section as --<boundary>-<part>-- and renders
	// matches as ModSecurity error-log lines, which is what SIEM and fail2ban
	// parsers expect.
	for _, want := range []string{"-A--", "-B--", "-H--", "[id \"900001\"]", "[tag \"test/header\"]"} {
		if !strings.Contains(log, want) {
			t.Fatalf("audit log missing %q:\n%s", want, log)
		}
	}
}

func TestConfigRejectsRulelessStart(t *testing.T) {
	cfg := DefaultConfig()
	if _, err := New(cfg, testLogger()); err == nil {
		t.Fatal("agent started with no rules configured, want an error")
	}
}

func TestConfigRejectsMissingRuleFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RuleFiles = []string{filepath.Join(t.TempDir(), "absent.conf")}
	if _, err := New(cfg, testLogger()); err == nil {
		t.Fatal("agent started with a missing rule file, want an error")
	}
}

func TestConfigRejectsEmptyRuleDirectory(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RuleFiles = []string{t.TempDir()}
	if _, err := New(cfg, testLogger()); err == nil {
		t.Fatal("agent started with an empty rule directory, want an error")
	}
}

func TestShippedDefaultRulesLoadAndBlock(t *testing.T) {
	agent := newTestAgent(t, func(c *Config) {
		c.Directives = ""
		c.RuleFiles = []string{"rules"}
	})

	resp := agent.OnRequestHeaders(context.Background(),
		headersEvent("cid-14", "GET", "/files/../../etc/passwd", nil))

	if resp.Decision.IsAllow() {
		t.Fatalf("path traversal was allowed by the shipped ruleset")
	}
	if !contains(resp.Audit.RuleIDs, "100001") {
		t.Fatalf("audit rule ids = %v, want 100001", resp.Audit.RuleIDs)
	}
}

func TestEngineDirectivesReflectFlags(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeDetection
	cfg.RequestBody = false
	cfg.AuditLog = "/tmp/audit.log"
	got := cfg.engineDirectives()

	for _, want := range []string{
		"SecRuleEngine DetectionOnly",
		"SecRequestBodyAccess Off",
		"SecAuditLogFormat Native",
		"SecAuditLogType Serial",
		"SecAuditLog /tmp/audit.log",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("directives missing %q:\n%s", want, got)
		}
	}

	cfg.AuditLog = ""
	if !strings.Contains(cfg.engineDirectives(), "SecAuditEngine Off") {
		t.Fatal("audit engine not disabled when --audit-log is empty")
	}
}

// inFlight reports how many transactions the table currently holds.
func (a *Agent) inFlight() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.txs)
}

func contains(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
