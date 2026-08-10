package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	za "github.com/zentinelproxy/zentinel/sdk/go"
)

// maxAuditRuleIDs bounds how many rule IDs and tags travel back to the proxy
// in one response; a request matching hundreds of rules must not turn into a
// hundreds-of-entries audit payload on the hot path.
const maxAuditRuleIDs = 32

// Agent runs SecLang rules through Coraza on behalf of the proxy.
//
// Lock ordering: Agent.mu is never held while acquiring txState.mu. Handlers
// take Agent.mu only to look up or mutate the table, then work under
// txState.mu (Coraza transactions are explicitly not thread-safe).
type Agent struct {
	waf coraza.WAF
	cfg Config
	log *slog.Logger

	mu  sync.Mutex
	txs map[string]*txState

	stats stats
}

type stats struct {
	started  atomic.Uint64
	blocked  atomic.Uint64
	detected atomic.Uint64
	overflow atomic.Uint64
	expired  atomic.Uint64
	orphan   atomic.Uint64
}

// txState owns one Coraza transaction plus the bookkeeping the table needs.
type txState struct {
	mu   sync.Mutex
	tx   types.Transaction
	once sync.Once

	// lastSeen is guarded by Agent.mu, not txState.mu.
	lastSeen time.Time
}

// close runs the logging phase (which writes the audit record) and releases
// the transaction. Safe to call from the sweeper and a handler concurrently.
func (s *txState) close(log *slog.Logger) {
	s.once.Do(func() {
		s.tx.ProcessLogging()
		if err := s.tx.Close(); err != nil {
			log.Warn("closing transaction", "error", err)
		}
	})
}

// New builds the WAF from cfg. Rule-file syntax errors surface here, at
// startup, rather than on the first request.
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	files, err := expandRuleFiles(cfg.RuleFiles)
	if err != nil {
		return nil, err
	}

	wafCfg := coraza.NewWAFConfig().WithDirectives(cfg.engineDirectives())
	for _, f := range files {
		wafCfg = wafCfg.WithDirectivesFromFile(f)
	}
	if cfg.Directives != "" {
		wafCfg = wafCfg.WithDirectives(cfg.Directives)
	}

	waf, err := coraza.NewWAF(wafCfg)
	if err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}

	log.Info("rules loaded",
		"files", len(files),
		"mode", string(cfg.Mode),
		"lifecycle", string(cfg.Lifecycle),
		"request_body", cfg.RequestBody,
		"response_body", cfg.ResponseBody,
		"audit_log", cfg.AuditLog)

	return &Agent{
		waf: waf,
		cfg: cfg,
		log: log,
		txs: make(map[string]*txState),
	}, nil
}

// ============================================================================
// Event handlers (the zentinelagent.Handler surface)
// ============================================================================

// OnRequestHeaders runs phase 1, and phase 2 as well when no request body will
// be inspected. It is the only mandatory handler.
func (a *Agent) OnRequestHeaders(_ context.Context, e *za.RequestHeadersEvent) *za.Response {
	cid := e.Metadata.CorrelationID
	txID := e.Metadata.RequestID
	if txID == "" {
		txID = cid
	}

	st := &txState{tx: a.waf.NewTransactionWithID(txID), lastSeen: time.Now()}
	a.stats.started.Add(1)

	st.mu.Lock()
	defer st.mu.Unlock()

	st.tx.ProcessConnection(e.Metadata.ClientIP, int(e.Metadata.ClientPort), "", 0)
	if name := serverNameOf(e); name != "" {
		st.tx.SetServerName(name)
	}
	st.tx.ProcessURI(e.URI, e.Method, e.Metadata.Protocol)
	for name, values := range e.Headers {
		for _, v := range values {
			st.tx.AddRequestHeader(name, v)
		}
	}

	if it := st.tx.ProcessRequestHeaders(); it != nil {
		return a.blocked(cid, st, it)
	}

	if a.cfg.runPhase2AtHeaders() {
		// No body will reach us, so evaluate phase 2 now: that is where
		// ARGS-based rules (most of CRS) live.
		it, err := st.tx.ProcessRequestBody()
		if err != nil {
			a.log.Warn("processing request body phase", "error", err, "tx", st.tx.ID())
		} else if it != nil {
			return a.blocked(cid, st, it)
		}
	}

	// Nothing further to inspect: log and release before answering.
	if a.cfg.Lifecycle == LifecycleHeaders {
		resp := a.allowed(st)
		st.close(a.log)
		return resp
	}

	if !a.track(cid, st) {
		return a.overflowed(st)
	}

	resp := a.allowed(st)
	resp.NeedsMore = a.cfg.RequestBody
	return resp
}

// OnRequestBodyChunk feeds body bytes to Coraza and runs phase 2 on the last
// chunk.
func (a *Agent) OnRequestBodyChunk(_ context.Context, e *za.RequestBodyChunkEvent) *za.Response {
	st := a.lookup(e.CorrelationID)
	if st == nil {
		return a.orphaned("request_body_chunk", e.CorrelationID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	if data, ok := a.decode(e.Data, e.CorrelationID); ok && len(data) > 0 {
		it, _, err := st.tx.WriteRequestBody(data)
		if err != nil {
			a.log.Warn("writing request body", "error", err, "tx", st.tx.ID())
		} else if it != nil {
			return a.blocked(e.CorrelationID, st, it)
		}
	}

	if e.IsLast {
		it, err := st.tx.ProcessRequestBody()
		if err != nil {
			a.log.Warn("processing request body", "error", err, "tx", st.tx.ID())
		} else if it != nil {
			return a.blocked(e.CorrelationID, st, it)
		}
	}

	resp := a.allowed(st)
	resp.NeedsMore = !e.IsLast
	return resp
}

// OnResponseHeaders runs phase 3 against the upstream response.
func (a *Agent) OnResponseHeaders(_ context.Context, e *za.ResponseHeadersEvent) *za.Response {
	st := a.lookup(e.CorrelationID)
	if st == nil {
		return a.orphaned("response_headers", e.CorrelationID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	for name, values := range e.Headers {
		for _, v := range values {
			st.tx.AddResponseHeader(name, v)
		}
	}
	if it := st.tx.ProcessResponseHeaders(int(e.Status), "HTTP/1.1"); it != nil {
		return a.blocked(e.CorrelationID, st, it)
	}

	resp := a.allowed(st)
	resp.NeedsMore = a.cfg.ResponseBody && st.tx.IsResponseBodyProcessable()
	return resp
}

// OnResponseBodyChunk feeds response bytes to Coraza and runs phase 4 on the
// last chunk.
func (a *Agent) OnResponseBodyChunk(_ context.Context, e *za.ResponseBodyChunkEvent) *za.Response {
	st := a.lookup(e.CorrelationID)
	if st == nil {
		return a.orphaned("response_body_chunk", e.CorrelationID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	if data, ok := a.decode(e.Data, e.CorrelationID); ok && len(data) > 0 {
		it, _, err := st.tx.WriteResponseBody(data)
		if err != nil {
			a.log.Warn("writing response body", "error", err, "tx", st.tx.ID())
		} else if it != nil {
			return a.blocked(e.CorrelationID, st, it)
		}
	}

	if e.IsLast {
		it, err := st.tx.ProcessResponseBody()
		if err != nil {
			a.log.Warn("processing response body", "error", err, "tx", st.tx.ID())
		} else if it != nil {
			return a.blocked(e.CorrelationID, st, it)
		}
	}

	resp := a.allowed(st)
	resp.NeedsMore = !e.IsLast
	return resp
}

// OnRequestComplete runs phase 5, which is what writes the audit-log record,
// and releases the transaction.
func (a *Agent) OnRequestComplete(_ context.Context, e *za.RequestCompleteEvent) *za.Response {
	st := a.untrack(e.CorrelationID)
	if st == nil {
		return a.orphaned("request_complete", e.CorrelationID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.close(a.log)
	return za.AllowResponse()
}

// ============================================================================
// Transaction table (bounded by count and by age)
// ============================================================================

// track registers st under cid. It reports false when the table is full; the
// caller then applies the overflow policy. Nothing is evicted to make room —
// evicting an in-flight transaction would silently stop inspecting a request
// that is still being processed.
func (a *Agent) track(cid string, st *txState) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.txs) >= a.cfg.MaxTransactions {
		return false
	}
	a.txs[cid] = st
	return true
}

func (a *Agent) lookup(cid string) *txState {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.txs[cid]
	if st != nil {
		st.lastSeen = time.Now()
	}
	return st
}

func (a *Agent) untrack(cid string) *txState {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.txs[cid]
	delete(a.txs, cid)
	return st
}

// StartSweeper reclaims transactions whose request never completed (client
// aborted, or the proxy is not registered for request_complete events) until
// ctx is cancelled.
func (a *Agent) StartSweeper(ctx context.Context) {
	interval := a.cfg.TransactionTTL / 2
	if interval <= 0 {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.sweep(time.Now())
			}
		}
	}()
}

// sweep closes every transaction older than the TTL. Returns how many were
// reclaimed (tests assert on this).
func (a *Agent) sweep(now time.Time) int {
	var expired []*txState
	a.mu.Lock()
	for cid, st := range a.txs {
		if now.Sub(st.lastSeen) > a.cfg.TransactionTTL {
			expired = append(expired, st)
			delete(a.txs, cid)
		}
	}
	inFlight := len(a.txs)
	a.mu.Unlock()

	for _, st := range expired {
		st.mu.Lock()
		st.close(a.log)
		st.mu.Unlock()
	}
	if n := len(expired); n > 0 {
		a.stats.expired.Add(uint64(n))
		a.log.Warn("transactions expired before completion",
			"count", n, "ttl", a.cfg.TransactionTTL, "in_flight", inFlight,
			"hint", "register the agent for request_complete events, or lower --transaction-ttl")
	}
	return len(expired)
}

// Close releases every tracked transaction, flushing their audit records.
func (a *Agent) Close() {
	a.mu.Lock()
	remaining := make([]*txState, 0, len(a.txs))
	for cid, st := range a.txs {
		remaining = append(remaining, st)
		delete(a.txs, cid)
	}
	a.mu.Unlock()

	for _, st := range remaining {
		st.mu.Lock()
		st.close(a.log)
		st.mu.Unlock()
	}
	a.log.Info("waf stopped",
		"requests", a.stats.started.Load(),
		"blocked", a.stats.blocked.Load(),
		"detected", a.stats.detected.Load(),
		"overflow", a.stats.overflow.Load(),
		"expired", a.stats.expired.Load(),
		"orphan_events", a.stats.orphan.Load())
}

// ============================================================================
// Responses
// ============================================================================

// blocked turns an interruption into a proxy decision and retires the
// transaction. Must be called with st.mu held.
func (a *Agent) blocked(cid string, st *txState, it *types.Interruption) *za.Response {
	a.stats.blocked.Add(1)
	a.log.Info("request blocked",
		"tx", st.tx.ID(), "rule_id", it.RuleID, "action", it.Action, "status", it.Status)

	resp := za.NewResponse(a.decisionFor(it)).WithAudit(a.auditFor(st.tx, it))
	// The transaction is done either way: remove it from the table (it may
	// never have been added) and flush its audit record.
	a.mu.Lock()
	delete(a.txs, cid)
	a.mu.Unlock()
	st.close(a.log)
	return resp
}

// allowed builds an allow response, carrying any non-disruptive matches so the
// proxy's own logs show what detection mode saw. Must be called with st.mu held.
func (a *Agent) allowed(st *txState) *za.Response {
	resp := za.AllowResponse()
	if matched := st.tx.MatchedRules(); len(matched) > 0 {
		a.stats.detected.Add(1)
		resp.WithAudit(a.auditFor(st.tx, nil))
	}
	return resp
}

// overflowed applies the table-full policy. Must be called with st.mu held.
func (a *Agent) overflowed(st *txState) *za.Response {
	a.stats.overflow.Add(1)
	a.log.Warn("transaction table full",
		"max", a.cfg.MaxTransactions, "policy", string(a.cfg.Overflow),
		"tx", st.tx.ID())
	st.close(a.log)

	audit := za.AuditMetadata{
		Tags:        []string{"zentinel/waf"},
		RuleIDs:     []string{},
		ReasonCodes: []string{"waf_overflow"},
		Custom:      map[string]any{"waf_max_transactions": a.cfg.MaxTransactions},
	}
	if a.cfg.Overflow == OverflowBlock {
		return za.NewResponse(za.Block(a.cfg.BlockStatus, a.cfg.BlockBody)).WithAudit(audit)
	}
	return za.AllowResponse().WithAudit(audit)
}

// orphaned answers an event whose transaction is gone (expired, or the proxy
// sent a later phase for a request we never saw headers for).
func (a *Agent) orphaned(event, cid string) *za.Response {
	a.stats.orphan.Add(1)
	a.log.Debug("event without a live transaction", "event", event, "correlation_id", cid)
	return za.AllowResponse()
}

// decisionFor maps a Coraza disruptive action onto a proxy decision.
func (a *Agent) decisionFor(it *types.Interruption) za.Decision {
	status := uint16(it.Status)
	if it.Action == "redirect" {
		if status == 0 {
			status = 302
		}
		return za.Redirect(it.Data, status)
	}
	// deny, drop, and anything else map to a plain block. "drop" would close
	// the connection under ModSecurity; the proxy owns the socket, so the
	// closest honest equivalent is an error response.
	if status == 0 {
		status = a.cfg.BlockStatus
	}
	block := za.BlockDecision{Status: status}
	if a.cfg.BlockBody != "" {
		body := a.cfg.BlockBody
		block.Body = &body
	}
	if a.cfg.ExposeRuleID {
		block.Headers = map[string]string{"X-Zentinel-WAF-Rule": strconv.Itoa(it.RuleID)}
	}
	return za.BlockWith(block)
}

// auditFor summarises matched rules for the proxy's audit metadata. Coraza's
// own audit log stays the full-fidelity record; this is the short version that
// travels with the decision.
func (a *Agent) auditFor(tx types.Transaction, it *types.Interruption) za.AuditMetadata {
	audit := za.AuditMetadata{
		Tags:        []string{"zentinel/waf"},
		RuleIDs:     []string{},
		ReasonCodes: []string{},
		Custom:      map[string]any{"waf_tx_id": tx.ID()},
	}

	seenTags := map[string]bool{"zentinel/waf": true}
	seenRules := map[int]bool{}
	for _, m := range tx.MatchedRules() {
		rule := m.Rule()
		if !seenRules[rule.ID()] && len(audit.RuleIDs) < maxAuditRuleIDs {
			seenRules[rule.ID()] = true
			audit.RuleIDs = append(audit.RuleIDs, strconv.Itoa(rule.ID()))
		}
		for _, tag := range rule.Tags() {
			if !seenTags[tag] && len(audit.Tags) < maxAuditRuleIDs {
				seenTags[tag] = true
				audit.Tags = append(audit.Tags, tag)
			}
		}
	}

	if it != nil {
		audit.ReasonCodes = append(audit.ReasonCodes, "waf_"+it.Action)
		audit.Custom["waf_rule_id"] = it.RuleID
		audit.Custom["waf_action"] = it.Action
	} else if len(audit.RuleIDs) > 0 {
		audit.ReasonCodes = append(audit.ReasonCodes, "waf_detected")
	}
	return audit
}

// decode unwraps the base64 body payload. A malformed chunk is logged and
// skipped rather than failing the request: the proxy's failure-mode setting,
// not the agent, decides what a broken WAF means for traffic.
func (a *Agent) decode(data, cid string) ([]byte, bool) {
	if data == "" {
		return nil, true
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		a.log.Warn("undecodable body chunk", "error", err, "correlation_id", cid)
		return nil, false
	}
	return raw, true
}

// serverNameOf prefers the TLS/route server name and falls back to the Host
// header, so SERVER_NAME is populated for plain HTTP too.
func serverNameOf(e *za.RequestHeadersEvent) string {
	if e.Metadata.ServerName != nil && *e.Metadata.ServerName != "" {
		return *e.Metadata.ServerName
	}
	return e.Header("host")
}
