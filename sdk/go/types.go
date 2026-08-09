// Package zentinelagent implements the agent side of the Zentinel agent
// protocol v2 over Unix domain sockets, so an external agent can be written
// as a handful of event callbacks and nothing else.
//
// Wire compatibility is defined by the Rust implementation in
// crates/agent-protocol (the `UdsAgentServerV2` server and the serde JSON
// shapes in protocol.rs); this package mirrors those shapes exactly.
package zentinelagent

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the only protocol version this SDK speaks.
const ProtocolVersion = 2

// ============================================================================
// Decision — mirrors Rust `Decision` (externally tagged, snake_case)
// ============================================================================

// Decision is the agent's verdict for an event. Construct with Allow, Block,
// Redirect, or Challenge. The zero value marshals as "allow".
type Decision struct {
	block     *BlockDecision
	redirect  *RedirectDecision
	challenge *ChallengeDecision
}

// BlockDecision returns a custom error response instead of proxying.
type BlockDecision struct {
	Status  uint16            `json:"status"`
	Body    *string           `json:"body"`
	Headers map[string]string `json:"headers,omitempty"`
}

// RedirectDecision redirects the client.
type RedirectDecision struct {
	URL    string `json:"url"`
	Status uint16 `json:"status"`
}

// ChallengeDecision requests additional client verification (captcha, OTP).
type ChallengeDecision struct {
	ChallengeType string            `json:"challenge_type"`
	Params        map[string]string `json:"params"`
}

// Allow lets the request/response continue unmodified.
func Allow() Decision { return Decision{} }

// Block returns status with an optional body. body may be "" for no body.
func Block(status uint16, body string) Decision {
	var b *string
	if body != "" {
		b = &body
	}
	return Decision{block: &BlockDecision{Status: status, Body: b}}
}

// BlockWith gives full control over the block response.
func BlockWith(d BlockDecision) Decision { return Decision{block: &d} }

// Redirect sends the client to url with the given 3xx status.
func Redirect(url string, status uint16) Decision {
	return Decision{redirect: &RedirectDecision{URL: url, Status: status}}
}

// Challenge asks the proxy to run a challenge flow.
func Challenge(challengeType string, params map[string]string) Decision {
	return Decision{challenge: &ChallengeDecision{ChallengeType: challengeType, Params: params}}
}

// IsAllow reports whether the decision is a plain allow.
func (d Decision) IsAllow() bool {
	return d.block == nil && d.redirect == nil && d.challenge == nil
}

// MarshalJSON emits the serde externally-tagged representation:
// "allow" | {"block":{...}} | {"redirect":{...}} | {"challenge":{...}}.
func (d Decision) MarshalJSON() ([]byte, error) {
	switch {
	case d.block != nil:
		return json.Marshal(map[string]*BlockDecision{"block": d.block})
	case d.redirect != nil:
		return json.Marshal(map[string]*RedirectDecision{"redirect": d.redirect})
	case d.challenge != nil:
		return json.Marshal(map[string]*ChallengeDecision{"challenge": d.challenge})
	default:
		return json.Marshal("allow")
	}
}

// UnmarshalJSON accepts both the unit form ("allow") and tagged objects.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var unit string
	if err := json.Unmarshal(data, &unit); err == nil {
		if unit == "allow" {
			*d = Decision{}
			return nil
		}
		return fmt.Errorf("unknown decision %q", unit)
	}
	var tagged struct {
		Block     *BlockDecision     `json:"block"`
		Redirect  *RedirectDecision  `json:"redirect"`
		Challenge *ChallengeDecision `json:"challenge"`
	}
	if err := json.Unmarshal(data, &tagged); err != nil {
		return err
	}
	*d = Decision{block: tagged.Block, redirect: tagged.Redirect, challenge: tagged.Challenge}
	return nil
}

// ============================================================================
// HeaderOp — mirrors Rust `HeaderOp` (externally tagged, snake_case)
// ============================================================================

// HeaderOp mutates one header. Construct with SetHeader/AddHeader/RemoveHeader.
type HeaderOp struct {
	set    *headerNameValue
	add    *headerNameValue
	remove *headerName
}

type headerNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type headerName struct {
	Name string `json:"name"`
}

// SetHeader replaces (or creates) a header.
func SetHeader(name, value string) HeaderOp {
	return HeaderOp{set: &headerNameValue{Name: name, Value: value}}
}

// AddHeader appends a header value.
func AddHeader(name, value string) HeaderOp {
	return HeaderOp{add: &headerNameValue{Name: name, Value: value}}
}

// RemoveHeader deletes a header.
func RemoveHeader(name string) HeaderOp {
	return HeaderOp{remove: &headerName{Name: name}}
}

// MarshalJSON emits {"set":{"name":...,"value":...}} etc.
func (h HeaderOp) MarshalJSON() ([]byte, error) {
	switch {
	case h.set != nil:
		return json.Marshal(map[string]*headerNameValue{"set": h.set})
	case h.add != nil:
		return json.Marshal(map[string]*headerNameValue{"add": h.add})
	case h.remove != nil:
		return json.Marshal(map[string]*headerName{"remove": h.remove})
	default:
		return nil, fmt.Errorf("empty HeaderOp")
	}
}

// UnmarshalJSON parses the tagged representation.
func (h *HeaderOp) UnmarshalJSON(data []byte) error {
	var tagged struct {
		Set    *headerNameValue `json:"set"`
		Add    *headerNameValue `json:"add"`
		Remove *headerName      `json:"remove"`
	}
	if err := json.Unmarshal(data, &tagged); err != nil {
		return err
	}
	*h = HeaderOp{set: tagged.Set, add: tagged.Add, remove: tagged.Remove}
	return nil
}

// ============================================================================
// Events (proxy → agent) — field names match serde output exactly
// ============================================================================

// RequestMetadata describes the request being processed.
type RequestMetadata struct {
	CorrelationID string  `json:"correlation_id"`
	RequestID     string  `json:"request_id"`
	ClientIP      string  `json:"client_ip"`
	ClientPort    uint16  `json:"client_port"`
	ServerName    *string `json:"server_name"`
	Protocol      string  `json:"protocol"`
	TLSVersion    *string `json:"tls_version"`
	TLSCipher     *string `json:"tls_cipher"`
	RouteID       *string `json:"route_id"`
	UpstreamID    *string `json:"upstream_id"`
	Timestamp     string  `json:"timestamp"`
	Traceparent   *string `json:"traceparent,omitempty"`
}

// RequestHeadersEvent fires when request headers arrive.
type RequestHeadersEvent struct {
	Metadata RequestMetadata     `json:"metadata"`
	Method   string              `json:"method"`
	URI      string              `json:"uri"`
	Headers  map[string][]string `json:"headers"`
}

// Header returns the first value of a (lowercase) header name, or "".
func (e *RequestHeadersEvent) Header(name string) string {
	if vs := e.Headers[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// RequestBodyChunkEvent fires per request-body chunk. Data is base64.
type RequestBodyChunkEvent struct {
	CorrelationID string `json:"correlation_id"`
	Data          string `json:"data"`
	IsLast        bool   `json:"is_last"`
	TotalSize     *uint  `json:"total_size"`
	ChunkIndex    uint32 `json:"chunk_index"`
	BytesReceived uint   `json:"bytes_received"`
}

// ResponseHeadersEvent fires when upstream response headers arrive.
type ResponseHeadersEvent struct {
	CorrelationID string              `json:"correlation_id"`
	Status        uint16              `json:"status"`
	Headers       map[string][]string `json:"headers"`
}

// ResponseBodyChunkEvent fires per response-body chunk. Data is base64.
type ResponseBodyChunkEvent struct {
	CorrelationID string `json:"correlation_id"`
	Data          string `json:"data"`
	IsLast        bool   `json:"is_last"`
	TotalSize     *uint  `json:"total_size"`
	ChunkIndex    uint32 `json:"chunk_index"`
	BytesSent     uint   `json:"bytes_sent"`
}

// RequestCompleteEvent fires after the exchange finishes (audit/logging).
type RequestCompleteEvent struct {
	CorrelationID    string  `json:"correlation_id"`
	Status           uint16  `json:"status"`
	DurationMs       uint64  `json:"duration_ms"`
	RequestBodySize  uint    `json:"request_body_size"`
	ResponseBodySize uint    `json:"response_body_size"`
	UpstreamAttempts uint32  `json:"upstream_attempts"`
	Error            *string `json:"error"`
}

// ============================================================================
// Response (agent → proxy)
// ============================================================================

// AuditMetadata is attached to responses for logging/metrics.
type AuditMetadata struct {
	Tags        []string       `json:"tags"`
	RuleIDs     []string       `json:"rule_ids"`
	Confidence  *float32       `json:"confidence"`
	ReasonCodes []string       `json:"reason_codes"`
	Custom      map[string]any `json:"custom"`
}

// Response is the agent's answer to any event.
type Response struct {
	Version         uint32            `json:"version"`
	Decision        Decision          `json:"decision"`
	RequestHeaders  []HeaderOp        `json:"request_headers"`
	ResponseHeaders []HeaderOp        `json:"response_headers"`
	RoutingMetadata map[string]string `json:"routing_metadata"`
	Audit           AuditMetadata     `json:"audit"`
	NeedsMore       bool              `json:"needs_more"`
}

// NewResponse returns an allow response ready for chaining.
func NewResponse(d Decision) *Response {
	return &Response{
		Version:         ProtocolVersion,
		Decision:        d,
		RequestHeaders:  []HeaderOp{},
		ResponseHeaders: []HeaderOp{},
		RoutingMetadata: map[string]string{},
		Audit: AuditMetadata{
			Tags:        []string{},
			RuleIDs:     []string{},
			ReasonCodes: []string{},
			Custom:      map[string]any{},
		},
	}
}

// AllowResponse is shorthand for NewResponse(Allow()).
func AllowResponse() *Response { return NewResponse(Allow()) }

// AddRequestHeader appends a request-header mutation.
func (r *Response) AddRequestHeader(op HeaderOp) *Response {
	r.RequestHeaders = append(r.RequestHeaders, op)
	return r
}

// AddResponseHeader appends a response-header mutation.
func (r *Response) AddResponseHeader(op HeaderOp) *Response {
	r.ResponseHeaders = append(r.ResponseHeaders, op)
	return r
}

// WithAudit replaces the audit block.
func (r *Response) WithAudit(a AuditMetadata) *Response {
	if a.Custom == nil {
		a.Custom = map[string]any{}
	}
	r.Audit = a
	return r
}

// ============================================================================
// Handshake (always JSON on the wire)
// ============================================================================

type handshakeRequest struct {
	SupportedVersions  []uint32        `json:"supported_versions"`
	ProxyID            string          `json:"proxy_id"`
	ProxyVersion       string          `json:"proxy_version"`
	Config             json.RawMessage `json:"config"`
	SupportedEncodings []string        `json:"supported_encodings,omitempty"`
}

type handshakeResponse struct {
	ProtocolVersion uint32       `json:"protocol_version"`
	Capabilities    capabilities `json:"capabilities"`
	Success         bool         `json:"success"`
	Error           *string      `json:"error"`
	Encoding        string       `json:"encoding"`
}

type capabilities struct {
	AgentID         string   `json:"agent_id"`
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	SupportedEvents []int32  `json:"supported_events"`
	Features        features `json:"features"`
	Limits          limits   `json:"limits"`
}

type features struct {
	StreamingBody      bool   `json:"streaming_body"`
	WebSocket          bool   `json:"websocket"`
	Guardrails         bool   `json:"guardrails"`
	ConfigPush         bool   `json:"config_push"`
	MetricsExport      bool   `json:"metrics_export"`
	ConcurrentRequests uint32 `json:"concurrent_requests"`
	Cancellation       bool   `json:"cancellation"`
	FlowControl        bool   `json:"flow_control"`
	HealthReporting    bool   `json:"health_reporting"`
}

type limits struct {
	MaxBodySize        uint64 `json:"max_body_size"`
	MaxConcurrency     uint32 `json:"max_concurrency"`
	PreferredChunkSize uint64 `json:"preferred_chunk_size"`
}

// Event type identifiers, as sent in capabilities.supported_events
// (crates/agent-protocol/src/v2/server.rs event_type_to_i32).
const (
	eventRequestHeaders    int32 = 1
	eventRequestBodyChunk  int32 = 2
	eventResponseHeaders   int32 = 3
	eventResponseBodyChunk int32 = 4
	eventRequestComplete   int32 = 5
)
