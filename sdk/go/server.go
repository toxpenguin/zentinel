package zentinelagent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
)

// maxMessageSize mirrors MAX_UDS_MESSAGE_SIZE in the Rust implementation.
const maxMessageSize = 16 * 1024 * 1024

// Message type bytes (crates/agent-protocol/src/v2/uds.rs MessageType).
const (
	msgHandshakeRequest  byte = 0x01
	msgHandshakeResponse byte = 0x02
	msgRequestHeaders    byte = 0x10
	msgRequestBodyChunk  byte = 0x11
	msgResponseHeaders   byte = 0x12
	msgResponseBodyChunk byte = 0x13
	msgRequestComplete   byte = 0x14
	msgAgentResponse     byte = 0x20
	msgCancel            byte = 0x40
	msgPing              byte = 0x41
	msgPong              byte = 0x42
)

// Handler is the one interface every agent must implement.
type Handler interface {
	// OnRequestHeaders decides what happens to an incoming request.
	OnRequestHeaders(ctx context.Context, event *RequestHeadersEvent) *Response
}

// Optional handler extensions. Implement any of these on the same type to
// receive additional events; unimplemented events are answered with Allow,
// matching the Rust trait's defaults.
type (
	// RequestBodyHandler receives request body chunks (base64 in Data).
	RequestBodyHandler interface {
		OnRequestBodyChunk(ctx context.Context, event *RequestBodyChunkEvent) *Response
	}
	// ResponseHeadersHandler receives upstream response headers.
	ResponseHeadersHandler interface {
		OnResponseHeaders(ctx context.Context, event *ResponseHeadersEvent) *Response
	}
	// ResponseBodyHandler receives response body chunks.
	ResponseBodyHandler interface {
		OnResponseBodyChunk(ctx context.Context, event *ResponseBodyChunkEvent) *Response
	}
	// CompleteHandler receives the end-of-exchange audit event.
	CompleteHandler interface {
		OnRequestComplete(ctx context.Context, event *RequestCompleteEvent) *Response
	}
)

// Config configures a Server. Zero value + Name/Version is valid.
type Config struct {
	// AgentID identifies the agent to the proxy. Defaults to Name.
	AgentID string
	// Name is the human-readable agent name (required).
	Name string
	// Version is the agent version string (required).
	Version string
	// MaxBodySize advertised in limits (bytes). 0 = 10 MiB.
	MaxBodySize uint64
	// MaxConcurrency advertised in limits. 0 = 64.
	MaxConcurrency uint32
	// Logger for connection lifecycle events. nil = slog.Default().
	Logger *slog.Logger
}

// Server serves the v2 agent protocol on a Unix domain socket.
type Server struct {
	cfg     Config
	handler Handler
	log     *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
}

// NewServer builds a server for handler. See Config for required fields.
func NewServer(cfg Config, handler Handler) (*Server, error) {
	if cfg.Name == "" || cfg.Version == "" {
		return nil, errors.New("zentinelagent: Config.Name and Config.Version are required")
	}
	if cfg.AgentID == "" {
		cfg.AgentID = cfg.Name
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 10 * 1024 * 1024
	}
	if cfg.MaxConcurrency == 0 {
		cfg.MaxConcurrency = 64
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:     cfg,
		handler: handler,
		log:     log,
		conns:   map[net.Conn]struct{}{},
	}, nil
}

// ListenAndServe binds socketPath and serves until ctx is cancelled. A stale
// socket file at socketPath is removed first (the standard UDS restart
// dance). Returns nil on clean shutdown.
func (s *Server) ListenAndServe(ctx context.Context, socketPath string) error {
	// Remove a stale socket from a previous run; a live listener would have
	// prevented the file from being connectable anyway.
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zentinelagent: removing stale socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("zentinelagent: listen %s: %w", socketPath, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	s.log.Info("agent listening", "socket", socketPath, "agent", s.cfg.AgentID)

	go func() {
		<-ctx.Done()
		s.shutdown()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("zentinelagent: accept: %w", err)
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		go func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			if err := s.serveConn(ctx, conn); err != nil &&
				!errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log.Warn("connection ended", "error", err)
			}
		}()
	}
}

func (s *Server) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
}

// serveConn runs handshake + event loop for one proxy connection.
func (s *Server) serveConn(ctx context.Context, conn net.Conn) error {
	// ── Handshake (always JSON) ─────────────────────────────────────────
	msgType, payload, err := readMessage(conn)
	if err != nil {
		return err
	}
	if msgType != msgHandshakeRequest {
		return fmt.Errorf("expected HandshakeRequest (0x01), got 0x%02x", msgType)
	}
	var req handshakeRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return fmt.Errorf("handshake decode: %w", err)
	}

	supported := false
	for _, v := range req.SupportedVersions {
		if v == ProtocolVersion {
			supported = true
			break
		}
	}
	resp := handshakeResponse{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    s.capabilities(),
		Success:         supported,
		// This SDK speaks JSON; the proxy always supports it.
		Encoding: "json",
	}
	if !supported {
		msg := fmt.Sprintf("agent only speaks protocol v%d, proxy offered %v",
			ProtocolVersion, req.SupportedVersions)
		resp.Error = &msg
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if err := writeMessage(conn, msgHandshakeResponse, respBytes); err != nil {
		return err
	}
	if !supported {
		return fmt.Errorf("handshake rejected: no common protocol version")
	}
	s.log.Debug("handshake complete", "proxy", req.ProxyID, "proxy_version", req.ProxyVersion)

	// ── Event loop ──────────────────────────────────────────────────────
	for {
		msgType, payload, err := readMessage(conn)
		if err != nil {
			return err
		}

		switch msgType {
		case msgPing:
			if err := writeMessage(conn, msgPong, payload); err != nil {
				return err
			}
		case msgCancel:
			// Sequential dispatch means there is no in-flight work to stop;
			// acknowledge by ignoring, mirroring the Rust server.
			continue
		case msgRequestHeaders:
			var event RequestHeadersEvent
			resp, cid := dispatch(ctx, payload, &event,
				func(e *RequestHeadersEvent) string { return e.Metadata.CorrelationID },
				s.handler.OnRequestHeaders)
			if err := writeResponse(conn, cid, resp); err != nil {
				return err
			}
		case msgRequestBodyChunk:
			h, _ := s.handler.(RequestBodyHandler)
			var event RequestBodyChunkEvent
			resp, cid := dispatchOptional(ctx, payload, &event,
				func(e *RequestBodyChunkEvent) string { return e.CorrelationID },
				h, RequestBodyHandler.OnRequestBodyChunk)
			if err := writeResponse(conn, cid, resp); err != nil {
				return err
			}
		case msgResponseHeaders:
			h, _ := s.handler.(ResponseHeadersHandler)
			var event ResponseHeadersEvent
			resp, cid := dispatchOptional(ctx, payload, &event,
				func(e *ResponseHeadersEvent) string { return e.CorrelationID },
				h, ResponseHeadersHandler.OnResponseHeaders)
			if err := writeResponse(conn, cid, resp); err != nil {
				return err
			}
		case msgResponseBodyChunk:
			h, _ := s.handler.(ResponseBodyHandler)
			var event ResponseBodyChunkEvent
			resp, cid := dispatchOptional(ctx, payload, &event,
				func(e *ResponseBodyChunkEvent) string { return e.CorrelationID },
				h, ResponseBodyHandler.OnResponseBodyChunk)
			if err := writeResponse(conn, cid, resp); err != nil {
				return err
			}
		case msgRequestComplete:
			h, _ := s.handler.(CompleteHandler)
			var event RequestCompleteEvent
			resp, cid := dispatchOptional(ctx, payload, &event,
				func(e *RequestCompleteEvent) string { return e.CorrelationID },
				h, CompleteHandler.OnRequestComplete)
			if err := writeResponse(conn, cid, resp); err != nil {
				return err
			}
		default:
			s.log.Debug("ignoring unhandled message type", "type", fmt.Sprintf("0x%02x", msgType))
		}
	}
}

// capabilities derives the advertised capability set from which optional
// interfaces the handler implements.
func (s *Server) capabilities() capabilities {
	events := []int32{eventRequestHeaders}
	_, hasReqBody := s.handler.(RequestBodyHandler)
	if hasReqBody {
		events = append(events, eventRequestBodyChunk)
	}
	_, hasRespHeaders := s.handler.(ResponseHeadersHandler)
	if hasRespHeaders {
		events = append(events, eventResponseHeaders)
	}
	_, hasRespBody := s.handler.(ResponseBodyHandler)
	if hasRespBody {
		events = append(events, eventResponseBodyChunk)
	}
	if _, ok := s.handler.(CompleteHandler); ok {
		events = append(events, eventRequestComplete)
	}

	return capabilities{
		AgentID:         s.cfg.AgentID,
		Name:            s.cfg.Name,
		Version:         s.cfg.Version,
		SupportedEvents: events,
		Features: features{
			StreamingBody:      hasReqBody || hasRespBody,
			ConcurrentRequests: s.cfg.MaxConcurrency,
		},
		Limits: limits{
			MaxBodySize:        s.cfg.MaxBodySize,
			MaxConcurrency:     s.cfg.MaxConcurrency,
			PreferredChunkSize: 64 * 1024,
		},
	}
}

// dispatch decodes payload into event and invokes fn. Decode failures answer
// Allow (fail-open at the protocol layer; policy-level failure modes are the
// proxy's job), mirroring the Rust server.
func dispatch[E any](
	ctx context.Context,
	payload []byte,
	event *E,
	cidOf func(*E) string,
	fn func(context.Context, *E) *Response,
) (*Response, string) {
	if err := json.Unmarshal(payload, event); err != nil {
		return AllowResponse(), ""
	}
	cid := cidOf(event)
	resp := fn(ctx, event)
	if resp == nil {
		resp = AllowResponse()
	}
	return resp, cid
}

// dispatchOptional is dispatch for events whose handler interface may not be
// implemented; a nil handler answers Allow like the Rust trait defaults.
func dispatchOptional[H any, E any](
	ctx context.Context,
	payload []byte,
	event *E,
	cidOf func(*E) string,
	handler H,
	method func(H, context.Context, *E) *Response,
) (*Response, string) {
	if err := json.Unmarshal(payload, event); err != nil {
		return AllowResponse(), ""
	}
	cid := cidOf(event)
	if any(handler) == nil {
		return AllowResponse(), cid
	}
	resp := method(handler, ctx, event)
	if resp == nil {
		resp = AllowResponse()
	}
	return resp, cid
}

// writeResponse injects the correlation id into audit.custom (the proxy's
// multiplexing client routes responses by it) and writes an AgentResponse.
func writeResponse(conn net.Conn, correlationID string, resp *Response) error {
	if resp.Audit.Custom == nil {
		resp.Audit.Custom = map[string]any{}
	}
	resp.Audit.Custom["correlation_id"] = correlationID
	if resp.Version == 0 {
		resp.Version = ProtocolVersion
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return writeMessage(conn, msgAgentResponse, payload)
}

// ============================================================================
// Framing: 4-byte big-endian length (includes type byte) + type + payload
// ============================================================================

func writeMessage(w io.Writer, msgType byte, payload []byte) error {
	if len(payload) > maxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(payload), maxMessageSize)
	}
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)+1))
	header[4] = msgType
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMessage(r io.Reader) (byte, []byte, error) {
	var lenBytes [4]byte
	if _, err := io.ReadFull(r, lenBytes[:]); err != nil {
		return 0, nil, err
	}
	totalLen := binary.BigEndian.Uint32(lenBytes[:])
	if totalLen == 0 {
		return 0, nil, errors.New("zero-length message")
	}
	if totalLen > maxMessageSize {
		return 0, nil, fmt.Errorf("message too large: %d > %d", totalLen, maxMessageSize)
	}
	var typeByte [1]byte
	if _, err := io.ReadFull(r, typeByte[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, totalLen-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typeByte[0], payload, nil
}
