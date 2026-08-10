// Command coraza-waf is a Zentinel external agent that enforces
// ModSecurity-compatible SecLang rulesets — OWASP CRS, Comodo, Imunify360
// exports, custom vendor rules — using the Coraza engine.
//
// It speaks the v2 agent protocol over a Unix socket via the Go SDK, so a
// crash or a rule-induced hang is contained in this process and never reaches
// the proxy dataplane.
//
//	coraza-waf --socket /run/zentinel/coraza-waf.sock \
//	           --rules /etc/modsecurity.d/owasp-crs \
//	           --audit-log /var/log/zentinel/waf-audit.log
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	za "github.com/zentinelproxy/zentinel/sdk/go"
)

// version is the agent version reported in the protocol handshake.
const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "coraza-waf: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := DefaultConfig()

	fs := flag.NewFlagSet("coraza-waf", flag.ContinueOnError)
	socket := fs.String("socket", "/run/zentinel/coraza-waf.sock", "Unix socket to serve the agent protocol on")
	agentName := fs.String("name", "coraza-waf", "agent name reported in the handshake")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	showVersion := fs.Bool("version", false, "print version and exit")

	var rules multiFlag
	fs.Var(&rules, "rules", "SecLang rule file or directory of *.conf (repeatable, loaded in order)")
	mode := fs.String("mode", string(cfg.Mode), "blocking (enforce) or detection (log only)")
	fs.StringVar(&cfg.Directives, "directives", cfg.Directives, "extra inline SecLang directives, applied after --rules")
	fs.StringVar(&cfg.AuditLog, "audit-log", cfg.AuditLog, "path for ModSecurity-native audit records (empty disables auditing)")
	fs.StringVar(&cfg.AuditParts, "audit-parts", cfg.AuditParts, "SecAuditLogParts letters")
	fs.BoolVar(&cfg.RequestBody, "request-body", cfg.RequestBody, "inspect request bodies (requires the request_body event in KDL)")
	fs.BoolVar(&cfg.ResponseBody, "response-body", cfg.ResponseBody, "inspect response bodies (requires the response_body event in KDL)")
	fs.IntVar(&cfg.BodyLimit, "body-limit", cfg.BodyLimit, "max bytes buffered per body, per direction")
	blockStatus := fs.Uint("block-status", uint(cfg.BlockStatus), "status returned when a rule denies without one")
	fs.StringVar(&cfg.BlockBody, "block-body", cfg.BlockBody, "body returned on a block")
	fs.BoolVar(&cfg.ExposeRuleID, "expose-rule-id", cfg.ExposeRuleID, "add X-Zentinel-WAF-Rule to block responses (tells clients which rule fired)")
	lifecycle := fs.String("lifecycle", string(cfg.Lifecycle), "headers (phases 1-2, no state) or full (phases 1-5)")
	fs.IntVar(&cfg.MaxTransactions, "max-transactions", cfg.MaxTransactions, "max in-flight transactions (lifecycle=full)")
	fs.DurationVar(&cfg.TransactionTTL, "transaction-ttl", cfg.TransactionTTL, "reclaim transactions idle for longer than this")
	overflow := fs.String("overflow", string(cfg.Overflow), "allow or block when the transaction table is full")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("coraza-waf %s (agent protocol v%d)\n", version, za.ProtocolVersion)
		return nil
	}

	cfg.RuleFiles = rules
	cfg.Mode = Mode(*mode)
	cfg.Lifecycle = Lifecycle(*lifecycle)
	cfg.Overflow = Overflow(*overflow)
	cfg.BlockStatus = uint16(*blockStatus)

	logger, err := newLogger(*logLevel, *logFormat)
	if err != nil {
		return err
	}

	agent, err := New(cfg, logger)
	if err != nil {
		return err
	}
	defer agent.Close()

	server, err := za.NewServer(za.Config{
		Name:        *agentName,
		Version:     version,
		MaxBodySize: uint64(cfg.BodyLimit),
		Logger:      logger,
	}, agent)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agent.StartSweeper(ctx)

	return server.ListenAndServe(ctx, *socket)
}

func newLogger(level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("log-level: unknown level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(format) {
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("log-format: want text or json, got %q", format)
	}
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("empty value")
	}
	*m = append(*m, v)
	return nil
}
