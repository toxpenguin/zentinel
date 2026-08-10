package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Mode selects whether rule matches are enforced or only recorded.
type Mode string

const (
	// ModeBlocking enforces disruptive actions (SecRuleEngine On).
	ModeBlocking Mode = "blocking"
	// ModeDetection records matches without blocking (SecRuleEngine DetectionOnly).
	ModeDetection Mode = "detection"
)

// Lifecycle selects how long a Coraza transaction is kept alive.
type Lifecycle string

const (
	// LifecycleHeaders inspects phases 1 and 2 at request-headers time and
	// closes the transaction immediately: no per-request state is retained.
	LifecycleHeaders Lifecycle = "headers"
	// LifecycleFull keeps the transaction across body and response events so
	// phases 2-5 can run, bounded by MaxTransactions and TransactionTTL.
	LifecycleFull Lifecycle = "full"
)

// Overflow selects what happens to a request that arrives while the
// transaction table is full.
type Overflow string

const (
	// OverflowAllow lets the request through uninspected (fail-open).
	OverflowAllow Overflow = "allow"
	// OverflowBlock rejects the request (fail-closed).
	OverflowBlock Overflow = "block"
)

// Config is the full agent configuration. Every field maps to exactly one
// command-line flag; there are no values that can only be set in code.
type Config struct {
	// Mode is blocking or detection.
	Mode Mode
	// RuleFiles are SecLang files or directories of *.conf, loaded in order.
	RuleFiles []string
	// Directives is extra inline SecLang, applied after RuleFiles.
	Directives string

	// AuditLog is the path for ModSecurity-native audit records. Empty
	// disables Coraza's audit engine.
	AuditLog string
	// AuditParts is the SecAuditLogParts string (ModSecurity letters).
	AuditParts string

	// RequestBody enables request body inspection (phase 2 over body bytes).
	RequestBody bool
	// ResponseBody enables response body inspection (phase 4).
	ResponseBody bool
	// BodyLimit bounds how many body bytes are buffered per direction.
	BodyLimit int

	// BlockStatus is the response status used when a rule denies without one.
	BlockStatus uint16
	// BlockBody is the body returned on a block.
	BlockBody string
	// ExposeRuleID adds X-Zentinel-WAF-Rule to block responses. Off by
	// default: rule IDs tell an attacker exactly which rule to evade.
	ExposeRuleID bool

	// Lifecycle is headers or full.
	Lifecycle Lifecycle
	// MaxTransactions bounds the in-flight transaction table (Lifecycle full).
	MaxTransactions int
	// TransactionTTL reclaims transactions whose request never completed.
	TransactionTTL time.Duration
	// Overflow is the decision applied when MaxTransactions is reached.
	Overflow Overflow
}

// DefaultConfig returns the configuration the flags default to.
func DefaultConfig() Config {
	return Config{
		Mode:            ModeBlocking,
		RuleFiles:       nil,
		Directives:      "",
		AuditLog:        "",
		AuditParts:      "ABCFHZ",
		RequestBody:     true,
		ResponseBody:    false,
		BodyLimit:       1 << 20, // 1 MiB
		BlockStatus:     403,
		BlockBody:       "Request blocked by WAF.",
		ExposeRuleID:    false,
		Lifecycle:       LifecycleFull,
		MaxTransactions: 10000,
		TransactionTTL:  60 * time.Second,
		Overflow:        OverflowAllow,
	}
}

// Validate checks the configuration and rejects combinations that would make
// the agent a silent no-op.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeBlocking, ModeDetection:
	default:
		return fmt.Errorf("mode: want %q or %q, got %q", ModeBlocking, ModeDetection, c.Mode)
	}
	switch c.Lifecycle {
	case LifecycleHeaders, LifecycleFull:
	default:
		return fmt.Errorf("lifecycle: want %q or %q, got %q", LifecycleHeaders, LifecycleFull, c.Lifecycle)
	}
	switch c.Overflow {
	case OverflowAllow, OverflowBlock:
	default:
		return fmt.Errorf("overflow: want %q or %q, got %q", OverflowAllow, OverflowBlock, c.Overflow)
	}
	if len(c.RuleFiles) == 0 && strings.TrimSpace(c.Directives) == "" {
		return fmt.Errorf("no rules configured: pass --rules and/or --directives " +
			"(refusing to start a WAF that would inspect nothing)")
	}
	if c.BodyLimit <= 0 {
		return fmt.Errorf("body-limit: must be > 0, got %d", c.BodyLimit)
	}
	if c.MaxTransactions <= 0 {
		return fmt.Errorf("max-transactions: must be > 0, got %d", c.MaxTransactions)
	}
	if c.TransactionTTL <= 0 {
		return fmt.Errorf("transaction-ttl: must be > 0, got %s", c.TransactionTTL)
	}
	if c.BlockStatus < 100 || c.BlockStatus > 599 {
		return fmt.Errorf("block-status: must be a valid HTTP status, got %d", c.BlockStatus)
	}
	if c.AuditLog != "" && strings.TrimSpace(c.AuditParts) == "" {
		return fmt.Errorf("audit-parts: must not be empty when --audit-log is set")
	}
	return nil
}

// runPhase2AtHeaders reports whether the request-body phase must be evaluated
// while handling request headers. Phase 2 is where most rulesets (CRS
// included) inspect ARGS, so it has to run even when no body is inspected —
// otherwise query-string rules would never fire.
func (c *Config) runPhase2AtHeaders() bool {
	return c.Lifecycle == LifecycleHeaders || !c.RequestBody
}

// engineDirectives renders the SecLang preamble derived from the flags. It is
// loaded before the operator's rule files so their directives win.
func (c *Config) engineDirectives() string {
	engine := "On"
	if c.Mode == ModeDetection {
		engine = "DetectionOnly"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SecRuleEngine %s\n", engine)
	fmt.Fprintf(&b, "SecRequestBodyAccess %s\n", onOff(c.RequestBody))
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\n", c.BodyLimit)
	fmt.Fprintf(&b, "SecRequestBodyInMemoryLimit %d\n", c.BodyLimit)
	b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	fmt.Fprintf(&b, "SecResponseBodyAccess %s\n", onOff(c.ResponseBody))
	fmt.Fprintf(&b, "SecResponseBodyLimit %d\n", c.BodyLimit)
	b.WriteString("SecResponseBodyLimitAction ProcessPartial\n")

	if c.AuditLog == "" {
		b.WriteString("SecAuditEngine Off\n")
		return b.String()
	}
	// Native + serial = the on-disk format ModSecurity writes, so existing
	// SIEM parsers and fail2ban regexes keep working unchanged.
	b.WriteString("SecAuditEngine RelevantOnly\n")
	b.WriteString("SecAuditLogType Serial\n")
	b.WriteString("SecAuditLogFormat Native\n")
	fmt.Fprintf(&b, "SecAuditLogParts %s\n", c.AuditParts)
	fmt.Fprintf(&b, "SecAuditLog %s\n", c.AuditLog)
	return b.String()
}

func onOff(v bool) string {
	if v {
		return "On"
	}
	return "Off"
}

// expandRuleFiles resolves each entry to concrete files: a file stays as-is, a
// directory expands to its *.conf entries in lexical order (the convention
// ModSecurity deployments already use). Missing paths and empty directories
// are errors — a WAF that loaded no rules must not start quietly.
func expandRuleFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("rules %q: %w", p, err)
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(p, "*.conf"))
		if err != nil {
			return nil, fmt.Errorf("rules %q: %w", p, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("rules %q: directory contains no *.conf files", p)
		}
		sort.Strings(matches)
		out = append(out, matches...)
	}
	return out, nil
}
