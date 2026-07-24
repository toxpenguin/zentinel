//! Semantic configuration diff.
//!
//! Reports the *behavioral* delta between two configurations — routes that
//! changed shape or reachability, upstream/agent/listener wiring, TLS policy,
//! failure-mode flips — rather than a textual diff. Serves the same North Star
//! as `explain` and `lint`: every decision visible and traceable, so an
//! operator (or CI) can gate a deploy on "this change only touches route X".
//!
//! # Semantics
//!
//! - Entities are matched across the two configs by **id**; a rename therefore
//!   reads as a remove plus an add.
//! - Equality is computed on *behavior*, not text. Order-independent collections
//!   (a route's match conditions) are compared as multisets, so reordering them
//!   yields no delta; order-dependent ones (a route's filter chain, whose
//!   execution order is load-bearing) are compared in order.
//! - Reachability deltas reuse the linter's shadowing analysis, which detects
//!   only *strictly-higher-priority* shadowing — so "became unreachable" carries
//!   that same blind spot (equal-priority/specificity shadowing is not detected).
//! - Route-level `failure-mode` and `timeout-secs` are compared (a failure-mode
//!   flip is High — a security-posture change). Other `policies` fields
//!   (`rate-limit`, request/response buffering, `max-body-size`) are not yet
//!   parsed from KDL, so they are not compared.

use std::collections::HashMap;

use serde::Serialize;

use zentinel_common::types::TlsVersion;

use super::lint::shadowing_route;
use crate::filters::Filter;
use crate::{Config, FailureMode, MatchCondition, RouteConfig};

/// Whether a delta should gate CI or is merely advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Silently breaks traffic or removes a security control. CI should gate.
    High,
    /// Review recommended, not blocking.
    Advisory,
}

/// A single behavioral difference between two configs.
#[derive(Debug, Clone, Serialize)]
pub struct Delta {
    /// Gate vs advisory.
    pub severity: Severity,
    /// Entity kind: `route`, `upstream`, `listener`, `agent`, or `filter`.
    pub category: &'static str,
    /// The id of the entity the delta concerns.
    pub entity: String,
    /// Human-readable description of what changed.
    pub summary: String,
}

impl Delta {
    fn high(category: &'static str, entity: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            severity: Severity::High,
            category,
            entity: entity.into(),
            summary: summary.into(),
        }
    }

    fn advisory(
        category: &'static str,
        entity: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            severity: Severity::Advisory,
            category,
            entity: entity.into(),
            summary: summary.into(),
        }
    }
}

/// The full semantic diff between two configs.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigDiff {
    /// All behavioral deltas, High severity first.
    pub deltas: Vec<Delta>,
}

impl ConfigDiff {
    /// True if any delta gates CI.
    #[must_use]
    pub fn has_high_severity(&self) -> bool {
        self.deltas.iter().any(|d| d.severity == Severity::High)
    }

    /// Render the diff as a human-readable report.
    #[must_use]
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();

        if self.deltas.is_empty() {
            out.push_str("No behavioral differences.\n");
            return out;
        }

        let high = self
            .deltas
            .iter()
            .filter(|d| d.severity == Severity::High)
            .count();
        let advisory = self.deltas.len() - high;
        let _ = writeln!(
            out,
            "{} behavioral change(s): {high} high, {advisory} advisory.\n",
            self.deltas.len()
        );
        for d in &self.deltas {
            let tag = match d.severity {
                Severity::High => "HIGH",
                Severity::Advisory => "adv ",
            };
            let _ = writeln!(out, "  [{tag}] {}: {}", d.category, d.summary);
        }
        out
    }
}

/// Compute the semantic diff from `old` to `new`.
#[must_use]
pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
    let mut deltas = Vec::new();

    diff_routes(old, new, &mut deltas);
    diff_upstreams(old, new, &mut deltas);
    diff_listeners(old, new, &mut deltas);
    diff_agents(old, new, &mut deltas);
    diff_filters(old, new, &mut deltas);

    // High severity first; stable sort preserves discovery order within a group.
    deltas.sort_by_key(|d| match d.severity {
        Severity::High => 0,
        Severity::Advisory => 1,
    });

    ConfigDiff { deltas }
}

// ============================================================================
// Routes
// ============================================================================

fn diff_routes(old: &Config, new: &Config, deltas: &mut Vec<Delta>) {
    let old_idx = index_by_id(old.routes.iter().map(|r| r.id.as_str()));
    let new_idx = index_by_id(new.routes.iter().map(|r| r.id.as_str()));

    for r in &old.routes {
        if !new_idx.contains_key(r.id.as_str()) {
            deltas.push(Delta::high(
                "route",
                &r.id,
                format!("route '{}' removed", r.id),
            ));
        }
    }
    for r in &new.routes {
        if !old_idx.contains_key(r.id.as_str()) {
            deltas.push(Delta::advisory(
                "route",
                &r.id,
                format!("route '{}' added", r.id),
            ));
        }
    }

    for (id, &oi) in &old_idx {
        let Some(&ni) = new_idx.get(id) else {
            continue;
        };
        let o = &old.routes[oi];
        let n = &new.routes[ni];

        // Primary upstream changed — live traffic is redirected to a different backend.
        if o.upstream != n.upstream {
            deltas.push(Delta::high(
                "route",
                *id,
                format!(
                    "route '{id}' upstream {} -> {}",
                    opt_str(&o.upstream),
                    opt_str(&n.upstream)
                ),
            ));
        }

        // Match conditions (behavioral: order-independent).
        if !matches_eq(&o.matches, &n.matches) {
            deltas.push(Delta::advisory(
                "route",
                *id,
                format!("route '{id}' match conditions changed"),
            ));
        }

        // Priority.
        if o.priority != n.priority {
            deltas.push(Delta::advisory(
                "route",
                *id,
                format!("route '{id}' priority {} -> {}", o.priority, n.priority),
            ));
        }

        // Failure-mode flip — a security-posture change (fail-open vs fail-closed).
        if o.policies.failure_mode != n.policies.failure_mode {
            deltas.push(Delta::high(
                "route",
                *id,
                format!(
                    "route '{id}' failure-mode {} -> {}",
                    fmode(o.policies.failure_mode),
                    fmode(n.policies.failure_mode)
                ),
            ));
        }

        // Request timeout override.
        if o.policies.timeout_secs != n.policies.timeout_secs {
            deltas.push(Delta::advisory(
                "route",
                *id,
                format!(
                    "route '{id}' timeout {} -> {}",
                    opt_secs(o.policies.timeout_secs),
                    opt_secs(n.policies.timeout_secs)
                ),
            ));
        }

        // Filter chain (order-dependent).
        diff_route_filters(id, o, n, old, deltas);

        // Reachability regression.
        let reachable_old = shadowing_route(&old.routes, oi).is_none();
        let shadow_new = shadowing_route(&new.routes, ni);
        match (reachable_old, shadow_new) {
            (true, Some(h)) => deltas.push(Delta::high(
                "route",
                *id,
                format!(
                    "route '{id}' became unreachable (now shadowed by '{}')",
                    h.id
                ),
            )),
            (false, None) => deltas.push(Delta::advisory(
                "route",
                *id,
                format!("route '{id}' became reachable"),
            )),
            _ => {}
        }
    }
}

fn diff_route_filters(
    id: &str,
    o: &RouteConfig,
    n: &RouteConfig,
    old: &Config,
    deltas: &mut Vec<Delta>,
) {
    if o.filters == n.filters {
        return; // identical content and order
    }

    // Filters removed from the route that dispatch to an agent = a dropped
    // auth/WAF control -> High.
    let agent_removed: Vec<&str> = o
        .filters
        .iter()
        .filter(|f| !n.filters.contains(*f))
        .filter(|f| {
            old.filters
                .get(f.as_str())
                .is_some_and(|fc| matches!(fc.filter, Filter::Agent(_)))
        })
        .map(String::as_str)
        .collect();

    let chain = format!("[{}] -> [{}]", o.filters.join(", "), n.filters.join(", "));
    if agent_removed.is_empty() {
        deltas.push(Delta::advisory(
            "route",
            id,
            format!("route '{id}' filter chain changed: {chain}"),
        ));
    } else {
        deltas.push(Delta::high(
            "route",
            id,
            format!(
                "route '{id}' no longer runs agent filter(s) {}: {chain}",
                agent_removed.join(", ")
            ),
        ));
    }
}

// ============================================================================
// Upstreams
// ============================================================================

fn diff_upstreams(old: &Config, new: &Config, deltas: &mut Vec<Delta>) {
    for (id, o) in &old.upstreams {
        match new.upstreams.get(id) {
            None => deltas.push(Delta::high(
                "upstream",
                id,
                format!("upstream '{id}' removed"),
            )),
            Some(n) => {
                if !multiset_eq(&o.targets, &n.targets) {
                    deltas.push(Delta::advisory(
                        "upstream",
                        id,
                        format!(
                            "upstream '{id}' target set changed ({} -> {} target(s))",
                            o.targets.len(),
                            n.targets.len()
                        ),
                    ));
                }
                if o.load_balancing != n.load_balancing {
                    deltas.push(Delta::advisory(
                        "upstream",
                        id,
                        format!(
                            "upstream '{id}' load-balancing {:?} -> {:?}",
                            o.load_balancing, n.load_balancing
                        ),
                    ));
                }
                if o.health_check.is_some() != n.health_check.is_some() {
                    let word = if n.health_check.is_some() {
                        "added"
                    } else {
                        "removed"
                    };
                    deltas.push(Delta::advisory(
                        "upstream",
                        id,
                        format!("upstream '{id}' health check {word}"),
                    ));
                }
            }
        }
    }
    for id in new.upstreams.keys() {
        if !old.upstreams.contains_key(id) {
            deltas.push(Delta::advisory(
                "upstream",
                id,
                format!("upstream '{id}' added"),
            ));
        }
    }
}

// ============================================================================
// Listeners
// ============================================================================

fn diff_listeners(old: &Config, new: &Config, deltas: &mut Vec<Delta>) {
    let old_idx = index_by_id(old.listeners.iter().map(|l| l.id.as_str()));
    let new_idx = index_by_id(new.listeners.iter().map(|l| l.id.as_str()));

    for l in &old.listeners {
        if !new_idx.contains_key(l.id.as_str()) {
            deltas.push(Delta::high(
                "listener",
                &l.id,
                format!("listener '{}' removed", l.id),
            ));
        }
    }
    for l in &new.listeners {
        if !old_idx.contains_key(l.id.as_str()) {
            deltas.push(Delta::advisory(
                "listener",
                &l.id,
                format!("listener '{}' added", l.id),
            ));
        }
    }

    for (id, &oi) in &old_idx {
        let Some(&ni) = new_idx.get(id) else {
            continue;
        };
        let o = &old.listeners[oi];
        let n = &new.listeners[ni];

        match (&o.tls, &n.tls) {
            (Some(_), None) => deltas.push(Delta::high(
                "listener",
                *id,
                format!("listener '{id}' TLS removed"),
            )),
            (None, Some(_)) => deltas.push(Delta::advisory(
                "listener",
                *id,
                format!("listener '{id}' TLS added"),
            )),
            (Some(ot), Some(nt)) => {
                if tls_rank(&nt.min_version) < tls_rank(&ot.min_version) {
                    deltas.push(Delta::high(
                        "listener",
                        *id,
                        format!(
                            "listener '{id}' TLS minimum lowered {} -> {}",
                            ot.min_version, nt.min_version
                        ),
                    ));
                } else if tls_rank(&nt.min_version) > tls_rank(&ot.min_version) {
                    deltas.push(Delta::advisory(
                        "listener",
                        *id,
                        format!(
                            "listener '{id}' TLS minimum raised {} -> {}",
                            ot.min_version, nt.min_version
                        ),
                    ));
                }
                if ot.client_auth && !nt.client_auth {
                    deltas.push(Delta::high(
                        "listener",
                        *id,
                        format!("listener '{id}' client-auth disabled"),
                    ));
                } else if !ot.client_auth && nt.client_auth {
                    deltas.push(Delta::advisory(
                        "listener",
                        *id,
                        format!("listener '{id}' client-auth enabled"),
                    ));
                }
            }
            (None, None) => {}
        }

        if o.address != n.address {
            deltas.push(Delta::advisory(
                "listener",
                *id,
                format!("listener '{id}' address {} -> {}", o.address, n.address),
            ));
        }
        if o.default_route != n.default_route {
            deltas.push(Delta::advisory(
                "listener",
                *id,
                format!(
                    "listener '{id}' default-route {} -> {}",
                    opt_str(&o.default_route),
                    opt_str(&n.default_route)
                ),
            ));
        }
    }
}

// ============================================================================
// Agents
// ============================================================================

fn diff_agents(old: &Config, new: &Config, deltas: &mut Vec<Delta>) {
    let old_idx = index_by_id(old.agents.iter().map(|a| a.id.as_str()));
    let new_idx = index_by_id(new.agents.iter().map(|a| a.id.as_str()));

    for a in &old.agents {
        if !new_idx.contains_key(a.id.as_str()) {
            deltas.push(Delta::high(
                "agent",
                &a.id,
                format!("agent '{}' removed (routes referencing it will fail)", a.id),
            ));
        }
    }
    for a in &new.agents {
        if !old_idx.contains_key(a.id.as_str()) {
            deltas.push(Delta::advisory(
                "agent",
                &a.id,
                format!("agent '{}' added", a.id),
            ));
        }
    }

    for (id, &oi) in &old_idx {
        let Some(&ni) = new_idx.get(id) else {
            continue;
        };
        let o = &old.agents[oi];
        let n = &new.agents[ni];

        if o.failure_mode != n.failure_mode {
            deltas.push(Delta::high(
                "agent",
                *id,
                format!(
                    "agent '{id}' failure-mode {} -> {}",
                    fmode(o.failure_mode),
                    fmode(n.failure_mode)
                ),
            ));
        }
        if !value_eq(&o.agent_type, &n.agent_type) {
            deltas.push(Delta::advisory(
                "agent",
                *id,
                format!("agent '{id}' type changed"),
            ));
        }
        if !value_eq(&o.transport, &n.transport) {
            deltas.push(Delta::advisory(
                "agent",
                *id,
                format!("agent '{id}' transport/endpoint changed"),
            ));
        }
        if o.timeout_ms != n.timeout_ms {
            deltas.push(Delta::advisory(
                "agent",
                *id,
                format!(
                    "agent '{id}' timeout {} -> {} ms",
                    o.timeout_ms, n.timeout_ms
                ),
            ));
        }
    }
}

// ============================================================================
// Filters
// ============================================================================

fn diff_filters(old: &Config, new: &Config, deltas: &mut Vec<Delta>) {
    for (id, o) in &old.filters {
        match new.filters.get(id) {
            None => deltas.push(Delta::advisory(
                "filter",
                id,
                format!("filter '{id}' removed"),
            )),
            Some(n) => {
                if o.filter_type() != n.filter_type() {
                    deltas.push(Delta::high(
                        "filter",
                        id,
                        format!(
                            "filter '{id}' type {} -> {}",
                            o.filter_type(),
                            n.filter_type()
                        ),
                    ));
                } else if let (Filter::Agent(oa), Filter::Agent(na)) = (&o.filter, &n.filter) {
                    if oa.failure_mode != na.failure_mode {
                        deltas.push(Delta::high(
                            "filter",
                            id,
                            format!(
                                "filter '{id}' failure-mode {} -> {}",
                                opt_fmode(oa.failure_mode),
                                opt_fmode(na.failure_mode)
                            ),
                        ));
                    }
                    if oa.agent != na.agent {
                        deltas.push(Delta::advisory(
                            "filter",
                            id,
                            format!(
                                "filter '{id}' agent reference '{}' -> '{}'",
                                oa.agent, na.agent
                            ),
                        ));
                    }
                }
            }
        }
    }
    for id in new.filters.keys() {
        if !old.filters.contains_key(id) {
            deltas.push(Delta::advisory(
                "filter",
                id,
                format!("filter '{id}' added"),
            ));
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Build an id -> index map from an iterator of ids.
fn index_by_id<'a>(ids: impl Iterator<Item = &'a str>) -> HashMap<&'a str, usize> {
    ids.enumerate().map(|(i, id)| (id, i)).collect()
}

/// Behavioral equality of two match-condition sets. Order-independent across
/// conditions, and order-independent within a `Method` list (the router treats
/// methods as an upper-cased set, so `method "GET" "POST"` and
/// `method "POST" "get"` are the same behavior).
fn matches_eq(a: &[MatchCondition], b: &[MatchCondition]) -> bool {
    let mut ca: Vec<String> = a.iter().map(canonical_match).collect();
    let mut cb: Vec<String> = b.iter().map(canonical_match).collect();
    ca.sort();
    cb.sort();
    ca == cb
}

fn canonical_match(m: &MatchCondition) -> String {
    match m {
        MatchCondition::Method(methods) => {
            let mut ms: Vec<String> = methods.iter().map(|s| s.to_uppercase()).collect();
            ms.sort();
            format!("method:[{}]", ms.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Multiset equality via canonical JSON of each element. Order-independent —
/// two collections are equal iff they contain the same elements with the same
/// multiplicities, regardless of order.
fn multiset_eq<T: Serialize>(a: &[T], b: &[T]) -> bool {
    to_sorted_json(a) == to_sorted_json(b)
}

fn to_sorted_json<T: Serialize>(items: &[T]) -> Vec<String> {
    let mut json: Vec<String> = items
        .iter()
        .map(|item| serde_json::to_string(item).unwrap_or_default())
        .collect();
    json.sort();
    json
}

/// Structural (order-sensitive) equality via canonical JSON.
fn value_eq<T: Serialize>(a: &T, b: &T) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

fn opt_str(o: &Option<String>) -> String {
    match o {
        Some(s) => format!("'{s}'"),
        None => "(none)".to_string(),
    }
}

fn opt_secs(s: Option<u64>) -> String {
    match s {
        Some(v) => format!("{v}s"),
        None => "(listener default)".to_string(),
    }
}

/// Rank TLS versions so a lowered minimum can be detected (`TlsVersion` does
/// not implement `Ord`).
fn tls_rank(v: &TlsVersion) -> u8 {
    match v {
        TlsVersion::Tls12 => 12,
        TlsVersion::Tls13 => 13,
    }
}

fn fmode(mode: FailureMode) -> &'static str {
    match mode {
        FailureMode::Open => "open",
        FailureMode::Closed => "closed",
    }
}

fn opt_fmode(mode: Option<FailureMode>) -> &'static str {
    match mode {
        Some(FailureMode::Open) => "open",
        Some(FailureMode::Closed) => "closed",
        None => "unset",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
        system { worker-threads 0 }
        listeners {
            listener "http" { address "0.0.0.0:8080"  protocol "http" }
        }
        routes {
            route "api" {
                priority "normal"
                matches {
                    path-prefix "/api"
                    method "GET" "POST"
                }
                upstream "backend"
            }
        }
        upstreams {
            upstream "backend" {
                target "127.0.0.1:9000" weight=1
                load-balancing "round_robin"
            }
        }
    "#;

    fn cfg(kdl: &str) -> Config {
        Config::from_kdl(kdl).unwrap()
    }

    fn summaries(d: &ConfigDiff) -> Vec<String> {
        d.deltas.iter().map(|x| x.summary.clone()).collect()
    }

    #[test]
    fn identical_configs_have_no_deltas() {
        let d = diff(&cfg(BASE), &cfg(BASE));
        assert!(
            d.deltas.is_empty(),
            "unexpected deltas: {:?}",
            summaries(&d)
        );
        assert!(!d.has_high_severity());
    }

    #[test]
    fn reordered_match_conditions_are_not_a_delta() {
        // Behavioral equality: reordering match conditions must NOT diff.
        let a = r#"
            system { worker-threads 0 }
            listeners { listener "http" { address "0.0.0.0:8080"  protocol "http" } }
            routes {
                route "api" {
                    priority "normal"
                    matches {
                        path-prefix "/api"
                        host "example.com"
                        method "GET"
                    }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#;
        let b = r#"
            system { worker-threads 0 }
            listeners { listener "http" { address "0.0.0.0:8080"  protocol "http" } }
            routes {
                route "api" {
                    priority "normal"
                    matches {
                        method "GET"
                        host "example.com"
                        path-prefix "/api"
                    }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#;
        let d = diff(&cfg(a), &cfg(b));
        assert!(
            d.deltas.is_empty(),
            "reordering conditions should be no-op, got: {:?}",
            summaries(&d)
        );
    }

    #[test]
    fn changed_match_conditions_are_advisory() {
        let changed = BASE.replace("/api", "/apiv2");
        let d = diff(&cfg(BASE), &cfg(&changed));
        assert!(d
            .deltas
            .iter()
            .any(|x| x.summary.contains("match conditions changed")
                && x.severity == Severity::Advisory));
    }

    #[test]
    fn route_upstream_change_is_high() {
        let mut two = String::from(BASE);
        two = two.replace(
            "upstream \"backend\" {\n                target \"127.0.0.1:9000\"",
            "upstream \"other\" {\n                target \"127.0.0.1:9001\"",
        );
        // Point the route at the new upstream.
        let two = two.replace("upstream \"backend\"\n", "upstream \"other\"\n");
        let d = diff(&cfg(BASE), &cfg(&two));
        assert!(
            d.has_high_severity(),
            "expected high-severity delta, got: {:?}",
            summaries(&d)
        );
        assert!(d
            .deltas
            .iter()
            .any(|x| x.summary.contains("upstream") && x.severity == Severity::High));
    }

    #[test]
    fn route_removed_is_high() {
        let removed = r#"
            system { worker-threads 0 }
            listeners {
                listener "http" { address "0.0.0.0:8080"  protocol "http" }
            }
            routes {
                route "other" {
                    priority "normal"
                    matches { path-prefix "/other" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#;
        let d = diff(&cfg(BASE), &cfg(removed));
        assert!(d
            .deltas
            .iter()
            .any(|x| x.summary.contains("route 'api' removed") && x.severity == Severity::High));
        assert!(d.has_high_severity());
    }

    #[test]
    fn route_became_unreachable_is_high() {
        // New config adds a higher-priority catch-all that shadows "api".
        let shadowed = r#"
            system { worker-threads 0 }
            listeners {
                listener "http" { address "0.0.0.0:8080"  protocol "http" }
            }
            routes {
                route "catchall" {
                    priority "high"
                    matches { path-prefix "/" }
                    upstream "backend"
                }
                route "api" {
                    priority "normal"
                    matches {
                        path-prefix "/api"
                        method "GET" "POST"
                    }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#;
        let d = diff(&cfg(BASE), &cfg(shadowed));
        assert!(
            d.deltas
                .iter()
                .any(|x| x.summary.contains("became unreachable")
                    && x.summary.contains("catchall")
                    && x.severity == Severity::High),
            "expected unreachable delta, got: {:?}",
            summaries(&d)
        );
    }

    #[test]
    fn tls_minimum_lowered_is_high() {
        let tls13 = r#"
            system { worker-threads 0 }
            listeners {
                listener "https" {
                    address "0.0.0.0:8443"
                    protocol "https"
                    tls {
                        cert-file "/c.pem"
                        key-file "/k.pem"
                        min-version "TLS1.3"
                    }
                }
            }
            routes {
                route "api" {
                    priority "normal"
                    matches { path-prefix "/api" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#;
        let tls12 = tls13.replace("TLS1.3", "TLS1.2");
        let d = diff(&cfg(tls13), &cfg(&tls12));
        assert!(
            d.deltas
                .iter()
                .any(|x| x.summary.contains("TLS minimum lowered") && x.severity == Severity::High),
            "got: {:?}",
            summaries(&d)
        );
    }

    #[test]
    fn route_failure_mode_flip_is_high() {
        let open = r#"
            system { worker-threads 0 }
            listeners { listener "http" { address "0.0.0.0:8080"  protocol "http" } }
            routes {
                route "api" {
                    priority "normal"
                    matches { path-prefix "/api" }
                    upstream "backend"
                    policies { failure-mode "open" }
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#;
        let closed = open.replace("\"open\"", "\"closed\"");
        let d = diff(&cfg(open), &cfg(&closed));
        assert!(
            d.deltas
                .iter()
                .any(|x| x.summary.contains("failure-mode open -> closed")
                    && x.severity == Severity::High),
            "got: {:?}",
            summaries(&d)
        );
    }
}
