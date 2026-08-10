//! Dry-run request explanation for the `zentinel explain` subcommand.
//!
//! Given a [`Config`] and a synthetic request description, produce the full
//! routing decision: which route matched and what it beat, the ordered
//! filter/agent chain, effective timeout, failure mode, and upstream selection
//! policy. This is pure static analysis over the routing engine — no listener
//! is bound, no network I/O occurs, and the route cache is never consulted.
//!
//! It exists to serve the Manifesto's second principle — *security must be
//! explicit; every decision visible and traceable* — by making routing
//! decisions inspectable without running the proxy.
//!
//! # Fidelity
//!
//! The report mirrors Zentinel's **global** route matcher (the same one used
//! for requests that are not scoped to a namespace listener). Listener-scoped
//! default routes are not evaluated here; a request that matches no global
//! route is reported as `no_match` even if a listener would fall back to a
//! default. This is called out explicitly in the rendered output so nothing is
//! silently implied.

use std::collections::HashMap;

use serde::Serialize;

use zentinel_config::{Config, FailureMode, Filter, FilterPhase};

use crate::routing::{ExplainTrace, RequestInfo, RouteMatcher};

/// A synthetic request to explain. Owns its strings so the caller does not have
/// to keep the CLI arguments alive.
#[derive(Debug, Clone)]
pub struct ExplainRequest {
    /// HTTP method (upper-cased by the caller; matched case-sensitively).
    pub method: String,
    /// Request path, e.g. `/api/users`.
    pub path: String,
    /// Host header value, e.g. `example.com`.
    pub host: String,
    /// Additional headers for header-based route conditions (lower-cased keys).
    pub headers: HashMap<String, String>,
}

/// Full explanation of how a request routes. Serializable for `--json`.
#[derive(Debug, Serialize)]
pub struct ExplainReport {
    /// Echo of the request that was explained.
    pub request: RequestSummary,
    /// The winning route and its resolved wiring, if any route matched.
    pub matched: Option<MatchedRoute>,
    /// Routes that were evaluated but did not match, with the reason why.
    pub rejected: Vec<RejectedRoute>,
    /// True when no global route matched (see the module note on fidelity).
    pub no_match: bool,
}

/// Echo of the explained request.
#[derive(Debug, Serialize)]
pub struct RequestSummary {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Host header value.
    pub host: String,
}

/// The route that a request would be served by, plus its effective policy.
#[derive(Debug, Serialize)]
pub struct MatchedRoute {
    /// Route identifier.
    pub id: String,
    /// Route priority weight (higher is evaluated first).
    pub priority: i32,
    /// Tie-break specificity score (higher wins at equal priority).
    pub specificity: u32,
    /// Other routes that also matched but lost on priority/specificity.
    pub beat: Vec<BeatRoute>,
    /// Filters (including agent filters) in declared execution order.
    pub filters: Vec<FilterStep>,
    /// Whether the WAF is enabled on this route via the `waf-enabled` shorthand.
    pub waf_enabled: bool,
    /// Effective request timeout and where it comes from.
    pub timeout: TimeoutInfo,
    /// Failure mode when a dependency (e.g. an agent) fails: `open` or `closed`.
    pub failure_mode: String,
    /// Upstream selection, or `None` for static/built-in routes.
    pub upstream: Option<UpstreamInfo>,
}

/// A route beaten by the winner.
#[derive(Debug, Serialize)]
pub struct BeatRoute {
    /// Route identifier.
    pub id: String,
    /// Route priority weight.
    pub priority: i32,
}

/// A single filter in the route's chain.
#[derive(Debug, Serialize)]
pub struct FilterStep {
    /// Filter instance id (as referenced by the route).
    pub id: String,
    /// Filter type name, e.g. `headers`, `rate-limit`, `agent`.
    pub kind: String,
    /// Execution phase: `request`, `response`, or `both`.
    pub phase: String,
    /// True when this filter dispatches to an external agent.
    pub is_agent: bool,
    /// True when the route references a filter id that is not defined in the
    /// top-level `filters` block (it would be silently skipped at runtime).
    pub undefined: bool,
}

/// Effective timeout for the route.
///
/// Zentinel has no server-wide request timeout: the fallback is per-listener
/// (`listeners { listener { request-timeout-secs N } }`). Since explain is not
/// bound to a listener, the route override (if any) plus every listener's
/// request timeout are reported so the effective value is unambiguous.
#[derive(Debug, Serialize)]
pub struct TimeoutInfo {
    /// Route-level timeout override in seconds, if set.
    pub route_override_secs: Option<u64>,
    /// Per-listener request timeouts — the fallback when no route override.
    pub listener_defaults: Vec<ListenerTimeout>,
}

/// A single listener's request timeout.
#[derive(Debug, Serialize)]
pub struct ListenerTimeout {
    /// Listener id.
    pub listener: String,
    /// Request timeout in seconds for that listener.
    pub secs: u64,
}

/// Upstream selection policy for the matched route.
#[derive(Debug, Serialize)]
pub struct UpstreamInfo {
    /// Upstream pool name referenced by the route.
    pub name: String,
    /// Whether the referenced upstream is actually defined.
    pub defined: bool,
    /// Load-balancing algorithm, when the upstream is defined.
    pub load_balancing: Option<String>,
    /// Number of backend targets, when the upstream is defined.
    pub target_count: Option<usize>,
    /// PROXY protocol version emitted on new connections (`v1`/`v2`), if any.
    pub proxy_protocol: Option<String>,
    /// Backend profile named by the upstream, if any.
    pub profile: Option<String>,
    /// Settings the profile contributed, as `field=value` pairs. Empty when
    /// the upstream overrode everything the profile offered.
    pub profile_settings: Vec<String>,
}

/// A route that was evaluated but did not match.
#[derive(Debug, Serialize)]
pub struct RejectedRoute {
    /// Route identifier.
    pub id: String,
    /// Route priority weight.
    pub priority: i32,
    /// The first failing condition (or unmatched host set).
    pub reason: String,
}

/// Explain how `request` would route through `config`'s global routes.
///
/// # Errors
///
/// Returns an error if the routing engine fails to compile the configured
/// routes (e.g. an invalid path regex). Valid configs never fail here.
pub fn explain(config: &Config, request: &ExplainRequest) -> anyhow::Result<ExplainReport> {
    // Mirror the production global matcher: no listener-scoped default route.
    let matcher =
        RouteMatcher::with_cache_size(config.routes.clone(), None, config.server.route_cache_size)?;

    // Mirror production: the router matches against the query-stripped path
    // (`uri.path()`) and parses query params from `uri.query()`. Split a
    // `--path` that includes a `?query` the same way, so it routes exactly as it
    // would in the running proxy — including `query-param` match conditions.
    let (bare_path, query) = request
        .path
        .split_once('?')
        .map_or((request.path.as_str(), ""), |(p, q)| (p, q));

    let req = RequestInfo::new(&request.method, bare_path, &request.host)
        .with_headers(request.headers.clone())
        .with_query_params(RequestInfo::parse_query_string(query));

    let trace = matcher.explain_request(&req);

    Ok(build_report(config, request, &trace))
}

fn build_report(config: &Config, request: &ExplainRequest, trace: &ExplainTrace) -> ExplainReport {
    let summary = RequestSummary {
        method: request.method.clone(),
        path: request.path.clone(),
        host: request.host.clone(),
    };

    let rejected: Vec<RejectedRoute> = trace
        .evaluations
        .iter()
        .filter(|e| !e.matched)
        .map(|e| RejectedRoute {
            id: e.id.as_str().to_string(),
            priority: e.priority.as_i32(),
            reason: e
                .reject_reason
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        })
        .collect();

    let matched = trace.winner().map(|win| {
        // Look up the full route config for the winner to resolve its wiring.
        let route = config
            .routes
            .iter()
            .find(|r| r.id == win.id.as_str())
            .expect("winner id must exist in config routes");

        let beat = trace
            .beaten()
            .iter()
            .map(|e| BeatRoute {
                id: e.id.as_str().to_string(),
                priority: e.priority.as_i32(),
            })
            .collect();

        let filters = route
            .filters
            .iter()
            .map(|filter_id| match config.filters.get(filter_id) {
                Some(fc) => FilterStep {
                    id: filter_id.clone(),
                    kind: fc.filter_type().to_string(),
                    phase: phase_label(fc.phase()).to_string(),
                    is_agent: matches!(fc.filter, Filter::Agent(_)),
                    undefined: false,
                },
                None => FilterStep {
                    id: filter_id.clone(),
                    kind: "?".to_string(),
                    phase: "?".to_string(),
                    is_agent: false,
                    undefined: true,
                },
            })
            .collect();

        let timeout = TimeoutInfo {
            route_override_secs: route.policies.timeout_secs,
            listener_defaults: config
                .listeners
                .iter()
                .map(|l| ListenerTimeout {
                    listener: l.id.clone(),
                    secs: l.request_timeout_secs,
                })
                .collect(),
        };

        let upstream = route
            .upstream
            .as_ref()
            .map(|name| match config.upstreams.get(name) {
                Some(up) => UpstreamInfo {
                    name: name.clone(),
                    defined: true,
                    load_balancing: Some(format!("{:?}", up.load_balancing)),
                    target_count: Some(up.targets.len()),
                    proxy_protocol: up.proxy_protocol.map(|v| {
                        match v {
                            zentinel_config::ProxyProtocolVersion::V1 => "v1",
                            zentinel_config::ProxyProtocolVersion::V2 => "v2",
                        }
                        .to_string()
                    }),
                    profile: up.profile.as_ref().map(|p| p.name.clone()),
                    profile_settings: up.profile.as_ref().map_or_else(Vec::new, |p| {
                        p.settings
                            .iter()
                            .map(|s| format!("{}={}", s.field, s.value))
                            .collect()
                    }),
                },
                None => UpstreamInfo {
                    name: name.clone(),
                    defined: false,
                    load_balancing: None,
                    target_count: None,
                    proxy_protocol: None,
                    profile: None,
                    profile_settings: Vec::new(),
                },
            });

        MatchedRoute {
            id: win.id.as_str().to_string(),
            priority: win.priority.as_i32(),
            specificity: win.specificity,
            beat,
            filters,
            waf_enabled: route.waf_enabled,
            timeout,
            failure_mode: failure_mode_label(route.policies.failure_mode).to_string(),
            upstream,
        }
    });

    ExplainReport {
        no_match: matched.is_none(),
        request: summary,
        matched,
        rejected,
    }
}

fn phase_label(phase: FilterPhase) -> &'static str {
    match phase {
        FilterPhase::Request => "request",
        FilterPhase::Response => "response",
        FilterPhase::Both => "both",
    }
}

fn failure_mode_label(mode: FailureMode) -> &'static str {
    match mode {
        FailureMode::Open => "open",
        FailureMode::Closed => "closed",
    }
}

impl ExplainReport {
    /// Render the report as a human-readable text block.
    #[must_use]
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(512);

        let _ = writeln!(
            out,
            "Request: {} {}  (host: {})",
            self.request.method, self.request.path, self.request.host
        );
        out.push('\n');

        match &self.matched {
            Some(m) => {
                let _ = writeln!(
                    out,
                    "Matched route: \"{}\"  [priority {}, specificity {}]",
                    m.id, m.priority, m.specificity
                );

                if m.beat.is_empty() {
                    let _ = writeln!(out, "  Beat: (no other route matched)");
                } else {
                    let beat = m
                        .beat
                        .iter()
                        .map(|b| format!("\"{}\" [priority {}]", b.id, b.priority))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = writeln!(out, "  Beat: {beat}");
                }

                if m.filters.is_empty() {
                    let _ = writeln!(out, "  Filters: (none)");
                } else {
                    let _ = writeln!(out, "  Filters (in declared order):");
                    for (i, f) in m.filters.iter().enumerate() {
                        let agent = if f.is_agent { "  <- agent" } else { "" };
                        if f.undefined {
                            let _ = writeln!(
                                out,
                                "    {}. {}  UNDEFINED (not in filters block; skipped at runtime)",
                                i + 1,
                                f.id
                            );
                        } else {
                            let _ = writeln!(
                                out,
                                "    {}. {:<20} {:<12} [{}]{}",
                                i + 1,
                                f.id,
                                f.kind,
                                f.phase,
                                agent
                            );
                        }
                    }
                }

                let _ = writeln!(
                    out,
                    "  WAF: {}",
                    if m.waf_enabled {
                        "enabled (waf-enabled shorthand)"
                    } else {
                        "disabled"
                    }
                );

                match m.timeout.route_override_secs {
                    Some(secs) => {
                        let _ = writeln!(out, "  Effective timeout: {secs}s  (route override)");
                    }
                    None => {
                        let fallback = if m.timeout.listener_defaults.is_empty() {
                            "(no listeners configured)".to_string()
                        } else {
                            m.timeout
                                .listener_defaults
                                .iter()
                                .map(|l| format!("{}={}s", l.listener, l.secs))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        let _ = writeln!(
                            out,
                            "  Effective timeout: per-listener request-timeout — {fallback}"
                        );
                    }
                }

                let _ = writeln!(out, "  Failure mode: {}", m.failure_mode);

                match &m.upstream {
                    Some(u) if u.defined => {
                        let _ = writeln!(
                            out,
                            "  Upstream: \"{}\"  [{}, {} target(s)]",
                            u.name,
                            u.load_balancing.as_deref().unwrap_or("?"),
                            u.target_count.unwrap_or(0)
                        );
                        if let Some(pp) = &u.proxy_protocol {
                            let _ = writeln!(
                                out,
                                "  PROXY protocol: emits {pp} header on new connections \
                                 (backend sees real client IP; per-client connection pooling)"
                            );
                        }
                        // Profiles are shorthand, so show what the shorthand
                        // expanded to rather than just its name.
                        if let Some(profile) = &u.profile {
                            if u.profile_settings.is_empty() {
                                let _ = writeln!(
                                    out,
                                    "  Profile: \"{profile}\" — contributed nothing \
                                     (every setting is declared on the upstream)"
                                );
                            } else {
                                let _ = writeln!(
                                    out,
                                    "  Profile: \"{profile}\" — contributed {}",
                                    u.profile_settings.join(", ")
                                );
                            }
                        }
                    }
                    Some(u) => {
                        let _ = writeln!(
                            out,
                            "  Upstream: \"{}\"  UNDEFINED (not in upstreams block)",
                            u.name
                        );
                    }
                    None => {
                        let _ = writeln!(out, "  Upstream: (none — static or built-in handler)");
                    }
                }
            }
            None => {
                let _ = writeln!(out, "No route matched.");
                let _ = writeln!(out, "  Evaluated {} route(s):", self.rejected.len());
                for r in &self.rejected {
                    let _ = writeln!(
                        out,
                        "    - \"{}\" [priority {}]  rejected: {}",
                        r.id, r.priority, r.reason
                    );
                }
                let _ = writeln!(
                    out,
                    "  (note: listener-scoped default routes are not evaluated by explain)"
                );
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::Config;

    /// Two routes: high-priority `/api` (with a filter, upstream, timeout
    /// override, fail-open) and a low-priority catch-all `/`.
    const CONFIG_MULTI: &str = r#"
        system { worker-threads 0 }
        listeners {
            listener "http" {
                address "0.0.0.0:8080"
                protocol "http"
                request-timeout-secs 45
            }
        }
        filters {
            filter "cors" { type "cors" }
        }
        routes {
            route "api" {
                priority "high"
                matches { path-prefix "/api" }
                upstream "backend"
                filters "cors"
                policies {
                    timeout-secs 7
                    failure-mode "open"
                }
            }
            route "wide" {
                priority "low"
                matches { path-prefix "/" }
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

    fn req(method: &str, path: &str, host: &str) -> ExplainRequest {
        ExplainRequest {
            method: method.to_string(),
            path: path.to_string(),
            host: host.to_string(),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn upstream_proxy_protocol_is_surfaced() {
        let config = Config::from_kdl(
            r#"
            system { worker-threads 0 }
            listeners {
                listener "http" { address "0.0.0.0:8080" }
            }
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000"
                    proxy-protocol "v2"
                }
            }
            "#,
        )
        .unwrap();

        let report = explain(&config, &req("GET", "/x", "example.com")).unwrap();
        let m = report.matched.as_ref().expect("should match");
        assert_eq!(
            m.upstream
                .as_ref()
                .and_then(|u| u.proxy_protocol.as_deref()),
            Some("v2")
        );
        assert!(report
            .render_text()
            .contains("PROXY protocol: emits v2 header"));
    }

    #[test]
    fn backend_profile_expansion_is_surfaced() {
        let config = Config::from_kdl(
            r#"
            system { worker-threads 0 }
            listeners {
                listener "http" { address "0.0.0.0:8080" }
            }
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000"
                    profile "apache-shared-hosting"
                    timeouts { request 120 }
                }
            }
            "#,
        )
        .unwrap();

        let report = explain(&config, &req("GET", "/x", "example.com")).unwrap();
        let upstream = report
            .matched
            .as_ref()
            .expect("should match")
            .upstream
            .as_ref()
            .expect("upstream resolved");

        assert_eq!(upstream.profile.as_deref(), Some("apache-shared-hosting"));
        // The overridden setting is not claimed by the profile; the rest are.
        assert!(!upstream
            .profile_settings
            .iter()
            .any(|s| s.starts_with("timeouts.request=")));
        assert!(upstream
            .profile_settings
            .iter()
            .any(|s| s == "timeouts.connect=5s"));

        let text = report.render_text();
        assert!(
            text.contains("Profile: \"apache-shared-hosting\" — contributed"),
            "profile expansion missing from explain output:\n{text}"
        );
        assert!(text.contains("connection-pool.idle-timeout=3s"), "{text}");
    }

    #[test]
    fn matched_route_resolves_full_wiring() {
        let config = Config::from_kdl(CONFIG_MULTI).unwrap();
        let report = explain(&config, &req("GET", "/api/users", "example.com")).unwrap();

        assert!(!report.no_match);
        let m = report.matched.expect("should match");
        assert_eq!(m.id, "api");
        assert_eq!(m.priority, 100); // "high"

        // Beat the low-priority catch-all, which also matched.
        let beat: Vec<&str> = m.beat.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(beat, vec!["wide"]);

        // Filter chain resolved in declared order, with phase and non-agent flag.
        assert_eq!(m.filters.len(), 1);
        assert_eq!(m.filters[0].id, "cors");
        assert_eq!(m.filters[0].kind, "cors");
        assert_eq!(m.filters[0].phase, "both");
        assert!(!m.filters[0].is_agent);
        assert!(!m.filters[0].undefined);

        // Route-level `timeout-secs` / `failure-mode` from the `policies` block
        // are honored (parsed from KDL); explain reflects them.
        assert_eq!(m.timeout.route_override_secs, Some(7));
        assert_eq!(m.failure_mode, "open");

        let up = m.upstream.expect("has upstream");
        assert!(up.defined);
        assert_eq!(up.target_count, Some(1));
        assert!(up.load_balancing.unwrap().contains("RoundRobin"));
    }

    #[test]
    fn route_policies_reflect_current_values() {
        // explain reports whatever `RoutePolicies` currently holds, regardless
        // of source. Set values distinct from the config's KDL to prove it reads
        // the live struct, not a hardcoded default.
        let mut config = Config::from_kdl(CONFIG_MULTI).unwrap();
        let api = config
            .routes
            .iter_mut()
            .find(|r| r.id == "api")
            .expect("api route exists");
        api.policies.timeout_secs = Some(99);
        api.policies.failure_mode = FailureMode::Closed;

        let report = explain(&config, &req("GET", "/api/users", "example.com")).unwrap();
        let m = report.matched.as_ref().expect("should match");
        assert_eq!(m.timeout.route_override_secs, Some(99));
        assert_eq!(m.failure_mode, "closed");

        // Text render reflects the override branch.
        assert!(report.render_text().contains("route override"));
    }

    #[test]
    fn query_param_route_matches_via_path_query() {
        // A `--path` carrying a query string routes to a `query-param` route,
        // exactly as the running proxy would (both source params from the query).
        let config = Config::from_kdl(
            r#"
            system { worker-threads 0 }
            listeners { listener "http" { address "0.0.0.0:8080"  protocol "http" } }
            routes {
                route "beta" {
                    priority "high"
                    matches { query-param "flag" "on" }
                    upstream "backend"
                }
                route "wide" {
                    priority "low"
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:9000" weight=1
                    load-balancing "round_robin"
                }
            }
        "#,
        )
        .unwrap();

        // With ?flag=on the beta route wins.
        let hit = explain(&config, &req("GET", "/x?flag=on", "example.com")).unwrap();
        assert_eq!(hit.matched.expect("match").id, "beta");

        // Without it, the catch-all handles the request.
        let miss = explain(&config, &req("GET", "/x?flag=off", "example.com")).unwrap();
        assert_eq!(miss.matched.expect("match").id, "wide");
    }

    #[test]
    fn timeout_falls_back_to_listener_when_no_override() {
        let config = Config::from_kdl(CONFIG_MULTI).unwrap();
        // `/other` misses `/api` but hits the catch-all `wide`, which has no
        // route-level timeout override.
        let report = explain(&config, &req("GET", "/other", "example.com")).unwrap();

        let m = report.matched.expect("catch-all matches");
        assert_eq!(m.id, "wide");
        assert_eq!(m.timeout.route_override_secs, None);
        assert_eq!(m.timeout.listener_defaults.len(), 1);
        assert_eq!(m.timeout.listener_defaults[0].listener, "http");
        assert_eq!(m.timeout.listener_defaults[0].secs, 45);
        // Default failure mode is fail-closed (secure by default).
        assert_eq!(m.failure_mode, "closed");
    }

    #[test]
    fn no_match_reports_reasons() {
        // A single host-scoped route; a request to a different host matches
        // nothing, so the report is a no-match with an explained rejection.
        let config = Config::from_kdl(
            r#"
            system { worker-threads 0 }
            listeners {
                listener "http" { address "0.0.0.0:8080"  protocol "http" }
            }
            routes {
                route "only" {
                    matches { host "only.example.com" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" { target "127.0.0.1:9000" weight=1 }
            }
        "#,
        )
        .unwrap();

        let report = explain(&config, &req("GET", "/", "other.example.com")).unwrap();
        assert!(report.no_match);
        assert!(report.matched.is_none());
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].id, "only");
        assert!(report.rejected[0].reason.contains("host"));
    }

    #[test]
    fn query_string_in_path_is_stripped_for_matching() {
        // Production matches against `uri.path()` (query stripped). A `--path`
        // carrying a query string must still route to the path route, exactly
        // as the running proxy would.
        let config = Config::from_kdl(CONFIG_MULTI).unwrap();
        let report = explain(
            &config,
            &req("GET", "/api/users?flag=1&debug=true", "example.com"),
        )
        .unwrap();

        let m = report
            .matched
            .expect("path route matches despite query string");
        assert_eq!(m.id, "api");
    }
}
