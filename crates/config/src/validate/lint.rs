//! Configuration linting for best practices
//!
//! Checks configuration for missing best practices and potential issues.

use super::{ValidationResult, ValidationWarning};
use crate::filters::{Filter, HeadersFilter};
use crate::{Config, FailureMode, MatchCondition, RouteConfig};

/// Lint configuration for best practices
pub fn lint_config(config: &Config) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check routes for missing best practices
    for route in &config.routes {
        // Check for missing retry policy
        if route.retry_policy.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' has no retry policy (recommended for production)",
                route.id
            )));
        }

        // Check for missing timeout
        if route.policies.timeout_secs.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' has no timeout (recommended for production)",
                route.id
            )));
        }

        // Check for missing upstream (skip for static and builtin service types)
        use crate::routes::ServiceType;
        if route.upstream.is_none()
            && !matches!(
                route.service_type,
                ServiceType::Static | ServiceType::Builtin
            )
        {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' has no upstream configured",
                route.id
            )));
        }
    }

    // Check upstreams for missing health checks
    for (name, upstream) in &config.upstreams {
        if upstream.health_check.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{}' has no health check (recommended for production)",
                name
            )));
        }

        // Check for single target without health check
        if upstream.targets.len() == 1 && upstream.health_check.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{}' has only one target and no health check (no failover possible)",
                name
            )));
        }

        // A profile whose every setting is overridden reads as if the backend
        // tuning came from the profile when none of it did.
        if let Some(profile) = &upstream.profile {
            if profile.settings.is_empty() {
                result.add_warning(ValidationWarning::new(format!(
                    "Upstream '{}' declares profile '{}' but overrides every setting it provides \
                     (the profile line is decorative — drop it, or drop the overrides)",
                    name, profile.name
                )));
            }
        }
    }

    // Check listeners for security best practices
    let has_tls_listener = config.listeners.iter().any(|l| l.tls.is_some());

    for listener in &config.listeners {
        // Check for HTTP listener on standard port without redirect to HTTPS
        if listener.address.ends_with(":80") && listener.tls.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Listener '{}' serves HTTP on port 80 without TLS (consider HTTPS redirect)",
                listener.address
            )));
        }

        // PROXY protocol trusting the whole address space defeats the
        // spoofing protection unless the network itself is isolated.
        if let Some(ref pp) = listener.proxy_protocol {
            for cidr in &pp.trusted {
                if cidr == "0.0.0.0/0" || cidr == "::/0" {
                    result.add_warning(ValidationWarning::new(format!(
                        "Listener '{}' accepts PROXY protocol from '{}' (every source): \
                         any client that can reach this listener can spoof its address. \
                         Only safe when the listener is reachable exclusively from \
                         trusted load balancers",
                        listener.id, cidr
                    )));
                }
            }
        }
    }

    // Check for HSTS header when TLS is enabled
    if has_tls_listener {
        check_hsts_headers(config, &mut result);
    }

    // Check observability configuration
    if !config.observability.metrics.enabled {
        result.add_warning(ValidationWarning::new(
            "Metrics are disabled (recommended for production monitoring)".to_string(),
        ));
    }

    // Check for access logs
    if let Some(ref access_log) = config.observability.logging.access_log {
        if !access_log.enabled {
            result.add_warning(ValidationWarning::new(
                "Access logs are disabled (recommended for debugging and compliance)".to_string(),
            ));
        }
    }

    // Route reachability: a strictly-higher-priority route can fully shadow a
    // lower one, making it dead config.
    check_unreachable_routes(config, &mut result);

    // Explicit failure policy for agent filters (Manifesto: no implied policy).
    check_agent_filter_failure_modes(config, &mut result);

    // Shadow/mirror traffic must not hit an upstream that serves live traffic.
    check_shadow_upstreams(config, &mut result);

    // Panel-issued certificates need their validation requests to reach the
    // panel, uninspected.
    check_dcv_passthrough(config, &mut result);

    result
}

// ============================================================================
// Rule: domain-control-validation (DCV) passthrough
// ============================================================================

/// Path prefixes certificate authorities fetch during domain validation.
/// `acme-challenge` is HTTP-01 (Let's Encrypt, ZeroSSL); `pki-validation` is
/// what Sectigo/Comodo — and therefore cPanel AutoSSL — use.
const DCV_PREFIXES: &[&str] = &[
    "/.well-known/acme-challenge/",
    "/.well-known/pki-validation/",
];

/// Warn about configurations where certificate renewal will fail silently.
///
/// When Zentinel owns :80/:443 in front of a control panel, the panel keeps
/// issuing and renewing certificates — but only if the CA's validation
/// requests still reach it. Nothing breaks on the day this is misconfigured;
/// it breaks at the first renewal, roughly 90 days later.
fn check_dcv_passthrough(config: &Config, result: &mut ValidationResult) {
    let panel_managed_certs = config.listeners.iter().any(|listener| {
        listener
            .tls
            .as_ref()
            .is_some_and(|tls| !tls.sni_cert_dirs.is_empty())
    });

    // Routes the operator pointed at a validation path on purpose, and routes
    // that merely happen to cover one (a catch-all, typically).
    let (dedicated, covering): (Vec<&RouteConfig>, Vec<&RouteConfig>) = config
        .routes
        .iter()
        .filter(|route| route_covers_dcv(route))
        .partition(|route| route_is_dedicated_dcv(route));

    if panel_managed_certs && dedicated.is_empty() && covering.is_empty() {
        result.add_warning(ValidationWarning::new(format!(
            "TLS listener serves panel-managed certificates (sni-cert-dir) but no route \
             matches {}. Domain-validation requests will not reach the panel, so \
             certificate renewals fail — silently, about 90 days after deployment. \
             Add a high-priority passthrough route to the panel's backend",
            DCV_PREFIXES.join(" or ")
        )));
    }

    // A validation request that gets inspected can be blocked, rewritten, or
    // delayed past the CA's timeout; the result is the same failed renewal.
    // Dedicated validation routes are always checked — writing the path out
    // states the intent. Broad routes are only checked when the config
    // actually depends on validation working (panel-managed certificates),
    // otherwise every catch-all with a filter would warn.
    let inspected = dedicated
        .iter()
        .chain(covering.iter().filter(|_| panel_managed_certs));

    for route in inspected {
        if !route.filters.is_empty() {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' serves domain-validation requests but runs filters ({}). \
                 Certificate authorities fetch these paths unauthenticated and with a \
                 short timeout — a WAF or auth agent blocking one fails the renewal. \
                 Serve validation paths without filters",
                route.id,
                route.filters.join(", ")
            )));
        }
        if route.waf_enabled {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' serves domain-validation requests with the WAF enabled. \
                 Disable WAF inspection on validation paths so renewals cannot be blocked",
                route.id
            )));
        }
    }
}

/// Whether requests to a DCV path can reach this route at all — either it was
/// written for validation paths, or its match is broad enough to include them.
fn route_covers_dcv(route: &RouteConfig) -> bool {
    route.matches.iter().any(|condition| match condition {
        MatchCondition::PathPrefix(prefix) => DCV_PREFIXES
            .iter()
            .any(|dcv| dcv.starts_with(prefix.as_str()) || prefix.starts_with(dcv)),
        // An exact path can only be a validation URL if it sits under one.
        MatchCondition::Path(path) => DCV_PREFIXES.iter().any(|dcv| path.starts_with(dcv)),
        _ => false,
    })
}

/// Whether the route names a validation path explicitly, rather than covering
/// it by being broad.
fn route_is_dedicated_dcv(route: &RouteConfig) -> bool {
    route.matches.iter().any(|condition| {
        let path = match condition {
            MatchCondition::PathPrefix(prefix) => prefix.as_str(),
            MatchCondition::Path(path) => path.as_str(),
            _ => return false,
        };
        path.starts_with("/.well-known/")
    })
}

// ============================================================================
// Rule: unreachable route (a higher-priority route fully shadows a lower one)
// ============================================================================

/// Warn when a route can never match because a strictly-higher-priority route
/// is evaluated first and matches a superset of its requests.
///
/// Deliberately conservative: it only warns when shadowing is *provable* and
/// bails silently on anything it cannot prove (regex conditions, host widening,
/// unconstrained lower routes), so it never emits a false "unreachable". It also
/// only considers *strictly* higher priority — equal-priority shadowing that
/// depends on specificity tie-breaks (resolved in the proxy crate) is
/// intentionally not detected, so the absence of a warning is not a guarantee
/// that no route is shadowed.
fn check_unreachable_routes(config: &Config, result: &mut ValidationResult) {
    let routes = &config.routes;
    for (li, lower) in routes.iter().enumerate() {
        if let Some(higher) = shadowing_route(routes, li) {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' (priority {}) is unreachable: route '{}' (priority {}) is \
                 evaluated first and matches every request '{}' would. Narrow '{}' or raise \
                 the priority of '{}'.",
                lower.id, lower.priority, higher.id, higher.priority, lower.id, higher.id, lower.id
            )));
        }
    }
}

/// The strictly-higher-priority route that shadows `routes[target_idx]`, if any
/// — the route that makes it unreachable. Shared with the config-diff module
/// (`super::diff`) for reachability analysis.
///
/// Detects only *strictly-higher-priority* shadowing (see
/// [`check_unreachable_routes`]); equal-priority shadowing decided by
/// specificity tie-breaks is intentionally not detected.
pub(crate) fn shadowing_route(routes: &[RouteConfig], target_idx: usize) -> Option<&RouteConfig> {
    let lower = &routes[target_idx];
    routes.iter().enumerate().find_map(|(hi, higher)| {
        (hi != target_idx && higher.priority > lower.priority && route_generalizes(higher, lower))
            .then_some(higher)
    })
}

/// True if every request matching `lower` also matches `higher`. Conservative:
/// returns `false` on anything not provably implied.
fn route_generalizes(higher: &RouteConfig, lower: &RouteConfig) -> bool {
    path_generalizes(higher, lower)
        && host_generalizes(higher, lower)
        && method_generalizes(higher, lower)
        && keyed_conditions_implied(higher, lower, KeyedKind::Header)
        && keyed_conditions_implied(higher, lower, KeyedKind::Query)
}

/// Every path condition on `higher` must be guaranteed by `lower`.
fn path_generalizes(higher: &RouteConfig, lower: &RouteConfig) -> bool {
    higher
        .matches
        .iter()
        .all(|h| higher_path_cond_is_guaranteed(h, lower))
}

/// Is a single path condition `h` from the higher route guaranteed to hold for
/// every request the lower route matches?
fn higher_path_cond_is_guaranteed(h: &MatchCondition, lower: &RouteConfig) -> bool {
    match h {
        MatchCondition::PathPrefix(hp) => {
            hp == "/" // matches every path
                || lower
                    .matches
                    .iter()
                    .any(|l| path_cond_guarantees_prefix(l, hp))
        }
        MatchCondition::Path(he) => lower
            .matches
            .iter()
            .any(|l| matches!(l, MatchCondition::Path(le) if le == he)),
        // A regex path condition cannot be proven implied.
        MatchCondition::PathRegex(_) => false,
        // Non-path conditions are handled by the other generalizes checks.
        _ => true,
    }
}

/// Does lower-route condition `l` guarantee the request path has prefix `hp`
/// (respecting Gateway API segment boundaries, as the router does)?
fn path_cond_guarantees_prefix(l: &MatchCondition, hp: &str) -> bool {
    match l {
        MatchCondition::PathPrefix(lp) => prefix_at_boundary(hp, lp),
        MatchCondition::Path(le) => prefix_at_boundary(hp, le),
        _ => false,
    }
}

/// True if any path with prefix/value `candidate` necessarily starts with
/// `prefix` at a segment boundary. Mirrors `CompiledMatcher::PathPrefix`.
fn prefix_at_boundary(prefix: &str, candidate: &str) -> bool {
    candidate.starts_with(prefix)
        && (prefix == "/"
            || candidate.len() == prefix.len()
            || prefix.ends_with('/')
            || candidate.as_bytes()[prefix.len()] == b'/')
}

/// Host conditions use OR semantics within a route. For `higher` to generalize
/// `lower`, every host `lower` permits must be covered by some `higher` host.
fn host_generalizes(higher: &RouteConfig, lower: &RouteConfig) -> bool {
    let h_hosts = host_patterns(higher);
    if h_hosts.is_empty() {
        return true; // higher does not constrain host
    }
    let l_hosts = host_patterns(lower);
    if l_hosts.is_empty() {
        return false; // lower matches any host; higher restricts -> not implied
    }
    l_hosts
        .iter()
        .all(|lh| h_hosts.iter().any(|hh| host_covers(hh, lh)))
}

fn host_patterns(route: &RouteConfig) -> Vec<&str> {
    route
        .matches
        .iter()
        .filter_map(|m| match m {
            MatchCondition::Host(h) => Some(h.as_str()),
            _ => None,
        })
        .collect()
}

/// Host-pattern classification mirroring `routing::HostMatcher`.
enum HostKind<'a> {
    Exact(&'a str),
    Wildcard(&'a str), // suffix after "*."
    Regex,             // opaque — coverage cannot be proven
}

fn classify_host(pattern: &str) -> HostKind<'_> {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        HostKind::Wildcard(suffix)
    } else if pattern.contains('*') || pattern.contains('[') {
        HostKind::Regex
    } else {
        HostKind::Exact(pattern)
    }
}

/// True if every host matching `lh` also matches `hh`.
fn host_covers(hh: &str, lh: &str) -> bool {
    match (classify_host(hh), classify_host(lh)) {
        (HostKind::Exact(h), HostKind::Exact(l)) => h == l,
        (HostKind::Wildcard(hsuf), HostKind::Exact(l)) => {
            // "*.hsuf" matches "x.hsuf": l ends with ".hsuf" and has a label before it.
            l.len() > hsuf.len() + 1
                && l.ends_with(hsuf)
                && l.as_bytes()[l.len() - hsuf.len() - 1] == b'.'
        }
        (HostKind::Wildcard(hsuf), HostKind::Wildcard(lsuf)) => {
            // "*.lsuf" is a subset of "*.hsuf" iff every "x.lsuf" ends with ".hsuf".
            lsuf == hsuf || lsuf.ends_with(&format!(".{hsuf}"))
        }
        // Exact higher cannot cover a wildcard set; regex is opaque.
        _ => false,
    }
}

/// The higher route's method restriction must be a superset of the lower's.
fn method_generalizes(higher: &RouteConfig, lower: &RouteConfig) -> bool {
    let Some(h_set) = method_set(higher) else {
        return true; // higher does not constrain method
    };
    let Some(l_set) = method_set(lower) else {
        return false; // lower matches all methods; higher restricts -> not implied
    };
    l_set.iter().all(|m| h_set.contains(m))
}

/// Methods a route accepts (upper-cased), or `None` if it sets no method
/// condition (accepts all). Multiple method conditions intersect (AND).
fn method_set(route: &RouteConfig) -> Option<std::collections::HashSet<String>> {
    let mut set: Option<std::collections::HashSet<String>> = None;
    for m in &route.matches {
        if let MatchCondition::Method(methods) = m {
            let upper: std::collections::HashSet<String> =
                methods.iter().map(|s| s.to_uppercase()).collect();
            set = Some(match set {
                None => upper,
                Some(existing) => existing.intersection(&upper).cloned().collect(),
            });
        }
    }
    set
}

/// Which keyed condition family to check.
#[derive(Clone, Copy)]
enum KeyedKind {
    Header,
    Query,
}

/// Every header/query condition on `higher` must be implied by a `lower`
/// condition of the same key.
fn keyed_conditions_implied(higher: &RouteConfig, lower: &RouteConfig, kind: KeyedKind) -> bool {
    let case_insensitive = matches!(kind, KeyedKind::Header);
    for (hn, hv) in keyed_conditions(higher, kind) {
        let implied = keyed_conditions(lower, kind).into_iter().any(|(ln, lv)| {
            let names_match = if case_insensitive {
                ln.eq_ignore_ascii_case(hn)
            } else {
                ln == hn
            };
            names_match
                && match hv {
                    None => true,                   // higher needs presence; lower guarantees the key
                    Some(hval) => lv == Some(hval), // higher needs a value; lower must fix the same one
                }
        });
        if !implied {
            return false;
        }
    }
    true
}

fn keyed_conditions(route: &RouteConfig, kind: KeyedKind) -> Vec<(&str, Option<&str>)> {
    route
        .matches
        .iter()
        .filter_map(|m| match (kind, m) {
            (KeyedKind::Header, MatchCondition::Header { name, value }) => {
                Some((name.as_str(), value.as_deref()))
            }
            (KeyedKind::Query, MatchCondition::QueryParam { name, value }) => {
                Some((name.as_str(), value.as_deref()))
            }
            _ => None,
        })
        .collect()
}

// ============================================================================
// Rule: agent filter without an explicit failure mode
// ============================================================================

/// Warn when a route references an agent filter that declares no `failure-mode`.
/// On agent failure such a filter silently inherits the route's `failure-mode`,
/// an implied policy the Manifesto asks to be made explicit.
fn check_agent_filter_failure_modes(config: &Config, result: &mut ValidationResult) {
    for route in &config.routes {
        for filter_id in &route.filters {
            let Some(filter_config) = config.filters.get(filter_id) else {
                continue; // undefined filter reference: reported elsewhere
            };
            if let Filter::Agent(agent_filter) = &filter_config.filter {
                if agent_filter.failure_mode.is_none() {
                    result.add_warning(ValidationWarning::new(format!(
                        "Agent filter '{}' on route '{}' has no explicit failure-mode; on agent \
                         failure it silently inherits the route's failure-mode ('{}'). Set \
                         failure-mode on the filter to make the policy explicit.",
                        filter_id,
                        route.id,
                        failure_mode_word(route.policies.failure_mode),
                    )));
                }
            }
        }
    }
}

fn failure_mode_word(mode: FailureMode) -> &'static str {
    match mode {
        FailureMode::Open => "open",
        FailureMode::Closed => "closed",
    }
}

// ============================================================================
// Rule: shadow traffic to a production upstream
// ============================================================================

/// Warn when a route mirrors shadow traffic to an upstream that also serves
/// live traffic as some route's primary target (including the route's own).
/// Mirrored requests reaching production can cause duplicate side effects.
fn check_shadow_upstreams(config: &Config, result: &mut ValidationResult) {
    use std::collections::HashSet;

    let primary: HashSet<&str> = config
        .routes
        .iter()
        .filter_map(|r| r.upstream.as_deref())
        .collect();

    for route in &config.routes {
        if let Some(shadow) = &route.shadow {
            if primary.contains(shadow.upstream.as_str()) {
                let target = if route.upstream.as_deref() == Some(shadow.upstream.as_str()) {
                    "its own primary upstream".to_string()
                } else {
                    format!("upstream '{}', which serves live traffic", shadow.upstream)
                };
                result.add_warning(ValidationWarning::new(format!(
                    "Route '{}' mirrors shadow traffic to {}. Mirrored requests will hit \
                     production; use a dedicated shadow upstream to avoid duplicate side effects.",
                    route.id, target
                )));
            }
        }
    }
}

/// HSTS header name (case-insensitive comparison should be used)
const HSTS_HEADER: &str = "Strict-Transport-Security";

/// Check for HSTS headers in route configurations and header filters
fn check_hsts_headers(config: &Config, result: &mut ValidationResult) {
    // Check if any route has HSTS in its response_headers
    let has_hsts_in_route_policies = config
        .routes
        .iter()
        .any(|route| route_has_hsts_header(&route.policies.response_headers));

    // Check if any headers filter sets HSTS
    let has_hsts_in_filter = config.filters.values().any(|filter_config| {
        if let Filter::Headers(headers_filter) = &filter_config.filter {
            headers_filter_has_hsts(headers_filter)
        } else {
            false
        }
    });

    // If TLS is enabled but no HSTS found, warn
    if !has_hsts_in_route_policies && !has_hsts_in_filter {
        result.add_warning(ValidationWarning::new(
            "TLS is enabled but no HSTS (Strict-Transport-Security) header is configured. \
             Consider adding HSTS to protect against protocol downgrade attacks and cookie hijacking. \
             Recommended value: 'max-age=31536000; includeSubDomains'".to_string(),
        ));
    }
}

/// Check if route header modifications contain HSTS
fn route_has_hsts_header(headers: &crate::HeaderModifications) -> bool {
    // Check 'set' headers (case-insensitive)
    let has_in_set = headers
        .set
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    // Check 'add' headers (case-insensitive)
    let has_in_add = headers
        .add
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    has_in_set || has_in_add
}

/// Check if a headers filter sets HSTS
fn headers_filter_has_hsts(filter: &HeadersFilter) -> bool {
    // Check 'set' headers (case-insensitive)
    let has_in_set = filter
        .set
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    // Check 'add' headers (case-insensitive)
    let has_in_add = filter
        .add
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    has_in_set || has_in_add
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::FilterConfig;
    use crate::{
        ConnectionPoolConfig, HttpVersionConfig, ListenerConfig, MatchCondition, RouteConfig,
        RoutePolicies, ServiceType, TlsConfig, UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;
    use zentinel_common::types::{LoadBalancingAlgorithm, Priority, TlsVersion};

    fn test_route_config() -> RouteConfig {
        RouteConfig {
            id: "test".to_string(),
            priority: Priority::NORMAL,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: None,
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            shadow: None,
            fallback: None,
        }
    }

    fn test_upstream_config() -> UpstreamConfig {
        UpstreamConfig {
            profile: None,
            id: "test".to_string(),
            targets: vec![UpstreamTarget {
                address: "127.0.0.1:8080".to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            }],
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: None,
            circuit_breaker: None,
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
            proxy_protocol: None,
        }
    }

    fn test_listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "test".to_string(),
            address: address.to_string(),
            protocol: crate::ListenerProtocol::Http,
            tls: None,
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            proxy_protocol: None,
        }
    }

    fn test_tls_listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "tls-test".to_string(),
            address: address.to_string(),
            protocol: crate::ListenerProtocol::Http,
            tls: Some(TlsConfig {
                sni_cert_dirs: Vec::new(),
                combined_file: None,
                cert_file: Some(PathBuf::from("/path/to/cert.pem")),
                key_file: Some(PathBuf::from("/path/to/key.pem")),
                additional_certs: vec![],
                ca_file: None,
                min_version: TlsVersion::Tls12,
                max_version: None,
                cipher_suites: vec![],
                client_auth: false,
                ocsp_stapling: true,
                session_resumption: true,
                acme: None,
            }),
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            proxy_protocol: None,
        }
    }

    #[test]
    fn lint_warns_on_proxy_protocol_trusting_every_source() {
        let mut config = Config::default_for_testing();
        let mut listener = test_listener_config("0.0.0.0:8080");
        listener.proxy_protocol = Some(crate::server::ProxyProtocolConfig {
            trusted: vec!["0.0.0.0/0".to_string()],
            header_timeout_ms: 2000,
        });
        config.listeners = vec![listener];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("can spoof its address")));
    }

    /// A TLS listener whose certificates come from a control panel.
    fn panel_tls_listener() -> ListenerConfig {
        let mut listener = test_tls_listener_config("0.0.0.0:443");
        if let Some(tls) = listener.tls.as_mut() {
            tls.sni_cert_dirs = vec![crate::server::SniCertDir {
                path: PathBuf::from("/var/cpanel/ssl/apache_tls"),
                combined_name: "combined".to_string(),
                cert_name: None,
                key_name: None,
            }];
        }
        listener
    }

    fn dcv_route() -> RouteConfig {
        let mut route = test_route_config();
        route.id = "acme-passthrough".to_string();
        route.matches = vec![MatchCondition::PathPrefix(
            "/.well-known/acme-challenge/".to_string(),
        )];
        route
    }

    #[test]
    fn lint_warns_when_panel_certs_have_no_validation_route() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![panel_tls_listener()];
        config.routes = vec![];

        let result = lint_config(&config);

        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.message.contains("certificate renewals fail")),
            "expected a DCV passthrough warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn lint_accepts_panel_certs_with_a_validation_route() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![panel_tls_listener()];
        config.routes = vec![dcv_route()];

        let result = lint_config(&config);

        assert!(!result
            .warnings
            .iter()
            .any(|w| w.message.contains("certificate renewals fail")));
    }

    #[test]
    fn lint_warns_when_validation_requests_are_inspected() {
        let mut config = Config::default_for_testing();
        let mut route = dcv_route();
        route.filters = vec!["waf-agent".to_string()];
        route.waf_enabled = true;
        config.listeners = vec![panel_tls_listener()];
        config.routes = vec![route];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("runs filters")));
        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("WAF enabled")));
    }

    #[test]
    fn lint_leaves_catch_all_routes_alone_without_panel_certs() {
        // A filtered catch-all covers the validation paths, but nothing in
        // this config depends on validation working — stay quiet.
        let mut config = Config::default_for_testing();
        let mut route = test_route_config();
        route.matches = vec![MatchCondition::PathPrefix("/".to_string())];
        route.filters = vec!["waf-agent".to_string()];
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];
        config.routes = vec![route];

        let result = lint_config(&config);

        assert!(!result
            .warnings
            .iter()
            .any(|w| w.message.contains("domain-validation")));
    }

    #[test]
    fn lint_warns_when_panel_traffic_reaches_validation_through_a_filtered_catch_all() {
        let mut config = Config::default_for_testing();
        let mut route = test_route_config();
        route.matches = vec![MatchCondition::PathPrefix("/".to_string())];
        route.filters = vec!["waf-agent".to_string()];
        config.listeners = vec![panel_tls_listener()];
        config.routes = vec![route];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("runs filters")));
    }

    #[test]
    fn lint_warns_on_a_profile_that_contributes_nothing() {
        let mut config = Config::default_for_testing();
        let mut upstream = test_upstream_config();
        upstream.profile = Some(crate::profiles::AppliedProfile {
            name: "apache-shared-hosting".to_string(),
            settings: vec![],
        });
        config.upstreams = HashMap::from([("test".to_string(), upstream)]);

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("decorative")));
    }

    #[test]
    fn lint_accepts_a_profile_that_contributes_settings() {
        let mut config = Config::default_for_testing();
        let mut upstream = test_upstream_config();
        upstream.profile = Some(crate::profiles::AppliedProfile {
            name: "apache-shared-hosting".to_string(),
            settings: vec![crate::profiles::ProfileSetting {
                field: "timeouts.connect".to_string(),
                value: "5s".to_string(),
            }],
        });
        config.upstreams = HashMap::from([("test".to_string(), upstream)]);

        let result = lint_config(&config);

        assert!(!result
            .warnings
            .iter()
            .any(|w| w.message.contains("decorative")));
    }

    #[test]
    fn lint_accepts_scoped_proxy_protocol_trust() {
        let mut config = Config::default_for_testing();
        let mut listener = test_listener_config("0.0.0.0:8080");
        listener.proxy_protocol = Some(crate::server::ProxyProtocolConfig {
            trusted: vec!["10.0.0.0/8".to_string()],
            header_timeout_ms: 2000,
        });
        config.listeners = vec![listener];

        let result = lint_config(&config);

        assert!(!result
            .warnings
            .iter()
            .any(|w| w.message.contains("can spoof its address")));
    }

    #[test]
    fn test_lint_missing_retry_policy() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_config()];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("no retry policy")));
    }

    #[test]
    fn test_lint_missing_health_check() {
        let mut config = Config::default_for_testing();
        config
            .upstreams
            .insert("test".to_string(), test_upstream_config());

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("no health check")));
    }

    #[test]
    fn test_lint_http_on_port_80() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_listener_config("0.0.0.0:80")];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("without TLS")));
    }

    #[test]
    fn test_lint_tls_without_hsts() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        let result = lint_config(&config);

        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.message.contains("HSTS")
                    && w.message.contains("Strict-Transport-Security"))
        );
    }

    #[test]
    fn test_lint_tls_with_hsts_in_route_policies() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        // Add route with HSTS header in response_headers
        let mut route = test_route_config();
        route.policies.response_headers.set.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000; includeSubDomains".to_string(),
        );
        config.routes = vec![route];

        let result = lint_config(&config);

        // Should NOT warn about HSTS since it's configured
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should not warn about HSTS when it's configured in route policies"
        );
    }

    #[test]
    fn test_lint_tls_with_hsts_in_filter() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        // Add headers filter with HSTS
        let mut headers_filter = HeadersFilter::default();
        headers_filter.set.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        config.filters.insert(
            "hsts-filter".to_string(),
            FilterConfig::new("hsts-filter", Filter::Headers(headers_filter)),
        );

        let result = lint_config(&config);

        // Should NOT warn about HSTS since it's configured in filter
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should not warn about HSTS when it's configured in headers filter"
        );
    }

    #[test]
    fn test_lint_hsts_case_insensitive() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        // Add route with lowercase HSTS header
        let mut route = test_route_config();
        route.policies.response_headers.set.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        config.routes = vec![route];

        let result = lint_config(&config);

        // Should NOT warn about HSTS (case-insensitive match)
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should detect HSTS header with case-insensitive matching"
        );
    }

    #[test]
    fn test_lint_no_hsts_warning_without_tls() {
        let mut config = Config::default_for_testing();
        // Only HTTP listener, no TLS
        config.listeners = vec![test_listener_config("0.0.0.0:8080")];

        let result = lint_config(&config);

        // Should NOT warn about HSTS when there's no TLS listener
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should not warn about HSTS when there's no TLS listener"
        );
    }

    // ------------------------------------------------------------------
    // Rule: unreachable route (shadowing)
    // ------------------------------------------------------------------

    fn route_with(id: &str, priority: Priority, matches: Vec<MatchCondition>) -> RouteConfig {
        let mut r = test_route_config();
        r.id = id.to_string();
        r.priority = priority;
        r.matches = matches;
        r.upstream = Some("backend".to_string());
        r
    }

    fn unreachable_warnings(config: &Config) -> Vec<String> {
        lint_config(config)
            .warnings
            .into_iter()
            .filter(|w| w.message.contains("is unreachable"))
            .map(|w| w.message)
            .collect()
    }

    #[test]
    fn unreachable_high_priority_catchall_shadows_specific() {
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "catchall",
                Priority::HIGH,
                vec![MatchCondition::PathPrefix("/".into())],
            ),
            route_with(
                "specific",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api/v1".into())],
            ),
        ];
        let warnings = unreachable_warnings(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("'specific'"));
        assert!(warnings[0].contains("'catchall'"));
    }

    #[test]
    fn unreachable_prefix_shadows_subprefix() {
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "api",
                Priority::HIGH,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
            route_with(
                "apiv1",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api/v1".into())],
            ),
        ];
        assert_eq!(unreachable_warnings(&config).len(), 1);
    }

    #[test]
    fn no_unreachable_when_prefix_not_at_boundary() {
        // "/api" must NOT generalize "/apix".
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "api",
                Priority::HIGH,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
            route_with(
                "apix",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/apix".into())],
            ),
        ];
        assert!(unreachable_warnings(&config).is_empty());
    }

    #[test]
    fn no_unreachable_at_equal_priority() {
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "a",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/".into())],
            ),
            route_with(
                "b",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
        ];
        assert!(unreachable_warnings(&config).is_empty());
    }

    #[test]
    fn no_unreachable_when_higher_restricts_method() {
        // Higher catch-all only matches GET; lower matches all methods.
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "get-only",
                Priority::HIGH,
                vec![
                    MatchCondition::PathPrefix("/".into()),
                    MatchCondition::Method(vec!["GET".into()]),
                ],
            ),
            route_with(
                "any",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
        ];
        assert!(unreachable_warnings(&config).is_empty());
    }

    #[test]
    fn no_unreachable_when_higher_restricts_host() {
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "host-scoped",
                Priority::HIGH,
                vec![
                    MatchCondition::PathPrefix("/".into()),
                    MatchCondition::Host("a.example.com".into()),
                ],
            ),
            route_with(
                "any-host",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
        ];
        assert!(unreachable_warnings(&config).is_empty());
    }

    #[test]
    fn no_unreachable_when_higher_uses_path_regex() {
        // A regex catch-all is treated as opaque (bail), so no false positive.
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "regex",
                Priority::HIGH,
                vec![MatchCondition::PathRegex(".*".into())],
            ),
            route_with(
                "specific",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
        ];
        assert!(unreachable_warnings(&config).is_empty());
    }

    #[test]
    fn no_unreachable_when_higher_needs_header_lower_does_not() {
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "needs-header",
                Priority::HIGH,
                vec![
                    MatchCondition::PathPrefix("/".into()),
                    MatchCondition::Header {
                        name: "x-key".into(),
                        value: None,
                    },
                ],
            ),
            route_with(
                "no-header",
                Priority::NORMAL,
                vec![MatchCondition::PathPrefix("/api".into())],
            ),
        ];
        assert!(unreachable_warnings(&config).is_empty());
    }

    #[test]
    fn unreachable_host_wildcard_covers_exact() {
        // Higher "*.example.com" catch-all shadows lower "api.example.com".
        let mut config = Config::default_for_testing();
        config.routes = vec![
            route_with(
                "wild",
                Priority::HIGH,
                vec![
                    MatchCondition::PathPrefix("/".into()),
                    MatchCondition::Host("*.example.com".into()),
                ],
            ),
            route_with(
                "exact",
                Priority::NORMAL,
                vec![
                    MatchCondition::PathPrefix("/api".into()),
                    MatchCondition::Host("api.example.com".into()),
                ],
            ),
        ];
        assert_eq!(unreachable_warnings(&config).len(), 1);
    }

    // ------------------------------------------------------------------
    // Rule: agent filter without explicit failure-mode
    // ------------------------------------------------------------------

    fn agent_filter(id: &str, failure_mode: Option<FailureMode>) -> FilterConfig {
        FilterConfig {
            id: id.to_string(),
            filter: Filter::Agent(crate::filters::AgentFilter {
                agent: "myagent".to_string(),
                phase: None,
                timeout_ms: None,
                failure_mode,
                inspect_body: false,
                max_body_bytes: None,
            }),
        }
    }

    #[test]
    fn agent_filter_without_failure_mode_warns() {
        let mut config = Config::default_for_testing();
        let mut route = route_with(
            "r",
            Priority::NORMAL,
            vec![MatchCondition::PathPrefix("/".into())],
        );
        route.filters = vec!["waf".to_string()];
        config.routes = vec![route];
        config
            .filters
            .insert("waf".to_string(), agent_filter("waf", None));

        let result = lint_config(&config);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("no explicit failure-mode")));
    }

    #[test]
    fn agent_filter_with_failure_mode_no_warn() {
        let mut config = Config::default_for_testing();
        let mut route = route_with(
            "r",
            Priority::NORMAL,
            vec![MatchCondition::PathPrefix("/".into())],
        );
        route.filters = vec!["waf".to_string()];
        config.routes = vec![route];
        config.filters.insert(
            "waf".to_string(),
            agent_filter("waf", Some(FailureMode::Closed)),
        );

        let result = lint_config(&config);
        assert!(!result
            .warnings
            .iter()
            .any(|w| w.message.contains("failure-mode")));
    }

    // ------------------------------------------------------------------
    // Rule: shadow traffic to a production upstream
    // ------------------------------------------------------------------

    fn shadow_to(upstream: &str) -> crate::routes::ShadowConfig {
        crate::routes::ShadowConfig {
            upstream: upstream.to_string(),
            percentage: 10.0,
            sample_header: None,
            timeout_ms: 1000,
            buffer_body: false,
            max_body_bytes: 0,
        }
    }

    #[test]
    fn shadow_to_production_upstream_warns() {
        let mut config = Config::default_for_testing();
        let live = route_with(
            "live",
            Priority::NORMAL,
            vec![MatchCondition::PathPrefix("/live".into())],
        );
        let mut canary = route_with(
            "canary",
            Priority::NORMAL,
            vec![MatchCondition::PathPrefix("/canary".into())],
        );
        canary.shadow = Some(shadow_to("backend")); // "backend" is live's primary
        config.routes = vec![live, canary];

        let result = lint_config(&config);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("mirrors shadow traffic")));
    }

    #[test]
    fn shadow_to_dedicated_upstream_no_warn() {
        let mut config = Config::default_for_testing();
        let mut route = route_with(
            "r",
            Priority::NORMAL,
            vec![MatchCondition::PathPrefix("/".into())],
        );
        route.shadow = Some(shadow_to("shadow-pool")); // not any route's primary
        config.routes = vec![route];

        let result = lint_config(&config);
        assert!(!result
            .warnings
            .iter()
            .any(|w| w.message.contains("mirrors shadow traffic")));
    }
}
