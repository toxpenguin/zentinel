//! Route matching and selection module for Zentinel proxy
//!
//! This module implements the routing logic for matching incoming requests
//! to configured routes based on various criteria (path, host, headers, etc.)
//! with support for priority-based evaluation.

use dashmap::DashMap;
use prometheus::{register_int_counter, IntCounter};
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use tracing::{debug, info, trace, warn};

/// Entries evicted from the route-match cache to enforce `route-cache-size`.
static ROUTE_CACHE_EVICTIONS: LazyLock<Option<IntCounter>> = LazyLock::new(|| {
    register_int_counter!(
        "zentinel_route_cache_evictions_total",
        "Route-match cache entries evicted to enforce route-cache-size"
    )
    .ok()
});

use zentinel_common::types::Priority;
use zentinel_common::RouteId;
use zentinel_config::{MatchCondition, RouteConfig, RoutePolicies};

/// Route matcher for efficient route selection
pub struct RouteMatcher {
    /// Routes sorted by priority (highest first)
    routes: Vec<CompiledRoute>,
    /// Default route ID if no match found
    default_route: Option<RouteId>,
    /// Cache for frequently matched routes (lock-free concurrent access)
    cache: Arc<RouteCache>,
    /// Whether any route requires header matching (optimization flag)
    needs_headers: bool,
    /// Whether any route requires query param matching (optimization flag)
    needs_query_params: bool,
}

/// Compiled route with pre-processed match conditions
struct CompiledRoute {
    /// Route configuration
    config: Arc<RouteConfig>,
    /// Route ID for quick lookup
    id: RouteId,
    /// Priority for ordering
    priority: Priority,
    /// Compiled match conditions
    matchers: Vec<CompiledMatcher>,
}

/// Compiled match condition for efficient evaluation
enum CompiledMatcher {
    /// Exact path match
    Path(String),
    /// Path prefix match
    PathPrefix(String),
    /// Regex path match
    PathRegex(Regex),
    /// Host match (exact or wildcard)
    Host(HostMatcher),
    /// Header presence or value match
    Header { name: String, value: Option<String> },
    /// HTTP method match
    Method(Vec<String>),
    /// Query parameter match
    QueryParam { name: String, value: Option<String> },
}

/// Host matching logic
enum HostMatcher {
    /// Exact host match
    Exact(String),
    /// Wildcard match (*.example.com)
    Wildcard { suffix: String },
    /// Regex match
    Regex(Regex),
}

/// Route cache for performance (lock-free concurrent access)
struct RouteCache {
    /// Cache entries (cache key -> route ID) - lock-free concurrent map
    entries: DashMap<String, RouteId>,
    /// Maximum cache size
    max_size: usize,
    /// Current entry count (approximate, for eviction decisions)
    entry_count: AtomicUsize,
    /// Cache hits counter
    hits: AtomicU64,
    /// Cache misses counter
    misses: AtomicU64,
}

impl RouteMatcher {
    /// Create a new route matcher from configuration with the default
    /// route-cache size (1000 entries).
    pub fn new(
        routes: Vec<RouteConfig>,
        default_route: Option<String>,
    ) -> Result<Self, RouteError> {
        Self::with_cache_size(routes, default_route, 1000)
    }

    /// Create a new route matcher with an explicit route-cache size
    /// (`system { route-cache-size N }`).
    pub fn with_cache_size(
        routes: Vec<RouteConfig>,
        default_route: Option<String>,
        cache_size: usize,
    ) -> Result<Self, RouteError> {
        info!(
            route_count = routes.len(),
            default_route = ?default_route,
            "Initializing route matcher"
        );

        let mut compiled_routes = Vec::new();

        for route in routes {
            trace!(
                route_id = %route.id,
                priority = ?route.priority,
                match_count = route.matches.len(),
                "Compiling route"
            );
            let compiled = CompiledRoute::compile(route)?;
            compiled_routes.push(compiled);
        }

        // Sort by priority (highest first), then by specificity
        compiled_routes.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.specificity().cmp(&a.specificity()))
        });

        // Log final route order
        for (index, route) in compiled_routes.iter().enumerate() {
            debug!(
                route_id = %route.id,
                order = index,
                priority = ?route.priority,
                specificity = route.specificity(),
                "Route compiled and ordered"
            );
        }

        // Determine if any routes need headers or query params (optimization)
        let needs_headers = compiled_routes.iter().any(|r| {
            r.matchers
                .iter()
                .any(|m| matches!(m, CompiledMatcher::Header { .. }))
        });
        let needs_query_params = compiled_routes.iter().any(|r| {
            r.matchers
                .iter()
                .any(|m| matches!(m, CompiledMatcher::QueryParam { .. }))
        });

        info!(
            compiled_routes = compiled_routes.len(),
            needs_headers, needs_query_params, "Route matcher initialized"
        );

        Ok(Self {
            routes: compiled_routes,
            default_route: default_route.map(RouteId::new),
            cache: Arc::new(RouteCache::new(cache_size)),
            needs_headers,
            needs_query_params,
        })
    }

    /// Check if any route requires header matching
    #[inline]
    pub fn needs_headers(&self) -> bool {
        self.needs_headers
    }

    /// Check if any route requires query param matching
    #[inline]
    pub fn needs_query_params(&self) -> bool {
        self.needs_query_params
    }

    /// Match a request to a route
    pub fn match_request(&self, req: &RequestInfo<'_>) -> Option<RouteMatch> {
        trace!(
            method = %req.method,
            path = %req.path,
            host = %req.host,
            "Starting route matching"
        );

        // Check cache first (lock-free read, zero-allocation on hit)
        let cached = req.with_cache_key(|key| {
            self.cache.get(key).map(|r| {
                let route_id = r.clone();
                drop(r);
                route_id
            })
        });
        if let Some(route_id) = cached {
            trace!(
                route_id = %route_id,
                "Route cache hit"
            );
            if let Some(route) = self.find_route_by_id(&route_id) {
                debug!(
                    route_id = %route_id,
                    method = %req.method,
                    path = %req.path,
                    source = "cache",
                    "Route matched from cache"
                );
                return Some(RouteMatch {
                    route_id,
                    config: route.config.clone(),
                });
            }
        }

        // Record cache miss
        self.cache.record_miss();

        trace!(
            route_count = self.routes.len(),
            "Cache miss, evaluating routes"
        );

        // Evaluate routes in priority order
        for (index, route) in self.routes.iter().enumerate() {
            trace!(
                route_id = %route.id,
                route_index = index,
                priority = ?route.priority,
                matcher_count = route.matchers.len(),
                "Evaluating route"
            );

            if route.matches(req) {
                debug!(
                    route_id = %route.id,
                    method = %req.method,
                    path = %req.path,
                    host = %req.host,
                    priority = ?route.priority,
                    route_index = index,
                    "Route matched"
                );

                // Update cache — allocate key only on miss (rare after warmup)
                req.with_cache_key(|key| {
                    self.cache.insert(key.to_string(), route.id.clone());
                });

                trace!(
                    route_id = %route.id,
                    "Route added to cache"
                );

                return Some(RouteMatch {
                    route_id: route.id.clone(),
                    config: route.config.clone(),
                });
            }
        }

        // Use default route if configured
        if let Some(ref default_id) = self.default_route {
            debug!(
                route_id = %default_id,
                method = %req.method,
                path = %req.path,
                "Using default route (no explicit match)"
            );
            if let Some(route) = self.find_route_by_id(default_id) {
                return Some(RouteMatch {
                    route_id: default_id.clone(),
                    config: route.config.clone(),
                });
            }
        }

        debug!(
            method = %req.method,
            path = %req.path,
            host = %req.host,
            routes_evaluated = self.routes.len(),
            "No route matched"
        );
        None
    }

    /// Explain how a request routes, evaluating **every** route.
    ///
    /// Unlike [`match_request`](Self::match_request), this never short-circuits
    /// on the first match and never consults the route cache. It returns the
    /// full ordered evaluation so callers can show the winning route *and*
    /// every route it beat — the basis for the `zentinel explain` subcommand.
    ///
    /// Routes are evaluated in the same order `match_request` uses (priority
    /// descending, then specificity descending), so the reported winner is
    /// identical to what a live request would select.
    #[must_use]
    pub fn explain_request(&self, req: &RequestInfo<'_>) -> ExplainTrace {
        let mut evaluations = Vec::with_capacity(self.routes.len());
        let mut winner = None;

        for (index, route) in self.routes.iter().enumerate() {
            let reject_reason = route.explain_match(req).err();
            let matched = reject_reason.is_none();
            if matched && winner.is_none() {
                winner = Some(index);
            }
            evaluations.push(RouteEvaluation {
                id: route.id.clone(),
                priority: route.priority,
                specificity: route.specificity(),
                matched,
                reject_reason,
            });
        }

        // No explicit match: fall back to the configured default route, which
        // already appears (unmatched) in `evaluations`.
        let mut used_default = false;
        if winner.is_none() {
            if let Some(ref default_id) = self.default_route {
                if let Some(idx) = evaluations.iter().position(|e| e.id == *default_id) {
                    winner = Some(idx);
                    used_default = true;
                }
            }
        }

        ExplainTrace {
            evaluations,
            winner,
            used_default,
        }
    }

    /// Find a route by ID
    fn find_route_by_id(&self, id: &RouteId) -> Option<&CompiledRoute> {
        self.routes.iter().find(|r| r.id == *id)
    }

    /// Clear the route cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            entries: self.cache.len(),
            max_size: self.cache.max_size,
            hit_rate: self.cache.hit_rate(),
        }
    }
}

impl CompiledRoute {
    /// Compile a route configuration into an optimized matcher
    fn compile(config: RouteConfig) -> Result<Self, RouteError> {
        let mut matchers = Vec::new();

        for condition in &config.matches {
            let compiled = match condition {
                MatchCondition::Path(path) => CompiledMatcher::Path(path.clone()),
                MatchCondition::PathPrefix(prefix) => CompiledMatcher::PathPrefix(prefix.clone()),
                MatchCondition::PathRegex(pattern) => {
                    let regex = Regex::new(pattern).map_err(|e| RouteError::InvalidRegex {
                        pattern: pattern.clone(),
                        error: e.to_string(),
                    })?;
                    CompiledMatcher::PathRegex(regex)
                }
                MatchCondition::Host(host) => CompiledMatcher::Host(HostMatcher::parse(host)),
                MatchCondition::Header { name, value } => CompiledMatcher::Header {
                    name: name.to_lowercase(),
                    value: value.clone(),
                },
                MatchCondition::Method(methods) => {
                    CompiledMatcher::Method(methods.iter().map(|m| m.to_uppercase()).collect())
                }
                MatchCondition::QueryParam { name, value } => CompiledMatcher::QueryParam {
                    name: name.clone(),
                    value: value.clone(),
                },
            };
            matchers.push(compiled);
        }

        Ok(Self {
            id: RouteId::new(&config.id),
            priority: config.priority,
            config: Arc::new(config),
            matchers,
        })
    }

    /// Check if this route matches the request.
    ///
    /// Host matchers use OR logic (match any host), all other matchers use AND.
    /// This matches Gateway API semantics where multiple hostnames on an
    /// HTTPRoute are alternatives, not conjunctions.
    fn matches(&self, req: &RequestInfo<'_>) -> bool {
        // Partition matchers into host matchers and non-host matchers
        let mut has_host_matchers = false;
        let mut any_host_matched = false;

        for matcher in &self.matchers {
            match matcher {
                CompiledMatcher::Host(_) => {
                    has_host_matchers = true;
                    if matcher.matches(req) {
                        any_host_matched = true;
                    }
                }
                _ => {
                    if !matcher.matches(req) {
                        trace!(
                            route_id = %self.id,
                            matcher_type = ?matcher,
                            path = %req.path,
                            "Matcher did not match"
                        );
                        return false;
                    }
                }
            }
        }

        // If there are host matchers, at least one must match (OR logic)
        if has_host_matchers && !any_host_matched {
            trace!(
                route_id = %self.id,
                host = %req.host,
                "No host matcher matched"
            );
            return false;
        }

        true
    }

    /// Calculate route specificity for tie-breaking.
    ///
    /// Per Gateway API precedence rules:
    /// 1. Path specificity is primary (exact > longest prefix > regex)
    /// 2. Host specificity is secondary (exact > wildcard)
    /// 3. Header/method/query conditions add specificity
    ///
    /// Host matchers use OR logic, so multiple hosts don't increase
    /// specificity — we use the max host score, not the sum.
    fn specificity(&self) -> u32 {
        let mut path_score = 0u32;
        let mut host_score = 0u32;
        let mut condition_score = 0u32;

        for matcher in &self.matchers {
            match matcher {
                CompiledMatcher::Path(_) => path_score = path_score.max(10000),
                CompiledMatcher::PathRegex(_) => path_score = path_score.max(5000),
                CompiledMatcher::PathPrefix(p) => {
                    path_score = path_score.max(1000 + p.len() as u32)
                }
                CompiledMatcher::Host(host) => {
                    let s = match host {
                        HostMatcher::Exact(_) => 70,
                        HostMatcher::Regex(_) => 60,
                        HostMatcher::Wildcard { .. } => 50,
                    };
                    host_score = host_score.max(s);
                }
                CompiledMatcher::Header { value, .. } => {
                    condition_score += if value.is_some() { 30 } else { 20 };
                }
                CompiledMatcher::Method(_) => condition_score += 10,
                CompiledMatcher::QueryParam { value, .. } => {
                    condition_score += if value.is_some() { 25 } else { 15 };
                }
            }
        }

        path_score + host_score + condition_score
    }

    /// Like [`matches`](Self::matches) but returns *why* the route was rejected.
    ///
    /// `Ok(())` means the route matches. `Err(reason)` describes the first
    /// failing condition (or the unmatched host set). This mirrors `matches`
    /// exactly — same host OR / non-host AND semantics — so the winner reported
    /// by an explain trace is identical to a live match.
    fn explain_match(&self, req: &RequestInfo<'_>) -> Result<(), String> {
        let mut has_host_matchers = false;
        let mut any_host_matched = false;

        for matcher in &self.matchers {
            match matcher {
                CompiledMatcher::Host(_) => {
                    has_host_matchers = true;
                    if matcher.matches(req) {
                        any_host_matched = true;
                    }
                }
                _ => {
                    if !matcher.matches(req) {
                        return Err(format!("{} did not match", matcher.describe()));
                    }
                }
            }
        }

        if has_host_matchers && !any_host_matched {
            return Err(format!("no host condition matched host '{}'", req.host));
        }

        Ok(())
    }
}

impl CompiledMatcher {
    /// Check if this matcher matches the request
    fn matches(&self, req: &RequestInfo<'_>) -> bool {
        match self {
            Self::Path(path) => req.path == *path,
            Self::PathPrefix(prefix) => {
                if !req.path.starts_with(prefix) {
                    return false;
                }
                // Enforce segment boundary per Gateway API spec:
                // PathPrefix "/v2" must NOT match "/v2example", only "/v2", "/v2/", "/v2/anything"
                prefix == "/"
                    || req.path.len() == prefix.len()
                    || prefix.ends_with('/')
                    || req.path.as_bytes()[prefix.len()] == b'/'
                    || req.path.as_bytes()[prefix.len()] == b'?'
            }
            Self::PathRegex(regex) => regex.is_match(req.path),
            Self::Host(host_matcher) => host_matcher.matches(req.host),
            Self::Header { name, value } => {
                if let Some(header_value) = req.headers().get(name) {
                    value.as_ref().is_none_or(|v| header_value == v)
                } else {
                    false
                }
            }
            Self::Method(methods) => methods.iter().any(|m| m == req.method),
            Self::QueryParam { name, value } => {
                if let Some(param_value) = req.query_params().get(name) {
                    value.as_ref().is_none_or(|v| param_value == v)
                } else {
                    false
                }
            }
        }
    }

    /// Human-readable description of this condition, for explain output.
    fn describe(&self) -> String {
        match self {
            Self::Path(path) => format!("path == '{path}'"),
            Self::PathPrefix(prefix) => format!("path-prefix '{prefix}'"),
            Self::PathRegex(regex) => format!("path-regex /{}/", regex.as_str()),
            Self::Host(_) => "host".to_string(),
            Self::Header { name, value } => match value {
                Some(v) => format!("header '{name}: {v}'"),
                None => format!("header '{name}' present"),
            },
            Self::Method(methods) => format!("method in [{}]", methods.join(", ")),
            Self::QueryParam { name, value } => match value {
                Some(v) => format!("query '{name}={v}'"),
                None => format!("query '{name}' present"),
            },
        }
    }
}

impl HostMatcher {
    /// Parse a host pattern into a matcher
    fn parse(pattern: &str) -> Self {
        if pattern.starts_with("*.") {
            // Wildcard pattern
            Self::Wildcard {
                suffix: pattern[2..].to_string(),
            }
        } else if pattern.contains('*') || pattern.contains('[') {
            // Treat as regex if it contains other special characters
            if let Ok(regex) = Regex::new(pattern) {
                Self::Regex(regex)
            } else {
                // Fall back to exact match if regex compilation fails
                warn!("Invalid host regex pattern: {}, using exact match", pattern);
                Self::Exact(pattern.to_string())
            }
        } else {
            // Exact match
            Self::Exact(pattern.to_string())
        }
    }

    /// Check if this matcher matches the host.
    ///
    /// Strips any port suffix from the host before matching, per Gateway API
    /// spec: `Host: example.com:8080` must match hostname `example.com`.
    fn matches(&self, host: &str) -> bool {
        // Strip port from host (e.g. "example.com:8080" → "example.com")
        let host = host.split(':').next().unwrap_or(host);
        match self {
            Self::Exact(pattern) => host == pattern,
            Self::Wildcard { suffix } => {
                host.ends_with(suffix)
                    && host.len() > suffix.len()
                    && host[..host.len() - suffix.len()].ends_with('.')
            }
            Self::Regex(regex) => regex.is_match(host),
        }
    }
}

impl RouteCache {
    /// Create a new route cache
    fn new(max_size: usize) -> Self {
        Self {
            entries: DashMap::with_capacity(max_size),
            max_size,
            entry_count: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get a route from cache (lock-free)
    fn get(&self, key: &str) -> Option<dashmap::mapref::one::Ref<'_, String, RouteId>> {
        let result = self.entries.get(key);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Record a cache miss
    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the hit rate (0.0 to 1.0)
    fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Insert a route into cache (lock-free)
    fn insert(&self, key: String, route_id: RouteId) {
        // Check if we need to evict (approximate check to avoid overhead)
        let current_count = self.entry_count.load(Ordering::Relaxed);
        if current_count >= self.max_size {
            // Evict ~10% of entries randomly for simplicity
            // This is faster than true LRU and good enough for a cache
            self.evict_random();
        }

        if self.entries.insert(key, route_id).is_none() {
            // Only increment if this was a new entry
            self.entry_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Evict random entries when cache is full
    fn evict_random(&self) {
        let to_evict = (self.max_size / 10).max(1); // Evict ~10%
        let mut evicted = 0;

        // Iterate and remove some entries
        self.entries.retain(|_, _| {
            if evicted < to_evict {
                evicted += 1;
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });

        // Update count (approximate)
        self.entry_count
            .store(self.entries.len(), Ordering::Relaxed);

        debug!(
            evicted = evicted,
            remaining = self.entries.len(),
            max_size = self.max_size,
            "Route cache at capacity; evicted entries"
        );
        if let Some(counter) = ROUTE_CACHE_EVICTIONS.as_ref() {
            counter.inc_by(evicted as u64);
        }
    }

    /// Get current cache size
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Clear all cache entries
    fn clear(&self) {
        self.entries.clear();
        self.entry_count.store(0, Ordering::Relaxed);
    }
}

/// Request information for route matching (zero-copy where possible)
#[derive(Debug)]
pub struct RequestInfo<'a> {
    /// HTTP method (borrowed from request header)
    pub method: &'a str,
    /// Request path (borrowed from request header)
    pub path: &'a str,
    /// Host header value (borrowed from request header)
    pub host: &'a str,
    /// Headers for matching (lazy-initialized, only if needed)
    headers: Option<HashMap<String, String>>,
    /// Query parameters (lazy-initialized, only if needed)
    query_params: Option<HashMap<String, String>>,
}

impl<'a> RequestInfo<'a> {
    /// Create a new RequestInfo with borrowed references (zero-copy for common case)
    #[inline]
    pub fn new(method: &'a str, path: &'a str, host: &'a str) -> Self {
        Self {
            method,
            path,
            host,
            headers: None,
            query_params: None,
        }
    }

    /// Set headers for header-based matching (only call if RouteMatcher.needs_headers())
    #[inline]
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Set query params for query-based matching (only call if RouteMatcher.needs_query_params())
    #[inline]
    pub fn with_query_params(mut self, params: HashMap<String, String>) -> Self {
        self.query_params = Some(params);
        self
    }

    /// Get headers (returns empty map if not set)
    #[inline]
    pub fn headers(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        self.headers
            .as_ref()
            .unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
    }

    /// Get query params (returns empty map if not set)
    #[inline]
    pub fn query_params(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        self.query_params
            .as_ref()
            .unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
    }

    /// Generate a cache key for this request using a thread-local buffer
    /// to avoid per-request heap allocation.
    fn with_cache_key<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        use std::cell::RefCell;
        use std::fmt::Write;

        thread_local! {
            static BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
        }

        BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let _ = write!(buf, "{}:{}:{}", self.method, self.host, self.path);
            // Include headers in cache key when header-based routing is active,
            // otherwise different header combinations can poison the cache.
            if let Some(ref headers) = self.headers {
                let mut pairs: Vec<_> = headers.iter().collect();
                pairs.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in pairs {
                    let _ = write!(buf, "\n{k}={v}");
                }
            }
            f(&buf)
        })
    }

    /// Parse query parameters from path (only call when needed)
    pub fn parse_query_params(path: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(query_start) = path.find('?') {
            let query = &path[query_start + 1..];
            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let key = &pair[..eq_pos];
                    let value = &pair[eq_pos + 1..];
                    params.insert(
                        urlencoding::decode(key)
                            .unwrap_or_else(|_| key.into())
                            .into_owned(),
                        urlencoding::decode(value)
                            .unwrap_or_else(|_| value.into())
                            .into_owned(),
                    );
                } else {
                    params.insert(
                        urlencoding::decode(pair)
                            .unwrap_or_else(|_| pair.into())
                            .into_owned(),
                        String::new(),
                    );
                }
            }
        }
        params
    }

    /// Build headers map from request header iterator (only call when needed)
    pub fn build_headers<'b, I>(iter: I) -> HashMap<String, String>
    where
        I: Iterator<Item = (&'b http::header::HeaderName, &'b http::header::HeaderValue)>,
    {
        let mut headers = HashMap::new();
        for (name, value) in iter {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), value_str.to_string());
            }
        }
        headers
    }
}

/// Route match result
#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub route_id: RouteId,
    pub config: Arc<RouteConfig>,
}

impl RouteMatch {
    /// Access route policies (convenience accessor to avoid repeated .config.policies)
    #[inline]
    pub fn policies(&self) -> &RoutePolicies {
        &self.config.policies
    }
}

/// Evaluation of a single route within an [`ExplainTrace`].
#[derive(Debug, Clone)]
pub struct RouteEvaluation {
    /// Route identifier.
    pub id: RouteId,
    /// Route priority (higher routes are evaluated first).
    pub priority: Priority,
    /// Tie-break specificity score (higher wins at equal priority).
    pub specificity: u32,
    /// Whether this route matched the request.
    pub matched: bool,
    /// If the route did not match, why — the first failing condition, or the
    /// unmatched host set. `None` when the route matched.
    pub reject_reason: Option<String>,
}

/// Full trace of how a request routes, produced by
/// [`RouteMatcher::explain_request`].
///
/// `evaluations` are in evaluation order (priority then specificity, both
/// descending). `winner` indexes the selected route within `evaluations`, if
/// any.
#[derive(Debug, Clone)]
pub struct ExplainTrace {
    /// Every configured route, in evaluation order.
    pub evaluations: Vec<RouteEvaluation>,
    /// Index into `evaluations` of the winning route, if one was selected.
    pub winner: Option<usize>,
    /// Whether the winner is the configured default route (no explicit match).
    pub used_default: bool,
}

impl ExplainTrace {
    /// The winning route evaluation, if a route matched (or a default applied).
    #[must_use]
    pub fn winner(&self) -> Option<&RouteEvaluation> {
        self.winner.map(|i| &self.evaluations[i])
    }

    /// Routes that also matched but lost to the winner on priority/specificity —
    /// the "what it beat" set for explain output.
    ///
    /// Empty when nothing matched, when the winner is the only match, or when a
    /// default route was applied (no route actually matched).
    #[must_use]
    pub fn beaten(&self) -> Vec<&RouteEvaluation> {
        let Some(win) = self.winner else {
            return Vec::new();
        };
        self.evaluations
            .iter()
            .enumerate()
            .filter(|(i, e)| *i != win && e.matched)
            .map(|(_, e)| e)
            .collect()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub max_size: usize,
    pub hit_rate: f64,
}

/// Route matching errors
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("Invalid regex pattern '{pattern}': {error}")]
    InvalidRegex { pattern: String, error: String },

    #[error("Invalid route configuration: {0}")]
    InvalidConfig(String),

    #[error("Duplicate route ID: {0}")]
    DuplicateRouteId(String),
}

impl std::fmt::Debug for CompiledMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(p) => write!(f, "Path({})", p),
            Self::PathPrefix(p) => write!(f, "PathPrefix({})", p),
            Self::PathRegex(_) => write!(f, "PathRegex(...)"),
            Self::Host(_) => write!(f, "Host(...)"),
            Self::Header { name, .. } => write!(f, "Header({})", name),
            Self::Method(m) => write!(f, "Method({:?})", m),
            Self::QueryParam { name, .. } => write!(f, "QueryParam({})", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_common::types::Priority;
    use zentinel_config::{MatchCondition, RouteConfig};

    #[test]
    fn route_cache_never_exceeds_max_size() {
        let cache = RouteCache::new(10);
        for i in 0..100 {
            cache.insert(format!("key-{i}"), RouteId::new(format!("route-{i}")));
            assert!(
                cache.len() <= 10,
                "route cache grew past max_size: {}",
                cache.len()
            );
        }
    }

    fn create_test_route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::NORMAL,
            matches,
            upstream: Some("test_upstream".to_string()),
            service_type: zentinel_config::ServiceType::Web,
            policies: Default::default(),
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

    #[test]
    fn test_path_matching() {
        let routes = vec![
            create_test_route(
                "exact",
                vec![MatchCondition::Path("/api/v1/users".to_string())],
            ),
            create_test_route(
                "prefix",
                vec![MatchCondition::PathPrefix("/api/".to_string())],
            ),
        ];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        let req = RequestInfo {
            method: "GET",
            path: "/api/v1/users",
            host: "example.com",
            headers: None,
            query_params: None,
        };

        let result = matcher.match_request(&req).unwrap();
        assert_eq!(result.route_id.as_str(), "exact");
    }

    #[test]
    fn test_host_wildcard_matching() {
        let routes = vec![create_test_route(
            "wildcard",
            vec![MatchCondition::Host("*.example.com".to_string())],
        )];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        let req = RequestInfo {
            method: "GET",
            path: "/",
            host: "api.example.com",
            headers: None,
            query_params: None,
        };

        let result = matcher.match_request(&req).unwrap();
        assert_eq!(result.route_id.as_str(), "wildcard");
    }

    #[test]
    fn test_priority_ordering() {
        let mut route1 =
            create_test_route("low", vec![MatchCondition::PathPrefix("/".to_string())]);
        route1.priority = Priority::LOW;

        let mut route2 =
            create_test_route("high", vec![MatchCondition::PathPrefix("/".to_string())]);
        route2.priority = Priority::HIGH;

        let routes = vec![route1, route2];
        let matcher = RouteMatcher::new(routes, None).unwrap();

        let req = RequestInfo {
            method: "GET",
            path: "/test",
            host: "example.com",
            headers: None,
            query_params: None,
        };

        let result = matcher.match_request(&req).unwrap();
        assert_eq!(result.route_id.as_str(), "high");
    }

    #[test]
    fn explain_records_winner_and_beaten_routes() {
        // Two routes both match /api/*; higher priority wins, lower is "beaten".
        let mut low =
            create_test_route("low", vec![MatchCondition::PathPrefix("/api".to_string())]);
        low.priority = Priority::LOW;
        let mut high =
            create_test_route("high", vec![MatchCondition::PathPrefix("/api".to_string())]);
        high.priority = Priority::HIGH;

        let matcher = RouteMatcher::new(vec![low, high], None).unwrap();
        let req = RequestInfo::new("GET", "/api/users", "example.com");

        let trace = matcher.explain_request(&req);
        assert_eq!(trace.winner().unwrap().id.as_str(), "high");
        let beaten: Vec<_> = trace.beaten().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(beaten, vec!["low"]);
    }

    #[test]
    fn explain_reports_reject_reason_for_nonmatch() {
        let route = create_test_route("api", vec![MatchCondition::PathPrefix("/api".to_string())]);
        let matcher = RouteMatcher::new(vec![route], None).unwrap();
        let req = RequestInfo::new("GET", "/other", "example.com");

        let trace = matcher.explain_request(&req);
        assert!(trace.winner().is_none());
        let eval = &trace.evaluations[0];
        assert!(!eval.matched);
        assert!(eval
            .reject_reason
            .as_deref()
            .unwrap()
            .contains("path-prefix"));
    }

    #[test]
    fn explain_winner_matches_live_match_request() {
        // Parity guarantee: explain's winner == match_request's result.
        let routes = vec![
            create_test_route(
                "exact",
                vec![MatchCondition::Path("/api/v1/users".to_string())],
            ),
            create_test_route(
                "prefix",
                vec![MatchCondition::PathPrefix("/api".to_string())],
            ),
        ];
        let matcher = RouteMatcher::new(routes, None).unwrap();
        let req = RequestInfo::new("GET", "/api/v1/users", "example.com");

        let live = matcher.match_request(&req).unwrap();
        let trace = matcher.explain_request(&req);
        assert_eq!(trace.winner().unwrap().id, live.route_id);
        assert_eq!(trace.winner().unwrap().id.as_str(), "exact");
    }

    #[test]
    fn explain_never_consults_cache() {
        // Warm the cache via match_request, then confirm explain still evaluates
        // every route and reports the same winner.
        let routes = vec![
            create_test_route("a", vec![MatchCondition::PathPrefix("/a".to_string())]),
            create_test_route("b", vec![MatchCondition::PathPrefix("/b".to_string())]),
        ];
        let matcher = RouteMatcher::new(routes, None).unwrap();
        let req = RequestInfo::new("GET", "/a/x", "example.com");

        let _ = matcher.match_request(&req); // warm cache
        let trace = matcher.explain_request(&req);
        assert_eq!(trace.evaluations.len(), 2);
        assert_eq!(trace.winner().unwrap().id.as_str(), "a");
    }

    #[test]
    fn explain_uses_default_route_when_no_match() {
        let route = create_test_route(
            "fallback",
            vec![MatchCondition::Host("only.example.com".to_string())],
        );
        let matcher = RouteMatcher::new(vec![route], Some("fallback".to_string())).unwrap();
        let req = RequestInfo::new("GET", "/", "other.example.com");

        let trace = matcher.explain_request(&req);
        assert!(trace.used_default);
        assert_eq!(trace.winner().unwrap().id.as_str(), "fallback");
        // The default applied because nothing actually matched.
        assert!(!trace.winner().unwrap().matched);
        assert!(trace.beaten().is_empty());
    }

    #[test]
    fn query_param_condition_is_inert_under_prod_style_construction() {
        // A route that matches on a query parameter.
        let route = create_test_route(
            "q",
            vec![MatchCondition::QueryParam {
                name: "flag".to_string(),
                value: Some("1".to_string()),
            }],
        );
        let matcher = RouteMatcher::new(vec![route], None).unwrap();

        // Production (and explain, which mirrors it) hands the router the
        // query-STRIPPED path and parses query params from that same stripped
        // path — so the params map is empty and the condition cannot match.
        // This pins the documented gap: `QueryParam` routing is inert because
        // http_trait.rs sets `ctx.path = uri.path()` then parses params from it.
        let stripped = "/search"; // uri.path() form: query already removed
        let prod_style = RequestInfo::new("GET", stripped, "example.com")
            .with_query_params(RequestInfo::parse_query_params(stripped));
        assert!(matcher.explain_request(&prod_style).winner().is_none());

        // The condition itself is sound: given populated params it matches, so
        // the gap is in how params are sourced, not in the matcher.
        let mut params = HashMap::new();
        params.insert("flag".to_string(), "1".to_string());
        let with_params =
            RequestInfo::new("GET", stripped, "example.com").with_query_params(params);
        assert_eq!(
            matcher
                .explain_request(&with_params)
                .winner()
                .unwrap()
                .id
                .as_str(),
            "q"
        );
    }

    #[test]
    fn test_query_param_parsing() {
        let params = RequestInfo::parse_query_params("/path?foo=bar&baz=qux&empty=");
        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
        assert_eq!(params.get("empty"), Some(&"".to_string()));
    }

    #[test]
    fn test_path_prefix_segment_boundary() {
        let routes = vec![
            create_test_route("v2", vec![MatchCondition::PathPrefix("/v2".to_string())]),
            create_test_route(
                "catch-all",
                vec![MatchCondition::PathPrefix("/".to_string())],
            ),
        ];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        // /v2 exact → v2
        let req = RequestInfo::new("GET", "/v2", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");

        // /v2/ with trailing slash → v2
        let req = RequestInfo::new("GET", "/v2/", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");

        // /v2/anything → v2
        let req = RequestInfo::new("GET", "/v2/anything", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");

        // /v2example must NOT match /v2 prefix — falls to catch-all
        let req = RequestInfo::new("GET", "/v2example", "example.com");
        assert_eq!(
            matcher.match_request(&req).unwrap().route_id.as_str(),
            "catch-all"
        );

        // /v2?query → v2
        let req = RequestInfo::new("GET", "/v2?foo=bar", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");
    }

    #[test]
    fn test_header_matching_with_specificity() {
        let routes = vec![
            create_test_route(
                "catch-all",
                vec![MatchCondition::PathPrefix("/".to_string())],
            ),
            create_test_route(
                "header-v2",
                vec![
                    MatchCondition::Header {
                        name: "version".to_string(),
                        value: Some("two".to_string()),
                    },
                    MatchCondition::PathPrefix("/".to_string()),
                ],
            ),
        ];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        // Without headers → catch-all
        let req = RequestInfo::new("GET", "/", "example.com");
        assert_eq!(
            matcher.match_request(&req).unwrap().route_id.as_str(),
            "catch-all"
        );

        // With version:two header → header-v2 (more specific)
        let mut headers = HashMap::new();
        headers.insert("version".to_string(), "two".to_string());
        let req = RequestInfo::new("GET", "/", "example.com").with_headers(headers);
        assert_eq!(
            matcher.match_request(&req).unwrap().route_id.as_str(),
            "header-v2"
        );
    }
}
