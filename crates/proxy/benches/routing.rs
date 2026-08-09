//! Routing hot-path benchmarks.
//!
//! `RouteMatcher::match_request` runs once per request before anything else
//! (filters, agents, upstream selection), so a regression here taxes every
//! route equally. Two production-representative arms are gated by CI
//! (`scripts/bench-gate.py` via `.github/workflows/bench.yml`):
//!
//! - `route_match/cache_hit` — steady-state: the LRU route cache absorbs
//!   repeated (method, path, host) tuples. This is the common case for real
//!   traffic, which concentrates on a small set of hot paths.
//! - `route_match/cache_miss` — worst case: every request evaluates the full
//!   compiled route table (long-tail paths, cache churn, cold start).
//!
//! The table mirrors a realistic mid-size config: a mix of exact, prefix, and
//! regex path matchers across priorities, with host and method conditions —
//! not a synthetic single-route best case.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use zentinel_config::Config;
use zentinel_proxy::routing::{RequestInfo, RouteMatcher};

/// Build a realistic route table: 50 routes across exact/prefix/regex
/// matchers, mixed priorities, some host- and method-scoped.
fn build_matcher() -> RouteMatcher {
    let mut kdl = String::from(
        r#"
        system { worker-threads 0 }
        listeners {
            listener "http" { address "0.0.0.0:8080" }
        }
        upstreams {
            upstream "backend" {
                target "127.0.0.1:9000"
            }
        }
        routes {
            route "health" {
                priority "high"
                matches { path-exact "/healthz" }
                upstream "backend"
            }
            route "api-users-id" {
                priority "high"
                matches { path-regex "^/api/users/[0-9]+$" }
                upstream "backend"
            }
            route "api-admin" {
                priority "high"
                matches {
                    path-prefix "/api/admin"
                    host "admin.example.com"
                }
                upstream "backend"
            }
            route "api-write" {
                priority "normal"
                matches {
                    path-prefix "/api"
                    method "POST"
                }
                upstream "backend"
            }
"#,
    );
    // Bulk of the table: prefix routes like a per-tenant / per-section config.
    for i in 0..45 {
        kdl.push_str(&format!(
            r#"
            route "section-{i}" {{
                matches {{ path-prefix "/s{i}/" }}
                upstream "backend"
            }}
"#
        ));
    }
    kdl.push_str(
        r#"
            route "catch-all" {
                priority "low"
                matches { path-prefix "/" }
                upstream "backend"
            }
        }
"#,
    );

    let config = Config::from_kdl(&kdl).expect("bench config parses");
    RouteMatcher::with_cache_size(config.routes, None, 1000).expect("routes compile")
}

fn bench_route_match(c: &mut Criterion) {
    let matcher = build_matcher();
    let mut group = c.benchmark_group("route_match");
    group.throughput(Throughput::Elements(1));

    // Steady-state: same hot tuple every iteration → LRU hit.
    group.bench_function("cache_hit", |b| {
        // Warm the cache entry once so every measured iteration hits.
        let warm = RequestInfo::new("GET", "/api/users/42", "example.com");
        black_box(matcher.match_request(&warm));

        b.iter(|| {
            let req = RequestInfo::new("GET", "/api/users/42", "example.com");
            black_box(matcher.match_request(&req))
        })
    });

    // Worst case: unique path every iteration → full table evaluation. More
    // unique paths than cache capacity so the cycle never re-hits.
    let miss_paths: Vec<String> = (0..4096)
        .map(|i| format!("/s{}/item/{i}", i % 45))
        .collect();
    group.bench_function("cache_miss", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let path = &miss_paths[idx % miss_paths.len()];
            idx = idx.wrapping_add(1);
            let req = RequestInfo::new("GET", path, "example.com");
            black_box(matcher.match_request(&req))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_route_match);
criterion_main!(benches);
