//! Named backend profiles.
//!
//! A profile is shorthand for a set of upstream tuning values that a specific
//! backend stack wants — nothing more. Profiles are **opt-in** (an upstream
//! must name one), they only fill in settings the upstream did not set itself,
//! and every value they contribute is reported back through
//! [`AppliedProfile`] so `zentinel explain` and `zentinel lint` can show
//! exactly what the shorthand expanded to.
//!
//! They are deliberately *not* defaults: an upstream without a `profile` line
//! behaves exactly as before.
//!
//! # Example
//!
//! ```kdl
//! upstreams {
//!     upstream "apache" {
//!         profile "apache-shared-hosting"
//!         target "127.0.0.1:8080"
//!         timeouts { request 120 }   // explicit values always win
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::upstreams::{ConnectionPoolConfig, UpstreamTimeouts};

/// A named bundle of upstream tuning values for a known backend stack.
///
/// Every profile sets every field: there are no partially-specified profiles,
/// so the expansion of a profile name is always the same complete list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendProfile {
    /// Name used in KDL (`profile "apache-shared-hosting"`).
    pub name: &'static str,
    /// One-line description of the backend this profile targets.
    pub summary: &'static str,

    /// Connect timeout, seconds.
    pub connect_secs: u64,
    /// Whole-request timeout, seconds.
    pub request_secs: u64,
    /// Read timeout, seconds.
    pub read_secs: u64,
    /// Write timeout, seconds.
    pub write_secs: u64,

    /// Maximum pooled connections per target.
    pub max_connections: usize,
    /// Maximum idle connections kept per target.
    pub max_idle: usize,
    /// How long an idle pooled connection is kept, seconds.
    pub idle_timeout_secs: u64,
    /// Hard cap on connection age, seconds.
    pub max_lifetime_secs: Option<u64>,

    /// Assumptions an operator has to check against their own backend.
    pub assumptions: &'static [&'static str],
}

/// Every profile Zentinel ships. Adding one here is the only step needed to
/// make it usable in KDL.
pub const PROFILES: &[BackendProfile] = &[
    BackendProfile {
        name: "apache-shared-hosting",
        summary: "Apache httpd (prefork/event) on a shared-hosting box, typically on loopback",
        // Apache on the same host either accepts immediately or is out of
        // workers; a long connect timeout just queues doomed requests.
        connect_secs: 5,
        request_secs: 60,
        read_secs: 60,
        write_secs: 60,
        // Shared hosting caps MaxRequestWorkers across *all* vhosts. A large
        // edge pool converts one busy site into a site-wide worker shortage.
        max_connections: 64,
        max_idle: 16,
        // Below Apache's default KeepAliveTimeout (5s) on purpose: the pool
        // must recycle a connection before Apache decides to close it,
        // otherwise a request lands on a socket the backend is tearing down
        // and surfaces as a spurious 502.
        idle_timeout_secs: 3,
        // `apachectl graceful` retires workers on their own schedule; capping
        // connection age bounds how long we can hold one that is going away.
        max_lifetime_secs: Some(30),
        assumptions: &[
            "Apache KeepAliveTimeout is the default 5s — if you lowered it, lower idle-timeout too",
            "Apache is reachable on a local or low-latency network (connect timeout is 5s)",
        ],
    },
    BackendProfile {
        name: "litespeed",
        summary: "LiteSpeed / OpenLiteSpeed, event-driven and cheap to keep connections against",
        connect_secs: 5,
        request_secs: 120,
        read_secs: 120,
        write_secs: 120,
        // LiteSpeed handles many concurrent connections without a worker per
        // connection, so a wider pool is safe where Apache's would not be.
        max_connections: 256,
        max_idle: 64,
        // Still under a 5s keep-alive window; the win here is pool width, not
        // holding connections longer.
        idle_timeout_secs: 4,
        max_lifetime_secs: Some(120),
        assumptions: &[
            "LiteSpeed keep-alive timeout is 5s or more",
            "The backend's max connections comfortably exceeds 256 per Zentinel instance",
        ],
    },
    BackendProfile {
        name: "php-fpm-behind-apache",
        summary: "Apache in front of PHP-FPM, where slow PHP requests are normal",
        connect_secs: 5,
        // PHP scripts on shared hosting routinely run to max_execution_time;
        // cutting them off at the edge turns a slow page into a 504 and loses
        // the error the application would have produced.
        request_secs: 300,
        read_secs: 300,
        // Uploads still stream at normal speed — no reason to relax writes.
        write_secs: 60,
        // pm.max_children is the real ceiling. Keeping edge concurrency below
        // it sheds excess load at the edge instead of queueing it in FPM,
        // where it would occupy Apache workers as well.
        max_connections: 32,
        max_idle: 8,
        idle_timeout_secs: 3,
        max_lifetime_secs: Some(30),
        assumptions: &[
            "PHP max_execution_time is 300s or less",
            "PHP-FPM pm.max_children is comfortably above 32 per Zentinel instance",
        ],
    },
];

impl BackendProfile {
    /// Look up a profile by its KDL name.
    #[must_use]
    pub fn find(name: &str) -> Option<&'static BackendProfile> {
        PROFILES.iter().find(|p| p.name == name)
    }

    /// Every profile name, for error messages and documentation.
    #[must_use]
    pub fn names() -> Vec<&'static str> {
        PROFILES.iter().map(|p| p.name).collect()
    }

    /// Timeout values this profile contributes.
    #[must_use]
    pub fn timeouts(&self) -> UpstreamTimeouts {
        UpstreamTimeouts {
            connect_secs: self.connect_secs,
            request_secs: self.request_secs,
            read_secs: self.read_secs,
            write_secs: self.write_secs,
        }
    }

    /// Connection-pool values this profile contributes.
    #[must_use]
    pub fn connection_pool(&self) -> ConnectionPoolConfig {
        ConnectionPoolConfig {
            max_connections: self.max_connections,
            max_idle: self.max_idle,
            idle_timeout_secs: self.idle_timeout_secs,
            max_lifetime_secs: self.max_lifetime_secs,
        }
    }
}

/// What a profile actually contributed to one upstream, recorded at parse time
/// so the expansion can be shown rather than guessed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedProfile {
    /// Profile name as written in the config.
    pub name: String,
    /// Settings the profile supplied, in config order. Empty means the
    /// upstream overrode everything the profile had to offer.
    pub settings: Vec<ProfileSetting>,
}

impl AppliedProfile {
    /// Render the contributed settings as `field=value` pairs.
    #[must_use]
    pub fn summary(&self) -> String {
        self.settings
            .iter()
            .map(|s| format!("{}={}", s.field, s.value))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// One setting a profile supplied, named by its KDL path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSetting {
    /// KDL path of the setting, e.g. `timeouts.connect`.
    pub field: String,
    /// Value as it would be written in KDL.
    pub value: String,
}

impl ProfileSetting {
    pub(crate) fn new(field: &str, value: impl std::fmt::Display) -> Self {
        Self {
            field: field.to_string(),
            value: value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_profile_is_findable_by_name() {
        for profile in PROFILES {
            assert_eq!(
                BackendProfile::find(profile.name).map(|p| p.name),
                Some(profile.name)
            );
        }
        assert!(BackendProfile::find("not-a-profile").is_none());
    }

    #[test]
    fn profile_names_are_unique() {
        let mut names = BackendProfile::names();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate profile name in PROFILES");
    }

    #[test]
    fn idle_timeout_stays_under_the_backend_keepalive_window() {
        // The whole point of the pool settings: recycle before the backend
        // does. A profile that violates this would reintroduce the 502s it
        // exists to prevent.
        for profile in PROFILES {
            assert!(
                profile.idle_timeout_secs < 5,
                "profile '{}' has idle-timeout {}s, which is not below a 5s backend keep-alive window",
                profile.name,
                profile.idle_timeout_secs
            );
        }
    }

    #[test]
    fn every_profile_documents_its_assumptions() {
        for profile in PROFILES {
            assert!(
                !profile.assumptions.is_empty(),
                "profile '{}' ships no assumptions for operators to check",
                profile.name
            );
            assert!(!profile.summary.is_empty());
        }
    }

    #[test]
    fn applied_profile_summary_lists_contributions() {
        let applied = AppliedProfile {
            name: "apache-shared-hosting".to_string(),
            settings: vec![
                ProfileSetting::new("timeouts.connect", "5s"),
                ProfileSetting::new("connection-pool.max-connections", 64),
            ],
        };
        assert_eq!(
            applied.summary(),
            "timeouts.connect=5s, connection-pool.max-connections=64"
        );
    }
}
