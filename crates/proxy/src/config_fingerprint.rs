//! Stable content fingerprint of a loaded configuration.
//!
//! The fingerprint is a hex SHA-256 over the *canonical* JSON of a [`Config`].
//! It backs two things:
//!
//! - the `content_hash` field on the `/config` builtin admin endpoint, and
//! - `zentinel validate --against-running`, which compares the hash of an
//!   on-disk config against the hash the running proxy reports.
//!
//! Equal files (loaded through the same [`Config::from_file`] pipeline) produce
//! equal hashes, so a mismatch means the on-disk file differs from the config
//! the proxy last loaded — the "edited the file, forgot to reload" incident
//! class the drift check targets.

use serde_json::Value;
use sha2::{Digest, Sha256};
use zentinel_config::Config;

/// Compute the hex-encoded SHA-256 content hash of `config`.
///
/// The hash is taken over a *canonical* JSON encoding: every JSON object's keys
/// are recursively sorted. This makes the hash stable regardless of `HashMap`
/// iteration order — `Config::upstreams` and `Config::filters` are `HashMap`s,
/// whose serialization order is otherwise non-deterministic — and regardless of
/// whether any crate enables `serde_json/preserve_order`. Array order is kept
/// on purpose: reordering routes can change priority and therefore behavior.
#[must_use]
pub fn content_hash(config: &Config) -> String {
    // `to_value` cannot fail for `Config`: it derives `Serialize` and all its
    // maps are string-keyed. Fail loud rather than hash a silent fallback that
    // would make distinct configs compare equal.
    let value = serde_json::to_value(config).expect("Config is always JSON-serializable");
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical).expect("canonical JSON value re-serializes");
    hex::encode(Sha256::digest(&bytes))
}

/// Recursively sort the keys of every JSON object so serialization is canonical.
fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> =
                map.into_iter().map(|(k, v)| (k, canonicalize(v))).collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            // Collecting the sorted entries preserves order whether the
            // `serde_json::Map` is a `BTreeMap` (default) or an `IndexMap`
            // (`preserve_order` feature), so the re-serialization is canonical.
            Value::Object(entries.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config::default_embedded().expect("embedded default config loads")
    }

    #[test]
    fn content_hash_is_stable_across_runs() {
        let config = base_config();
        assert_eq!(content_hash(&config), content_hash(&config));
    }

    #[test]
    fn content_hash_ignores_hashmap_insertion_order() {
        let c1 = base_config();

        // Rebuild the upstream and filter maps in reverse insertion order to
        // force a different `HashMap` layout; the canonical hash must not move.
        let mut c2 = c1.clone();
        let upstreams: Vec<_> = c2.upstreams.drain().collect();
        for (k, v) in upstreams.into_iter().rev() {
            c2.upstreams.insert(k, v);
        }
        let filters: Vec<_> = c2.filters.drain().collect();
        for (k, v) in filters.into_iter().rev() {
            c2.filters.insert(k, v);
        }

        assert_eq!(content_hash(&c1), content_hash(&c2));
    }

    #[test]
    fn content_hash_changes_when_content_changes() {
        let c1 = base_config();
        let before = content_hash(&c1);

        let mut c2 = c1.clone();
        c2.schema_version = format!("{}-modified", c2.schema_version);

        assert_ne!(before, content_hash(&c2));
    }

    #[test]
    fn content_hash_is_hex_sha256() {
        let hash = content_hash(&base_config());
        assert_eq!(hash.len(), 64, "SHA-256 hex is 64 chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
