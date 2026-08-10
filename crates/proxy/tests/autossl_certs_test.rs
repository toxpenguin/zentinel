//! Panel-issued certificate loading (cPanel AutoSSL and friends).
//!
//! Two layouts a control panel produces, neither of which Zentinel could read
//! before: a combined PEM (certificate + chain + key in one file), and a
//! directory holding one subdirectory per domain. Fixtures come from
//! tests/fixtures/tls — the `.pem` files there are already combined.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zentinel_config::{SniCertDir, TlsConfig};
use zentinel_proxy::tls::SniResolver;

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/tls")
}

/// TLS config with a default certificate and nothing else.
fn base_config() -> TlsConfig {
    let fixtures = fixtures_path();
    TlsConfig {
        cert_file: Some(fixtures.join("server-default.crt")),
        key_file: Some(fixtures.join("server-default.key")),
        combined_file: None,
        additional_certs: vec![],
        sni_cert_dirs: vec![],
        ca_file: None,
        min_version: zentinel_common::types::TlsVersion::Tls12,
        max_version: None,
        cipher_suites: vec![],
        client_auth: false,
        ocsp_stapling: false,
        session_resumption: true,
        acme: None,
    }
}

/// Panel layout: `<dir>/<domain>/combined`.
fn write_domain_cert(root: &Path, domain: &str, fixture: &str) {
    let dir = root.join(domain);
    fs::create_dir_all(&dir).unwrap();
    fs::copy(fixtures_path().join(fixture), dir.join("combined")).unwrap();
}

fn panel_dir(path: &Path) -> SniCertDir {
    SniCertDir {
        path: path.to_path_buf(),
        combined_name: "combined".to_string(),
        cert_name: None,
        key_name: None,
    }
}

#[test]
fn combined_pem_serves_as_the_default_certificate() {
    let mut config = base_config();
    config.cert_file = None;
    config.key_file = None;
    config.combined_file = Some(fixtures_path().join("server-default.pem"));

    let resolver = SniResolver::from_config(&config, Some("https"))
        .expect("combined PEM should load as the default certificate");

    let cert = resolver.resolve(Some("example.com"));
    assert!(Arc::strong_count(&cert) > 0);
}

#[test]
fn combined_pem_serves_as_an_sni_certificate() {
    let mut config = base_config();
    config.additional_certs = vec![zentinel_config::SniCertificate {
        hostnames: vec![],
        priority_hostnames: vec![],
        cert_file: None,
        key_file: None,
        combined_file: Some(fixtures_path().join("server-api.pem")),
        acme: None,
    }];

    let resolver = SniResolver::from_config(&config, Some("https")).unwrap();

    // Hostnames were not listed: they come from the certificate's SANs.
    let api = resolver.resolve(Some("api.example.com"));
    let fallback = resolver.resolve(Some("nothing.example.org"));
    assert!(
        !Arc::ptr_eq(&api, &fallback),
        "SAN auto-extraction failed for a combined PEM"
    );
}

#[test]
fn cert_directory_serves_domains_with_no_config_entries() {
    let root = tempfile::tempdir().unwrap();
    write_domain_cert(root.path(), "api.example.com", "server-api.pem");
    write_domain_cert(root.path(), "secure.example.com", "server-secure.pem");

    let mut config = base_config();
    config.sni_cert_dirs = vec![panel_dir(root.path())];

    let resolver = SniResolver::from_config(&config, Some("https")).unwrap();

    let api = resolver.resolve(Some("api.example.com"));
    let secure = resolver.resolve(Some("secure.example.com"));
    let fallback = resolver.resolve(Some("unknown.example.org"));

    assert!(!Arc::ptr_eq(&api, &fallback), "api cert not discovered");
    assert!(
        !Arc::ptr_eq(&secure, &fallback),
        "secure cert not discovered"
    );
    assert!(
        !Arc::ptr_eq(&api, &secure),
        "both domains resolved to the same certificate"
    );
}

#[test]
fn a_domain_added_after_startup_is_served_on_the_next_load() {
    // The panel issues a certificate for a new domain; the operator changes
    // nothing and reloads.
    let root = tempfile::tempdir().unwrap();
    write_domain_cert(root.path(), "api.example.com", "server-api.pem");

    let mut config = base_config();
    config.sni_cert_dirs = vec![panel_dir(root.path())];

    let before = SniResolver::from_config(&config, Some("https")).unwrap();
    assert!(
        Arc::ptr_eq(
            &before.resolve(Some("secure.example.com")),
            &before.resolve(Some("unknown.example.org"))
        ),
        "secure.example.com should not be served before its certificate exists"
    );

    write_domain_cert(root.path(), "secure.example.com", "server-secure.pem");

    let after = SniResolver::from_config(&config, Some("https")).unwrap();
    assert!(
        !Arc::ptr_eq(
            &after.resolve(Some("secure.example.com")),
            &after.resolve(Some("unknown.example.org"))
        ),
        "new domain not picked up by a rescan of the same config"
    );
}

#[test]
fn cert_directory_ignores_subdirectories_without_certificates() {
    let root = tempfile::tempdir().unwrap();
    write_domain_cert(root.path(), "api.example.com", "server-api.pem");
    // Panel directories routinely hold unrelated entries.
    fs::create_dir_all(root.path().join("bookkeeping")).unwrap();
    fs::write(root.path().join("README"), b"not a cert").unwrap();

    let mut config = base_config();
    config.sni_cert_dirs = vec![panel_dir(root.path())];

    let resolver = SniResolver::from_config(&config, Some("https"))
        .expect("unrelated entries must not fail the build");
    assert!(!Arc::ptr_eq(
        &resolver.resolve(Some("api.example.com")),
        &resolver.resolve(Some("unknown.example.org"))
    ));
}

#[test]
fn cert_directory_supports_split_cert_and_key_files() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("api.example.com");
    fs::create_dir_all(&dir).unwrap();
    fs::copy(
        fixtures_path().join("server-api.crt"),
        dir.join("fullchain.pem"),
    )
    .unwrap();
    fs::copy(
        fixtures_path().join("server-api.key"),
        dir.join("privkey.pem"),
    )
    .unwrap();

    let mut config = base_config();
    config.sni_cert_dirs = vec![SniCertDir {
        path: root.path().to_path_buf(),
        combined_name: "combined".to_string(),
        cert_name: Some("fullchain.pem".to_string()),
        key_name: Some("privkey.pem".to_string()),
    }];

    let resolver = SniResolver::from_config(&config, Some("https")).unwrap();
    assert!(!Arc::ptr_eq(
        &resolver.resolve(Some("api.example.com")),
        &resolver.resolve(Some("unknown.example.org"))
    ));
}

#[test]
fn overlapping_hostnames_between_discovered_certs_do_not_block_startup() {
    // Every fixture certificate carries `localhost` in its SANs, which is the
    // same shape as a panel adding the server hostname to every certificate.
    // There is no config entry to annotate a discovered certificate with, so
    // this must resolve deterministically instead of refusing to boot.
    let root = tempfile::tempdir().unwrap();
    write_domain_cert(root.path(), "api.example.com", "server-api.pem");
    write_domain_cert(root.path(), "secure.example.com", "server-secure.pem");

    let mut config = base_config();
    config.sni_cert_dirs = vec![panel_dir(root.path())];

    let first = SniResolver::from_config(&config, Some("https"))
        .expect("overlapping SANs must not fail the build");
    let second = SniResolver::from_config(&config, Some("https")).unwrap();

    // Each domain still gets its own certificate...
    assert!(!Arc::ptr_eq(
        &first.resolve(Some("api.example.com")),
        &first.resolve(Some("secure.example.com"))
    ));

    // ...and the contested name resolves the same way on every boot (first in
    // path order wins: api.example.com sorts before secure.example.com).
    let contested = first.resolve(Some("localhost"));
    assert!(Arc::ptr_eq(
        &contested,
        &first.resolve(Some("api.example.com"))
    ));
    assert!(Arc::ptr_eq(
        &second.resolve(Some("localhost")),
        &second.resolve(Some("api.example.com"))
    ));
}

#[test]
fn an_explicit_sni_entry_wins_over_a_discovered_one() {
    let root = tempfile::tempdir().unwrap();
    write_domain_cert(root.path(), "api.example.com", "server-api.pem");

    let mut config = base_config();
    config.additional_certs = vec![zentinel_config::SniCertificate {
        // The second hostname identifies this certificate uniquely; the
        // discovered one never claims it.
        hostnames: vec![
            "api.example.com".to_string(),
            "configured.example.net".to_string(),
        ],
        priority_hostnames: vec![],
        cert_file: Some(fixtures_path().join("server-secure.crt")),
        key_file: Some(fixtures_path().join("server-secure.key")),
        combined_file: None,
        acme: None,
    }];
    config.sni_cert_dirs = vec![panel_dir(root.path())];

    let resolver = SniResolver::from_config(&config, Some("https")).unwrap();

    assert!(
        Arc::ptr_eq(
            &resolver.resolve(Some("api.example.com")),
            &resolver.resolve(Some("configured.example.net"))
        ),
        "a discovered certificate overrode an explicitly configured one"
    );
}

#[test]
fn a_missing_cert_directory_fails_at_startup() {
    let mut config = base_config();
    config.sni_cert_dirs = vec![panel_dir(Path::new("/var/cpanel/ssl/does-not-exist"))];

    let err = SniResolver::from_config(&config, Some("https"))
        .expect_err("a mistyped certificate directory must not start silently")
        .to_string();

    assert!(err.contains("does-not-exist"), "got: {err}");
}

#[test]
fn an_empty_cert_directory_still_starts() {
    // A freshly provisioned box has no issued certificates yet; that is a
    // warning, not a reason to refuse to serve the default certificate.
    let root = tempfile::tempdir().unwrap();
    let mut config = base_config();
    config.sni_cert_dirs = vec![panel_dir(root.path())];

    let resolver = SniResolver::from_config(&config, Some("https")).unwrap();
    assert!(Arc::strong_count(&resolver.resolve(None)) > 0);
}
