//! Certificate validation
//!
//! Validates TLS certificates including existence, expiry, and validity.

use super::{ErrorCategory, ValidationError, ValidationResult, ValidationWarning};
use crate::Config;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Validate TLS certificates
pub async fn validate_certificates(config: &Config) -> ValidationResult {
    let mut result = ValidationResult::new();

    for listener in &config.listeners {
        if let Some(ref tls) = listener.tls {
            // If ACME is configured, validate ACME config instead of manual certs
            if let Some(ref acme_config) = tls.acme {
                // Validate ACME configuration
                if acme_config.domains.is_empty() {
                    result.add_error(ValidationError::new(
                        ErrorCategory::Certificate,
                        format!(
                            "ACME configuration for listener '{}' requires at least one domain",
                            listener.id
                        ),
                    ));
                }

                // Check storage directory is writable
                let storage_path = &acme_config.storage;
                if storage_path.exists() && !is_dir_writable(storage_path) {
                    result.add_error(ValidationError::new(
                        ErrorCategory::Certificate,
                        format!("ACME storage directory not writable: {:?}", storage_path),
                    ));
                }

                // Check if existing ACME certificates need renewal
                let primary_domain = acme_config.domains.first();
                if let Some(domain) = primary_domain {
                    let cert_path = storage_path.join("domains").join(domain).join("cert.pem");
                    if cert_path.exists() {
                        match load_and_validate_cert(&cert_path) {
                            Ok(Some(expiry_warning)) => {
                                result.add_warning(expiry_warning);
                            }
                            Ok(None) => {
                                // ACME certificate is valid
                            }
                            Err(e) => {
                                // ACME cert invalid, will be renewed
                                result.add_warning(ValidationWarning::new(format!(
                                    "ACME certificate validation failed (will be renewed): {}",
                                    e.message
                                )));
                            }
                        }
                    }
                }

                continue;
            }

            // Panel-managed certificate directories: the path itself is what
            // has to be right — a typo here looks identical to "no domains
            // issued yet" until a TLS handshake fails.
            for dir in &tls.sni_cert_dirs {
                match std::fs::read_dir(&dir.path) {
                    Ok(entries) => {
                        let domains = entries
                            .filter_map(std::result::Result::ok)
                            .filter(|e| e.path().is_dir())
                            .filter(|e| dir.paths_for(&e.path()).is_some())
                            .count();
                        if domains == 0 {
                            result.add_warning(ValidationWarning::new(format!(
                                "Certificate directory {:?} for listener '{}' holds no usable \
                                 certificates (expected <domain>/{} per domain)",
                                dir.path, listener.id, dir.combined_name
                            )));
                        }
                    }
                    Err(e) => {
                        result.add_error(ValidationError::new(
                            ErrorCategory::Certificate,
                            format!(
                                "Certificate directory {:?} for listener '{}' is unreadable: {}",
                                dir.path, listener.id, e
                            ),
                        ));
                    }
                }
            }

            // Manual certificate validation. A combined PEM carries the chain
            // and the key in one file, so both checks point at it.
            let (cert_file, key_file) = match (&tls.cert_file, &tls.key_file, &tls.combined_file) {
                (_, _, Some(combined)) => (combined, combined),
                (Some(cert), Some(key), None) => (cert, key),
                (None, _, None) => {
                    result.add_error(ValidationError::new(
                        ErrorCategory::Certificate,
                        format!(
                            "TLS configuration for listener '{}' requires cert-file, \
                             combined-file, or an acme block",
                            listener.id
                        ),
                    ));
                    continue;
                }
                (Some(_), None, None) => {
                    result.add_error(ValidationError::new(
                        ErrorCategory::Certificate,
                        format!(
                            "TLS configuration for listener '{}' requires key-file, \
                             combined-file, or an acme block",
                            listener.id
                        ),
                    ));
                    continue;
                }
            };

            // Check certificate file exists
            if !Path::new(cert_file).exists() {
                result.add_error(ValidationError::new(
                    ErrorCategory::Certificate,
                    format!("Certificate not found: {:?}", cert_file),
                ));
                continue;
            }

            // Check key file exists
            if !Path::new(key_file).exists() {
                result.add_error(ValidationError::new(
                    ErrorCategory::Certificate,
                    format!("Private key not found: {:?}", key_file),
                ));
                continue;
            }

            // Try to load and validate the certificate
            match load_and_validate_cert(cert_file) {
                Ok(Some(expiry_warning)) => {
                    result.add_warning(expiry_warning);
                }
                Ok(None) => {
                    // Certificate is valid
                }
                Err(e) => {
                    result.add_error(e);
                }
            }
        }
    }

    result
}

/// Check if a directory is writable
fn is_dir_writable(path: &Path) -> bool {
    use std::fs;
    let test_file = path.join(".zentinel_write_test");
    match fs::write(&test_file, b"test") {
        Ok(()) => {
            let _ = fs::remove_file(&test_file);
            true
        }
        Err(_) => false,
    }
}

/// Load a certificate and check its expiry
fn load_and_validate_cert(cert_path: &Path) -> Result<Option<ValidationWarning>, ValidationError> {
    use std::fs;

    // Read certificate file
    let cert_pem = fs::read(cert_path).map_err(|e| {
        ValidationError::new(
            ErrorCategory::Certificate,
            format!("Failed to read certificate {:?}: {}", cert_path, e),
        )
    })?;

    // Parse PEM certificate
    let pem = pem::parse(&cert_pem).map_err(|e| {
        ValidationError::new(
            ErrorCategory::Certificate,
            format!("Failed to parse certificate {:?}: {}", cert_path, e),
        )
    })?;

    // Parse X509 certificate
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).map_err(|e| {
        ValidationError::new(
            ErrorCategory::Certificate,
            format!("Invalid X509 certificate {:?}: {}", cert_path, e),
        )
    })?;

    // Check expiry
    let now = SystemTime::now();
    let not_after = cert.validity().not_after.to_datetime().unix_timestamp() as u64;
    let expiry_time = SystemTime::UNIX_EPOCH + Duration::from_secs(not_after);

    if expiry_time < now {
        return Err(ValidationError::new(
            ErrorCategory::Certificate,
            format!(
                "Certificate expired: {:?} (expired at {})",
                cert_path,
                cert.validity().not_after
            ),
        ));
    }

    // Warn if expiring within 30 days
    let thirty_days = Duration::from_secs(30 * 86400);
    if expiry_time < now + thirty_days {
        return Ok(Some(ValidationWarning::new(format!(
            "Certificate expires soon: {:?} (expires at {})",
            cert_path,
            cert.validity().not_after
        ))));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ListenerConfig, ListenerProtocol, TlsConfig};
    use zentinel_common::types::TlsVersion;

    fn test_tls_config() -> TlsConfig {
        TlsConfig {
            sni_cert_dirs: Vec::new(),
            combined_file: None,
            cert_file: Some("/nonexistent/cert.pem".into()),
            key_file: Some("/nonexistent/key.pem".into()),
            additional_certs: vec![],
            ca_file: None,
            min_version: TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: false,
            session_resumption: false,
            acme: None,
        }
    }

    fn test_listener_config() -> ListenerConfig {
        ListenerConfig {
            id: "test".to_string(),
            address: "0.0.0.0:443".to_string(),
            protocol: ListenerProtocol::Https,
            tls: Some(test_tls_config()),
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            proxy_protocol: None,
        }
    }

    #[tokio::test]
    async fn test_validate_missing_certificate() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_listener_config()];

        let result = validate_certificates(&config).await;

        assert!(!result.errors.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("Certificate not found")));
    }

    #[tokio::test]
    async fn combined_pem_is_not_reported_as_a_missing_cert_file() {
        let mut config = Config::default_for_testing();
        let mut listener = test_listener_config();
        if let Some(tls) = listener.tls.as_mut() {
            tls.cert_file = None;
            tls.key_file = None;
            tls.combined_file = Some("/nonexistent/combined".into());
        }
        config.listeners = vec![listener];

        let result = validate_certificates(&config).await;

        // The file is still missing, but the complaint must name the file —
        // not claim that cert-file was left out.
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("Certificate not found")));
        assert!(!result
            .errors
            .iter()
            .any(|e| e.message.contains("requires cert-file")));
    }

    #[tokio::test]
    async fn unreadable_certificate_directory_is_an_error() {
        let mut config = Config::default_for_testing();
        let mut listener = test_listener_config();
        if let Some(tls) = listener.tls.as_mut() {
            tls.sni_cert_dirs = vec![crate::server::SniCertDir {
                path: "/nonexistent/panel/certs".into(),
                combined_name: "combined".to_string(),
                cert_name: None,
                key_name: None,
            }];
        }
        config.listeners = vec![listener];

        let result = validate_certificates(&config).await;

        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("is unreadable")));
    }

    #[tokio::test]
    async fn empty_certificate_directory_warns_but_does_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default_for_testing();
        let mut listener = test_listener_config();
        if let Some(tls) = listener.tls.as_mut() {
            tls.sni_cert_dirs = vec![crate::server::SniCertDir {
                path: dir.path().to_path_buf(),
                combined_name: "combined".to_string(),
                cert_name: None,
                key_name: None,
            }];
        }
        config.listeners = vec![listener];

        let result = validate_certificates(&config).await;

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("no usable certificates")));
        assert!(!result
            .errors
            .iter()
            .any(|e| e.message.contains("unreadable")));
    }
}
