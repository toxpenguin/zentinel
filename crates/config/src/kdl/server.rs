//! Server and listener KDL parsing.

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, trace};

use zentinel_common::types::{TlsVersion, TraceIdFormat};

use crate::server::{
    default_acme_storage, default_graceful_shutdown_timeout, default_keepalive_timeout,
    default_max_concurrent_streams, default_max_connections,
    default_proxy_protocol_header_timeout_ms, default_renewal_days, default_request_timeout,
    default_worker_threads, AcmeChallengeType, AcmeConfig, AcmeKeyType, DnsProviderConfig,
    DnsProviderType, ExternalAccountBinding, ListenerConfig, ListenerProtocol,
    PropagationCheckConfig, ProxyProtocolConfig, ServerConfig, SniCertDir, SniCertificate,
    TlsConfig,
};

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

/// Parse server configuration block
pub fn parse_server_config(node: &kdl::KdlNode) -> Result<ServerConfig> {
    trace!("Parsing server configuration block");

    let trace_id_format = get_string_entry(node, "trace-id-format")
        .map(|s| TraceIdFormat::from_str_loose(&s))
        .unwrap_or_default();

    let config = ServerConfig {
        worker_threads: get_int_entry(node, "worker-threads")
            .map(|v| v as usize)
            .unwrap_or_else(default_worker_threads),
        max_connections: get_int_entry(node, "max-connections")
            .map(|v| v as usize)
            .unwrap_or_else(default_max_connections),
        graceful_shutdown_timeout_secs: get_int_entry(node, "graceful-shutdown-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or_else(default_graceful_shutdown_timeout),
        daemon: get_bool_entry(node, "daemon").unwrap_or(false),
        pid_file: get_string_entry(node, "pid-file").map(PathBuf::from),
        user: get_string_entry(node, "user"),
        group: get_string_entry(node, "group"),
        working_directory: get_string_entry(node, "working-directory").map(PathBuf::from),
        trace_id_format,
        auto_reload: get_bool_entry(node, "auto-reload").unwrap_or(false),
        route_cache_size: get_int_entry(node, "route-cache-size")
            .map(|v| v as usize)
            .unwrap_or_else(crate::server::default_route_cache_size),
    };

    trace!(
        worker_threads = config.worker_threads,
        max_connections = config.max_connections,
        daemon = config.daemon,
        auto_reload = config.auto_reload,
        "Parsed server configuration"
    );

    Ok(config)
}

/// Parse listeners configuration block
pub fn parse_listeners(node: &kdl::KdlNode) -> Result<Vec<ListenerConfig>> {
    trace!("Parsing listeners configuration block");
    let mut listeners = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "listener" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener requires an ID argument, e.g., listener \"http\" {{ ... }}"
                    )
                })?;

                trace!(listener_id = %id, "Parsing listener");

                let address = get_string_entry(child, "address").ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener '{}' requires an 'address' field, e.g., address \"0.0.0.0:8080\"",
                        id
                    )
                })?;

                let protocol_str =
                    get_string_entry(child, "protocol").unwrap_or_else(|| "http".to_string());
                let protocol = match protocol_str.to_lowercase().as_str() {
                    "http" => ListenerProtocol::Http,
                    "https" => ListenerProtocol::Https,
                    "h2" => ListenerProtocol::Http2,
                    "h3" => ListenerProtocol::Http3,
                    other => {
                        return Err(anyhow::anyhow!(
                            "Invalid protocol '{}' for listener '{}'. Valid protocols: http, https, h2, h3",
                            other,
                            id
                        ));
                    }
                };

                // Parse TLS configuration if present
                let tls = if let Some(children) = child.children() {
                    children
                        .nodes()
                        .iter()
                        .find(|n| n.name().value() == "tls")
                        .map(|tls_node| parse_tls_config(tls_node, &id))
                        .transpose()?
                } else {
                    None
                };

                // Parse PROXY protocol acceptance if present
                let proxy_protocol = if let Some(children) = child.children() {
                    children
                        .nodes()
                        .iter()
                        .find(|n| n.name().value() == "proxy-protocol")
                        .map(|pp_node| parse_proxy_protocol_config(pp_node, &id))
                        .transpose()?
                } else {
                    None
                };

                trace!(
                    listener_id = %id,
                    address = %address,
                    protocol = ?protocol,
                    has_tls = tls.is_some(),
                    "Parsed listener"
                );

                listeners.push(ListenerConfig {
                    id,
                    address,
                    protocol,
                    tls,
                    default_route: get_string_entry(child, "default-route"),
                    namespace: get_string_entry(child, "namespace"),
                    request_timeout_secs: get_int_entry(child, "request-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_request_timeout),
                    keepalive_timeout_secs: get_int_entry(child, "keepalive-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_keepalive_timeout),
                    max_concurrent_streams: get_int_entry(child, "max-concurrent-streams")
                        .map(|v| v as u32)
                        .unwrap_or_else(default_max_concurrent_streams),
                    keepalive_max_requests: get_int_entry(child, "keepalive-max-requests")
                        .map(|v| v as u32),
                    proxy_protocol,
                });
            }
        }
    }

    trace!(
        listener_count = listeners.len(),
        "Finished parsing listeners"
    );
    Ok(listeners)
}

/// Parse PROXY protocol acceptance block
///
/// Example KDL:
/// ```kdl
/// proxy-protocol {
///     trusted "10.0.0.0/8" "192.168.0.0/16"
///     header-timeout-ms 2000
/// }
/// ```
pub(crate) fn parse_proxy_protocol_config(
    node: &kdl::KdlNode,
    listener_id: &str,
) -> Result<ProxyProtocolConfig> {
    let trusted: Vec<String> = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "trusted")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    if trusted.is_empty() {
        return Err(anyhow::anyhow!(
            "proxy-protocol on listener '{}' requires at least one 'trusted' CIDR \
             (headers from untrusted sources would let any client spoof its address; \
             use \"0.0.0.0/0\" to explicitly trust everything)",
            listener_id
        ));
    }

    for cidr in &trusted {
        cidr.parse::<zentinel_common::net::Cidr>().map_err(|e| {
            anyhow::anyhow!(
                "proxy-protocol on listener '{}': invalid trusted CIDR '{}': {}",
                listener_id,
                cidr,
                e
            )
        })?;
    }

    let header_timeout_ms = get_int_entry(node, "header-timeout-ms")
        .map(|v| v as u64)
        .unwrap_or_else(default_proxy_protocol_header_timeout_ms);
    if header_timeout_ms == 0 {
        return Err(anyhow::anyhow!(
            "proxy-protocol on listener '{}': header-timeout-ms must be greater than 0",
            listener_id
        ));
    }

    Ok(ProxyProtocolConfig {
        trusted,
        header_timeout_ms,
    })
}

/// Parse TLS configuration block
///
/// Example KDL:
/// ```kdl
/// tls {
///     // Option A: Manual certificates
///     cert-file "/etc/certs/server.crt"
///     key-file "/etc/certs/server.key"
///     ca-file "/etc/certs/ca.crt"  // Optional, for mTLS
///     min-version "1.2"
///     client-auth true
///
///     // SNI certificates
///     sni {
///         hostnames "example.com" "www.example.com"
///         cert-file "/etc/certs/example.crt"
///         key-file "/etc/certs/example.key"
///     }
///
///     // Option B: ACME automatic certificates
///     acme {
///         email "admin@example.com"
///         domains "example.com" "www.example.com"
///         staging false
///         storage "/var/lib/zentinel/acme"
///         renew-before-days 30
///     }
/// }
/// ```
pub fn parse_tls_config(node: &kdl::KdlNode, listener_id: &str) -> Result<TlsConfig> {
    debug!(listener_id = %listener_id, "Parsing TLS configuration");

    // Parse ACME configuration if present
    let acme = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "acme")
            .map(|acme_node| parse_acme_config(acme_node, listener_id))
            .transpose()?
    } else {
        None
    };

    // cert-file and key-file are required unless ACME or a combined PEM is
    // configured.
    let cert_file = get_string_entry(node, "cert-file").map(PathBuf::from);
    let key_file = get_string_entry(node, "key-file").map(PathBuf::from);
    let combined_file = get_string_entry(node, "combined-file").map(PathBuf::from);

    if combined_file.is_some() && (cert_file.is_some() || key_file.is_some()) {
        return Err(anyhow::anyhow!(
            "TLS configuration for listener '{}' sets 'combined-file' together with \
             'cert-file'/'key-file'. A combined PEM already carries the certificate, \
             its chain, and the key — use one form or the other",
            listener_id
        ));
    }

    // Validate that either manual certs or ACME is configured
    if acme.is_none() && combined_file.is_none() && (cert_file.is_none() || key_file.is_none()) {
        return Err(anyhow::anyhow!(
            "TLS configuration for listener '{}' requires either 'cert-file' and 'key-file', \
             a 'combined-file', or an 'acme' block",
            listener_id
        ));
    }

    // Optional CA file for client verification (mTLS)
    let ca_file = get_string_entry(node, "ca-file").map(PathBuf::from);

    // TLS version configuration
    let min_version = get_string_entry(node, "min-version")
        .map(|s| parse_tls_version(&s))
        .unwrap_or(TlsVersion::Tls12);

    let max_version = get_string_entry(node, "max-version").map(|s| parse_tls_version(&s));

    // Client authentication (mTLS)
    let client_auth = get_bool_entry(node, "client-auth").unwrap_or(false);

    // OCSP and session options
    let ocsp_stapling = get_bool_entry(node, "ocsp-stapling").unwrap_or(true);
    let session_resumption = get_bool_entry(node, "session-resumption").unwrap_or(true);

    // Cipher suites
    let cipher_suites = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "cipher-suite")
            .filter_map(get_first_arg_string)
            .collect()
    } else {
        Vec::new()
    };

    // Parse SNI certificates
    let additional_certs = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "sni")
            .map(|sni_node| parse_sni_certificate(sni_node, listener_id))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    // Parse certificate directories (one subdirectory per domain)
    let sni_cert_dirs = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "sni-cert-dir")
            .map(|dir_node| parse_sni_cert_dir(dir_node, listener_id))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    debug!(
        listener_id = %listener_id,
        has_cert_file = cert_file.is_some(),
        has_combined_file = combined_file.is_some(),
        has_acme = acme.is_some(),
        has_ca = ca_file.is_some(),
        client_auth = client_auth,
        sni_cert_count = additional_certs.len(),
        sni_cert_dir_count = sni_cert_dirs.len(),
        "Parsed TLS configuration"
    );

    Ok(TlsConfig {
        cert_file,
        key_file,
        combined_file,
        additional_certs,
        sni_cert_dirs,
        ca_file,
        min_version,
        max_version,
        cipher_suites,
        client_auth,
        ocsp_stapling,
        session_resumption,
        acme,
    })
}

/// Parse ACME configuration block
///
/// Example KDL:
/// ```kdl
/// acme {
///     email "admin@example.com"
///     domains "example.com" "www.example.com"
///     staging false
///     storage "/var/lib/zentinel/acme"
///     renew-before-days 30
///     challenge-type "dns-01"  // or "http-01" (default)
///
///     dns-provider {
///         type "hetzner"
///         credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
///         api-timeout-secs 30
///
///         propagation {
///             initial-delay-secs 10
///             check-interval-secs 5
///             timeout-secs 120
///         }
///     }
/// }
/// ```
fn parse_acme_config(node: &kdl::KdlNode, listener_id: &str) -> Result<AcmeConfig> {
    debug!(listener_id = %listener_id, "Parsing ACME configuration");

    // Required: email
    let email = get_string_entry(node, "email").ok_or_else(|| {
        anyhow::anyhow!(
            "ACME configuration for listener '{}' requires 'email'",
            listener_id
        )
    })?;

    // Required: domains (at least one)
    let domains: Vec<String> = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "domains")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    if domains.is_empty() {
        return Err(anyhow::anyhow!(
            "ACME configuration for listener '{}' requires at least one domain in 'domains'",
            listener_id
        ));
    }

    // Optional with defaults
    let server_url = get_string_entry(node, "server-url");
    let staging = get_bool_entry(node, "staging").unwrap_or(false);
    // Parse EAB if present
    let eab = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "eab")
            .map(|eab_node| -> Result<ExternalAccountBinding> {
                let kid = get_string_entry(eab_node, "kid")
                    .ok_or_else(|| anyhow::anyhow!("ACME EAB configuration requires 'kid'"))?;
                let hmac_key = get_string_entry(eab_node, "hmac-key")
                    .ok_or_else(|| anyhow::anyhow!("ACME EAB configuration requires 'hmac-key'"))?;
                Ok(ExternalAccountBinding { kid, hmac_key })
            })
            .transpose()?
    } else {
        None
    };
    let storage = get_string_entry(node, "storage")
        .map(PathBuf::from)
        .unwrap_or_else(default_acme_storage);
    let renew_before_days = get_int_entry(node, "renew-before-days")
        .map(|v| v as u32)
        .unwrap_or_else(default_renewal_days);

    // Parse challenge type
    let challenge_type = get_string_entry(node, "challenge-type")
        .map(|s| parse_challenge_type(&s))
        .unwrap_or_default();

    // Parse key type
    let key_type = if let Some(s) = get_string_entry(node, "key-type") {
        AcmeKeyType::from_str_loose(&s).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid key-type '{}' for listener '{}'. Valid types: ecdsa-p256, ecdsa-p384",
                s,
                listener_id
            )
        })?
    } else {
        AcmeKeyType::default()
    };

    // Parse DNS provider configuration if present
    let dns_provider = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "dns-provider")
            .map(|dns_node| parse_dns_provider_config(dns_node, listener_id))
            .transpose()?
    } else {
        None
    };

    // Validate: DNS-01 requires dns-provider
    if challenge_type.is_dns01() && dns_provider.is_none() {
        return Err(anyhow::anyhow!(
            "ACME configuration for listener '{}' uses DNS-01 challenge but no 'dns-provider' is configured",
            listener_id
        ));
    }

    // Validate: Wildcard domains require DNS-01
    let has_wildcard = domains.iter().any(|d| d.starts_with("*."));
    if has_wildcard && !challenge_type.is_dns01() {
        return Err(anyhow::anyhow!(
            "ACME configuration for listener '{}' has wildcard domain(s) but uses HTTP-01 challenge. \
             Wildcard domains require 'challenge-type \"dns-01\"'",
            listener_id
        ));
    }

    debug!(
        listener_id = %listener_id,
        email = %email,
        domain_count = domains.len(),
        staging = staging,
        storage = %storage.display(),
        renew_before_days = renew_before_days,
        challenge_type = ?challenge_type,
        has_dns_provider = dns_provider.is_some(),
        "Parsed ACME configuration"
    );

    Ok(AcmeConfig {
        email,
        domains,
        server_url,
        staging,
        eab,
        storage,
        renew_before_days,
        challenge_type,
        key_type,
        dns_provider,
    })
}

/// Parse challenge type string
fn parse_challenge_type(s: &str) -> AcmeChallengeType {
    match s.to_lowercase().as_str() {
        "dns-01" | "dns01" | "dns" => AcmeChallengeType::Dns01,
        _ => AcmeChallengeType::Http01, // Default to HTTP-01
    }
}

/// Parse DNS provider configuration block
///
/// Example KDL:
/// ```kdl
/// dns-provider {
///     type "hetzner"
///     credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
///     credentials-env "HETZNER_DNS_TOKEN"
///     api-timeout-secs 30
///
///     propagation {
///         initial-delay-secs 10
///         check-interval-secs 5
///         timeout-secs 120
///         nameservers "8.8.8.8" "1.1.1.1"
///     }
/// }
/// ```
fn parse_dns_provider_config(node: &kdl::KdlNode, listener_id: &str) -> Result<DnsProviderConfig> {
    debug!(listener_id = %listener_id, "Parsing DNS provider configuration");

    // Required: type
    let provider_type = get_string_entry(node, "type").ok_or_else(|| {
        anyhow::anyhow!(
            "DNS provider configuration for listener '{}' requires 'type'",
            listener_id
        )
    })?;

    let provider = parse_dns_provider_type(&provider_type, node, listener_id)?;

    // Credentials (at least one required)
    let credentials_file = get_string_entry(node, "credentials-file").map(PathBuf::from);
    let credentials_env = get_string_entry(node, "credentials-env");

    if credentials_file.is_none() && credentials_env.is_none() {
        return Err(anyhow::anyhow!(
            "DNS provider configuration for listener '{}' requires either 'credentials-file' or 'credentials-env'",
            listener_id
        ));
    }

    // API timeout
    let api_timeout_secs = get_int_entry(node, "api-timeout-secs")
        .map(|v| v as u64)
        .unwrap_or(30);

    // Propagation configuration
    let propagation = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "propagation")
            .map(parse_propagation_config)
            .unwrap_or_default()
    } else {
        PropagationCheckConfig::default()
    };

    debug!(
        listener_id = %listener_id,
        provider_type = %provider_type,
        has_credentials_file = credentials_file.is_some(),
        has_credentials_env = credentials_env.is_some(),
        api_timeout_secs = api_timeout_secs,
        "Parsed DNS provider configuration"
    );

    Ok(DnsProviderConfig {
        provider,
        credentials_file,
        credentials_env,
        api_timeout_secs,
        propagation,
    })
}

/// Parse DNS provider type
fn parse_dns_provider_type(
    type_str: &str,
    node: &kdl::KdlNode,
    listener_id: &str,
) -> Result<DnsProviderType> {
    match type_str.to_lowercase().as_str() {
        "hetzner" => Ok(DnsProviderType::Hetzner),
        "cloudflare" => Ok(DnsProviderType::Cloudflare),
        "webhook" => {
            let url = get_string_entry(node, "url").ok_or_else(|| {
                anyhow::anyhow!(
                    "DNS provider 'webhook' for listener '{}' requires 'url'",
                    listener_id
                )
            })?;
            let auth_header = get_string_entry(node, "auth-header");
            Ok(DnsProviderType::Webhook { url, auth_header })
        }
        other => Err(anyhow::anyhow!(
            "Unknown DNS provider type '{}' for listener '{}'. Valid types: hetzner, webhook",
            other,
            listener_id
        )),
    }
}

/// Parse propagation check configuration
fn parse_propagation_config(node: &kdl::KdlNode) -> PropagationCheckConfig {
    let initial_delay_secs = get_int_entry(node, "initial-delay-secs")
        .map(|v| v as u64)
        .unwrap_or(10);

    let check_interval_secs = get_int_entry(node, "check-interval-secs")
        .map(|v| v as u64)
        .unwrap_or(5);

    let timeout_secs = get_int_entry(node, "timeout-secs")
        .map(|v| v as u64)
        .unwrap_or(120);

    // Parse nameservers
    let nameservers: Vec<String> = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "nameservers")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    PropagationCheckConfig {
        initial_delay_secs,
        check_interval_secs,
        timeout_secs,
        nameservers,
    }
}

/// Parse an SNI certificate configuration
///
/// Example KDL:
/// ```kdl
/// // With explicit hostnames (no SAN auto-extraction)
/// sni {
///     hostnames "example.com" "www.example.com"
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
///
/// // Without hostnames (auto-extracted from certificate CN/SAN at load time)
/// sni {
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
///
/// // With priority hostnames (auto-extract all SANs, but this cert wins for listed hostnames)
/// sni {
///     priority-hostnames "example.com"
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
/// ```
fn parse_sni_certificate(node: &kdl::KdlNode, listener_id: &str) -> Result<SniCertificate> {
    let children = node.children();

    // Parse hostnames - explicit override, disables SAN auto-extraction.
    let hostnames: Vec<String> = if let Some(children) = children {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "hostnames")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    // Parse priority-hostnames - tie-breaking with full SAN auto-extraction.
    let priority_hostnames: Vec<String> = if let Some(children) = children {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "priority-hostnames")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    // Validate mutual exclusion
    if !hostnames.is_empty() && !priority_hostnames.is_empty() {
        return Err(anyhow::anyhow!(
            "SNI certificate for listener '{}' cannot specify both 'hostnames' and 'priority-hostnames'. \
             Use 'hostnames' for an explicit hostname list (no auto-extraction), or \
             'priority-hostnames' for priority tie-breaking with full SAN auto-extraction.",
            listener_id
        ));
    }

    // Parse acme configuration if present
    let acme = if let Some(children) = children {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "acme")
            .map(|n| parse_acme_config(n, listener_id))
            .transpose()?
    } else {
        None
    };

    let cert_file = get_string_entry(node, "cert-file").map(PathBuf::from);
    let key_file = get_string_entry(node, "key-file").map(PathBuf::from);
    let combined_file = get_string_entry(node, "combined-file").map(PathBuf::from);

    // Exactly one certificate source: split files, a combined PEM, or ACME.
    if combined_file.is_some() && (cert_file.is_some() || key_file.is_some()) {
        return Err(anyhow::anyhow!(
            "SNI certificate for listener '{}' sets 'combined-file' together with \
             'cert-file'/'key-file'. A combined PEM already carries the certificate, \
             its chain, and the key — use one form or the other",
            listener_id
        ));
    }
    if combined_file.is_some() && acme.is_some() {
        return Err(anyhow::anyhow!(
            "SNI certificate for listener '{}' cannot specify both 'combined-file' and an 'acme' block",
            listener_id
        ));
    }

    if combined_file.is_none() {
        // Validate mutual exclusion and completeness
        match (&acme, &cert_file, &key_file) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(anyhow::anyhow!(
                    "SNI certificate for listener '{}' cannot specify both manual files and an 'acme' block",
                    listener_id
                ));
            }
            (None, None, _) | (None, _, None) => {
                return Err(anyhow::anyhow!(
                    "SNI certificate for listener '{}' requires both 'cert-file' and 'key-file', \
                     a 'combined-file', or an 'acme' block",
                    listener_id
                ));
            }
            _ => {} // Valid: either acme OR (cert_file AND key_file)
        }
    }

    if let Some(ref acme_config) = acme {
        debug!(
            listener_id = %listener_id,
            acme_domains = ?acme_config.domains,
            "Parsed SNI certificate with ACME"
        );
    } else {
        // One of the two is always set here (validated above).
        let cert_path = cert_file
            .as_ref()
            .or(combined_file.as_ref())
            .expect("a certificate source is present")
            .display();
        if !priority_hostnames.is_empty() {
            debug!(
                listener_id = %listener_id,
                priority_hostnames = ?priority_hostnames,
                cert_file = %cert_path,
                "Parsed SNI certificate (SAN auto-extraction with priority tie-breaking)"
            );
        } else if hostnames.is_empty() {
            debug!(
                listener_id = %listener_id,
                cert_file = %cert_path,
                "Parsed SNI certificate (hostnames will be auto-extracted from CN/SAN)"
            );
        } else {
            debug!(
                listener_id = %listener_id,
                hostnames = ?hostnames,
                cert_file = %cert_path,
                "Parsed SNI certificate"
            );
        }
    }

    Ok(SniCertificate {
        hostnames,
        priority_hostnames,
        cert_file,
        key_file,
        combined_file,
        acme,
    })
}

/// Parse a certificate-directory block.
///
/// Example KDL (cPanel AutoSSL layout — the default file name):
/// ```kdl
/// sni-cert-dir "/var/cpanel/ssl/apache_tls"
///
/// // Split layout, one subdirectory per domain:
/// sni-cert-dir "/etc/panel/certs" {
///     cert-file "fullchain.pem"
///     key-file "privkey.pem"
/// }
/// ```
fn parse_sni_cert_dir(node: &kdl::KdlNode, listener_id: &str) -> Result<SniCertDir> {
    let path = get_first_arg_string(node).ok_or_else(|| {
        anyhow::anyhow!(
            "sni-cert-dir for listener '{}' requires a directory path, e.g. \
             sni-cert-dir \"/var/cpanel/ssl/apache_tls\"",
            listener_id
        )
    })?;

    let cert_name = get_string_entry(node, "cert-file");
    let key_name = get_string_entry(node, "key-file");
    if cert_name.is_some() != key_name.is_some() {
        return Err(anyhow::anyhow!(
            "sni-cert-dir '{}' for listener '{}' sets only one of 'cert-file'/'key-file'. \
             Split layouts need both; omit both to use the combined-PEM layout",
            path,
            listener_id
        ));
    }

    let combined_name =
        get_string_entry(node, "combined-file").unwrap_or_else(|| "combined".to_string());

    debug!(
        listener_id = %listener_id,
        path = %path,
        combined_name = %combined_name,
        split_layout = cert_name.is_some(),
        "Parsed SNI certificate directory"
    );

    Ok(SniCertDir {
        path: PathBuf::from(path),
        combined_name,
        cert_name,
        key_name,
    })
}

/// Parse TLS version string
///
/// Only TLS 1.2 and 1.3 are supported (TLS 1.0/1.1 are deprecated)
fn parse_tls_version(s: &str) -> TlsVersion {
    match s.to_lowercase().as_str() {
        "1.3" | "tls1.3" | "tlsv1.3" => TlsVersion::Tls13,
        // All other values default to TLS 1.2
        _ => TlsVersion::Tls12,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Vec<ListenerConfig> {
        let doc: kdl::KdlDocument = input.parse().unwrap();
        let node = doc.nodes().first().unwrap();
        parse_listeners(node).unwrap()
    }

    #[test]
    fn parses_listener_namespace_reference() {
        let listeners = parse(
            r#"
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                }
                listener "admin" {
                    address "127.0.0.1:9000"
                    namespace "ops"
                }
            }
            "#,
        );

        let public = listeners.iter().find(|l| l.id == "public").unwrap();
        let admin = listeners.iter().find(|l| l.id == "admin").unwrap();

        assert_eq!(public.namespace, None);
        assert_eq!(admin.namespace, Some("ops".to_string()));
        assert_eq!(admin.address, "127.0.0.1:9000");
    }

    fn parse_result(input: &str) -> Result<Vec<ListenerConfig>> {
        let doc: kdl::KdlDocument = input.parse().unwrap();
        let node = doc.nodes().first().unwrap();
        parse_listeners(node)
    }

    fn tls_of(input: &str) -> TlsConfig {
        parse(input)
            .into_iter()
            .next()
            .unwrap()
            .tls
            .expect("listener has TLS")
    }

    #[test]
    fn parses_combined_pem_certificate() {
        let tls = tls_of(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        combined-file "/var/cpanel/ssl/apache_tls/example.com/combined"
                    }
                }
            }
            "#,
        );

        assert_eq!(
            tls.combined_file,
            Some(PathBuf::from(
                "/var/cpanel/ssl/apache_tls/example.com/combined"
            ))
        );
        assert!(tls.cert_file.is_none() && tls.key_file.is_none());
    }

    #[test]
    fn rejects_combined_file_alongside_split_files() {
        let err = parse_result(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        cert-file "/etc/zentinel/edge.crt"
                        key-file "/etc/zentinel/edge.key"
                        combined-file "/var/cpanel/ssl/apache_tls/example.com/combined"
                    }
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("combined-file"), "got: {err}");
    }

    #[test]
    fn parses_sni_cert_dir_with_panel_defaults() {
        let tls = tls_of(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        cert-file "/etc/zentinel/edge.crt"
                        key-file "/etc/zentinel/edge.key"
                        sni-cert-dir "/var/cpanel/ssl/apache_tls"
                    }
                }
            }
            "#,
        );

        assert_eq!(tls.sni_cert_dirs.len(), 1);
        let dir = &tls.sni_cert_dirs[0];
        assert_eq!(dir.path, PathBuf::from("/var/cpanel/ssl/apache_tls"));
        assert_eq!(dir.combined_name, "combined");
        assert!(dir.cert_name.is_none() && dir.key_name.is_none());
    }

    #[test]
    fn parses_sni_cert_dir_with_split_layout() {
        let tls = tls_of(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        cert-file "/etc/zentinel/edge.crt"
                        key-file "/etc/zentinel/edge.key"
                        sni-cert-dir "/etc/panel/certs" {
                            cert-file "fullchain.pem"
                            key-file "privkey.pem"
                        }
                    }
                }
            }
            "#,
        );

        let dir = &tls.sni_cert_dirs[0];
        assert_eq!(dir.cert_name.as_deref(), Some("fullchain.pem"));
        assert_eq!(dir.key_name.as_deref(), Some("privkey.pem"));
    }

    #[test]
    fn rejects_half_specified_split_cert_dir() {
        let err = parse_result(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        cert-file "/etc/zentinel/edge.crt"
                        key-file "/etc/zentinel/edge.key"
                        sni-cert-dir "/etc/panel/certs" {
                            cert-file "fullchain.pem"
                        }
                    }
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("only one of"), "got: {err}");
    }

    #[test]
    fn parses_sni_certificate_from_combined_pem() {
        let tls = tls_of(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        cert-file "/etc/zentinel/edge.crt"
                        key-file "/etc/zentinel/edge.key"
                        sni {
                            combined-file "/var/cpanel/ssl/apache_tls/shop.example.com/combined"
                        }
                    }
                }
            }
            "#,
        );

        let sni = &tls.additional_certs[0];
        assert!(sni.combined_file.is_some());
        assert!(sni.cert_file.is_none());
        // No hostnames listed: they come from the certificate's CN/SAN, which
        // is what lets the panel add domains without a config edit.
        assert!(sni.hostnames.is_empty());
    }

    #[test]
    fn rejects_sni_certificate_with_combined_and_acme() {
        let err = parse_result(
            r#"
            listeners {
                listener "https" {
                    address "0.0.0.0:443"
                    tls {
                        cert-file "/etc/zentinel/edge.crt"
                        key-file "/etc/zentinel/edge.key"
                        sni {
                            combined-file "/var/cpanel/ssl/apache_tls/shop.example.com/combined"
                            acme {
                                email "admin@example.com"
                                domains "shop.example.com"
                            }
                        }
                    }
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("combined-file"), "got: {err}");
    }

    #[test]
    fn parses_proxy_protocol_block() {
        let listeners = parse(
            r#"
            listeners {
                listener "behind-lb" {
                    address "0.0.0.0:8080"
                    proxy-protocol {
                        trusted "10.0.0.0/8" "192.168.0.0/16"
                        header-timeout-ms 500
                    }
                }
                listener "direct" {
                    address "0.0.0.0:8081"
                }
            }
            "#,
        );

        let lb = listeners.iter().find(|l| l.id == "behind-lb").unwrap();
        let pp = lb.proxy_protocol.as_ref().unwrap();
        assert_eq!(pp.trusted, vec!["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(pp.header_timeout_ms, 500);

        let direct = listeners.iter().find(|l| l.id == "direct").unwrap();
        assert!(direct.proxy_protocol.is_none());
    }

    #[test]
    fn proxy_protocol_timeout_defaults_when_omitted() {
        let listeners = parse(
            r#"
            listeners {
                listener "lb" {
                    address "0.0.0.0:8080"
                    proxy-protocol {
                        trusted "10.0.0.0/8"
                    }
                }
            }
            "#,
        );
        let pp = listeners[0].proxy_protocol.as_ref().unwrap();
        assert_eq!(pp.header_timeout_ms, 2000);
    }

    #[test]
    fn proxy_protocol_without_trusted_is_rejected() {
        let err = parse_result(
            r#"
            listeners {
                listener "lb" {
                    address "0.0.0.0:8080"
                    proxy-protocol {
                        header-timeout-ms 500
                    }
                }
            }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one 'trusted' CIDR"));
    }

    #[test]
    fn proxy_protocol_with_invalid_cidr_is_rejected() {
        let err = parse_result(
            r#"
            listeners {
                listener "lb" {
                    address "0.0.0.0:8080"
                    proxy-protocol {
                        trusted "10.0.0.0"
                    }
                }
            }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid trusted CIDR '10.0.0.0'"));
    }

    #[test]
    fn proxy_protocol_zero_timeout_is_rejected() {
        let err = parse_result(
            r#"
            listeners {
                listener "lb" {
                    address "0.0.0.0:8080"
                    proxy-protocol {
                        trusted "10.0.0.0/8"
                        header-timeout-ms 0
                    }
                }
            }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be greater than 0"));
    }
}
