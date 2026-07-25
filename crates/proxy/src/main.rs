// Allow field reassignment for Pingora's Opt/ServerConf structs
#![allow(clippy::field_reassign_with_default)]

//! Zentinel Proxy - Main entry point
//!
//! A security-first reverse proxy built on Pingora with sleepable ops at the edge.

// Use jemalloc as the global allocator for better performance
// jemalloc is optimized for multi-threaded allocation-heavy workloads
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pingora::prelude::*;
use std::sync::Arc;
use tracing::{error, info, warn};

use zentinel_config::server::{AcmeChallengeType, AcmeConfig};
use zentinel_config::Config;
use zentinel_proxy::acme::{
    AcmeClient, AcmeError, CertificateStorage, ChallengeManager, RenewalScheduler,
};
use zentinel_proxy::agent_scaffold::{run_agent_command, AgentArgs};
use zentinel_proxy::bundle::{run_bundle_command, BundleArgs};
use zentinel_proxy::tls::HotReloadableSniResolver;
use zentinel_proxy::{ReloadTrigger, SignalManager, SignalType, ZentinelProxy};

/// Version string combining Cargo semver and CalVer release tag
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (release ",
    env!("ZENTINEL_CALVER"),
    ", commit ",
    env!("ZENTINEL_COMMIT"),
    ")"
);

/// Zentinel - A security-first reverse proxy built on Pingora
#[derive(Parser, Debug)]
#[command(name = "zentinel")]
#[command(author, version = VERSION, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file path
    #[arg(short = 'c', long = "config", env = "ZENTINEL_CONFIG")]
    config: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,

    /// Enable verbose logging (debug level)
    #[arg(long = "verbose")]
    verbose: bool,

    /// Run in daemon mode (background)
    #[arg(short = 'd', long = "daemon")]
    daemon: bool,

    /// Upgrade from a running instance
    #[arg(short = 'u', long = "upgrade")]
    upgrade: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate configuration file and exit
    Test {
        /// Configuration file to test
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
    /// Run the proxy server (default)
    Run {
        /// Configuration file path
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
    /// Validate configuration with connectivity checks
    Validate {
        /// Configuration file to validate
        #[arg(short = 'c', long = "config")]
        config: Option<String>,

        /// Skip network connectivity checks
        #[arg(long = "skip-network")]
        skip_network: bool,

        /// Skip agent connectivity checks
        #[arg(long = "skip-agents")]
        skip_agents: bool,

        /// Skip certificate validation
        #[arg(long = "skip-certs")]
        skip_certs: bool,

        /// Compare the on-disk config against a running proxy and report drift.
        /// Pass the full URL of the proxy's builtin `/config` admin endpoint,
        /// e.g. http://127.0.0.1:9090/-/config
        #[arg(long = "against-running", value_name = "URL")]
        against_running: Option<String>,
    },
    /// Lint configuration for best practices
    Lint {
        /// Configuration file to lint
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },

    /// Explain how a synthetic request would route (dry-run, no server)
    Explain {
        /// Configuration file to explain against
        #[arg(short = 'c', long = "config")]
        config: Option<String>,

        /// HTTP method
        #[arg(short = 'm', long = "method", default_value = "GET")]
        method: String,

        /// Request path (e.g. /api/users)
        #[arg(short = 'p', long = "path", default_value = "/")]
        path: String,

        /// Host header value (overrides a `host=` entry in --header)
        #[arg(long = "host")]
        host: Option<String>,

        /// Additional request header, repeatable: --header name=value
        #[arg(long = "header", value_name = "NAME=VALUE")]
        header: Vec<String>,

        /// Emit JSON instead of human-readable text
        #[arg(long = "json")]
        json: bool,
    },

    /// Diff two configs and report behavioral changes (dry-run, no server)
    Diff {
        /// The old (baseline) configuration file
        #[arg(value_name = "OLD")]
        old: String,

        /// The new configuration file to compare against the baseline
        #[arg(value_name = "NEW")]
        new: String,

        /// Emit JSON instead of human-readable text
        #[arg(long = "json")]
        json: bool,
    },

    /// Manage bundled agents (install, status, update)
    Bundle(BundleArgs),

    /// Scaffold and manage external agents (`agent new <name>`)
    Agent(AgentArgs),
}

fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    // This must be done before Pingora initializes its TLS contexts
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Handle test flag or test subcommand
    if cli.test {
        return test_config(cli.config.as_deref());
    }

    // Handle subcommands
    match cli.command {
        Some(Commands::Test { config }) => test_config(config.as_deref().or(cli.config.as_deref())),
        Some(Commands::Run { config }) => {
            run_server(config.or(cli.config), cli.verbose, cli.daemon, cli.upgrade)
        }
        Some(Commands::Validate {
            config,
            skip_network,
            skip_agents,
            skip_certs,
            against_running,
        }) => validate_config(
            config.as_deref().or(cli.config.as_deref()),
            skip_network,
            skip_agents,
            skip_certs,
            against_running.as_deref(),
        ),
        Some(Commands::Lint { config }) => lint_config(config.as_deref().or(cli.config.as_deref())),
        Some(Commands::Explain {
            config,
            method,
            path,
            host,
            header,
            json,
        }) => explain_request_cmd(
            config.as_deref().or(cli.config.as_deref()),
            &method,
            &path,
            host.as_deref(),
            &header,
            json,
        ),
        Some(Commands::Diff { old, new, json }) => diff_configs(&old, &new, json),
        Some(Commands::Bundle(args)) => {
            // Initialize minimal logging for bundle commands
            tracing_subscriber::fmt()
                .with_target(false)
                .with_level(true)
                .init();
            run_bundle_command(args)
        }
        Some(Commands::Agent(args)) => run_agent_command(args),
        None => {
            // Default: run the server
            run_server(cli.config, cli.verbose, cli.daemon, cli.upgrade)
        }
    }
}

/// Test configuration file and exit
fn test_config(config_path: Option<&str>) -> Result<()> {
    // Initialize minimal logging for config test
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let config = match config_path {
        Some(path) => {
            info!("Testing configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Testing embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    // Validate the configuration
    config
        .validate()
        .context("Configuration validation failed")?;

    // Additional validation checks
    let route_count = config.routes.len();
    let upstream_count = config.upstreams.len();
    let listener_count = config.listeners.len();

    info!("Configuration test successful:");
    info!("  - {} listener(s)", listener_count);
    info!("  - {} route(s)", route_count);
    info!("  - {} upstream(s)", upstream_count);

    // Check for potential issues
    for route in &config.routes {
        if let Some(ref upstream) = route.upstream {
            if !config.upstreams.contains_key(upstream) {
                warn!(
                    "Route '{}' references undefined upstream '{}'",
                    route.id, upstream
                );
            }
        }
    }

    println!(
        "zentinel: configuration file {} test is successful",
        config_path.unwrap_or("(embedded)")
    );

    Ok(())
}

/// Validate configuration with connectivity checks
fn validate_config(
    config_path: Option<&str>,
    skip_network: bool,
    skip_agents: bool,
    skip_certs: bool,
    against_running: Option<&str>,
) -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Load configuration
    let config = match config_path {
        Some(path) => {
            info!("Validating configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Validating embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    // Schema validation (sync)
    config
        .validate()
        .context("Configuration schema validation failed")?;

    println!("✓ Configuration schema valid");

    // Runtime validation (async)
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        use zentinel_config::validate::*;

        let opts = ValidationOpts {
            skip_network,
            skip_agents,
            skip_certs,
        };

        let mut result = ValidationResult::new();

        // Network validation
        if !opts.skip_network {
            println!("Checking upstream connectivity...");
            result.merge(network::validate_upstreams(&config).await);
        }

        // Certificate validation
        if !opts.skip_certs {
            println!("Validating TLS certificates...");
            result.merge(certs::validate_certificates(&config).await);
        }

        // Agent validation
        if !opts.skip_agents {
            println!("Checking agent connectivity...");
            result.merge(agents::validate_agents(&config).await);
        }

        result
    });

    // Print results
    if result.errors.is_empty() {
        println!("✓ All validation checks passed");

        if !result.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &result.warnings {
                println!("  ⚠  {}", warning.message);
            }
        }

        // Optional drift check against a running proxy (exits 2 on drift).
        if let Some(url) = against_running {
            run_drift_check(&rt, url, &config)?;
        }

        std::process::exit(0);
    } else {
        println!("✗ Validation failed\n");
        println!("Errors:");
        for error in &result.errors {
            println!("  ✗ {}", error.message);
        }

        if !result.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &result.warnings {
                println!("  ⚠  {}", warning.message);
            }
        }

        std::process::exit(1);
    }
}

/// Fingerprint a running proxy reports from its `/config` admin endpoint.
struct RunningFingerprint {
    content_hash: String,
    loaded_at: Option<String>,
}

/// Compare the local (on-disk) config against a running proxy's fingerprint.
///
/// Both sides hash the config through the same [`Config::from_file`] pipeline,
/// so equal files produce equal hashes. Exits the process with code 2 when they
/// differ (drift detected), so CI can gate on it. Returns `Err` — which the
/// caller surfaces as a non-zero (code 1) exit — when the running proxy can't
/// be reached or its response can't be parsed.
///
/// Note: the hash covers the *effective* config (post env-substitution and
/// include-merge), so environment differences between the proxy's runtime and
/// this shell will legitimately show as drift.
fn run_drift_check(rt: &tokio::runtime::Runtime, url: &str, config: &Config) -> Result<()> {
    let local_hash = zentinel_proxy::config_fingerprint::content_hash(config);

    println!("\nChecking on-disk config against running proxy at {url} ...");
    let running = rt
        .block_on(fetch_running_fingerprint(url))
        .with_context(|| format!("Failed to query running proxy at {url}"))?;

    if running.content_hash == local_hash {
        println!("✓ On-disk config is in sync with the running proxy");
        if let Some(loaded_at) = &running.loaded_at {
            println!("  running config loaded at {loaded_at}");
        }
        Ok(())
    } else {
        println!("✗ Config drift detected — the running proxy is NOT running this file");
        println!("  on-disk : {local_hash}");
        println!("  running : {}", running.content_hash);
        if let Some(loaded_at) = &running.loaded_at {
            println!("  running config loaded at {loaded_at}");
        }
        println!("\n  Reload the proxy to apply the on-disk config.");
        std::process::exit(2);
    }
}

/// Fetch the `content_hash`/`loaded_at` a running proxy reports.
async fn fetch_running_fingerprint(url: &str) -> Result<RunningFingerprint> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?;

    let body: serde_json::Value = client
        .get(url)
        .send()
        .await
        .context("request to running proxy failed")?
        .error_for_status()
        .context("running proxy returned an error status")?
        .json()
        .await
        .context("running proxy response was not valid JSON")?;

    let content_hash = body
        .get("content_hash")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
        .context(
            "running proxy did not report `content_hash` (is the URL its builtin \
             `/config` admin endpoint, and is the proxy new enough to expose it?)",
        )?;

    let loaded_at = body
        .get("loaded_at")
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    Ok(RunningFingerprint {
        content_hash,
        loaded_at,
    })
}

/// Lint configuration for best practices
fn lint_config(config_path: Option<&str>) -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Load configuration
    let config = match config_path {
        Some(path) => {
            info!("Linting configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Linting embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    // Schema validation first
    config
        .validate()
        .context("Configuration schema validation failed")?;

    // Lint for best practices
    let result = zentinel_config::validate::lint::lint_config(&config);

    // Print results
    if result.warnings.is_empty() {
        println!("✓ No best practice issues found");
        std::process::exit(0);
    } else {
        println!(
            "⚠  Configuration has {} best practice warnings:\n",
            result.warnings.len()
        );
        for warning in &result.warnings {
            println!("  ⚠  {}", warning.message);
        }

        // Lint exits with 0 even with warnings (they're recommendations)
        std::process::exit(0);
    }
}

/// Explain how a synthetic request would route through the configuration.
///
/// Pure dry-run over the global route matcher: no listener is bound and no
/// network I/O occurs. Prints the matched route, what it beat, the ordered
/// filter/agent chain, effective timeout, failure mode, and upstream policy.
fn explain_request_cmd(
    config_path: Option<&str>,
    method: &str,
    path: &str,
    host: Option<&str>,
    headers: &[String],
    json: bool,
) -> Result<()> {
    use std::collections::HashMap;
    use zentinel_proxy::explain::{explain, ExplainRequest};

    // Logs go to stderr so the report (stdout) stays clean — critical for
    // `--json` piping. The default fmt writer is stdout, so set it explicitly.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr)
        .init();

    let config = match config_path {
        Some(path) => {
            info!("Explaining against configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Explaining against embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    config
        .validate()
        .context("Configuration schema validation failed")?;

    // Parse `name=value` headers (keys lower-cased to match route conditions).
    let mut header_map: HashMap<String, String> = HashMap::new();
    for raw in headers {
        match raw.split_once('=') {
            Some((name, value)) => {
                header_map.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
            None => {
                anyhow::bail!("invalid --header '{raw}' (expected name=value)");
            }
        }
    }

    // Host precedence: explicit --host, then a `host=` header, then empty.
    let host = host
        .map(str::to_string)
        .or_else(|| header_map.get("host").cloned())
        .unwrap_or_default();

    let request = ExplainRequest {
        method: method.to_uppercase(),
        path: path.to_string(),
        host,
        headers: header_map,
    };

    let report = explain(&config, &request).context("Failed to explain request")?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("Failed to serialize report")?
        );
    } else {
        print!("{}", report.render_text());
    }

    // Exit non-zero when nothing matched, so scripts can gate on routability.
    if report.no_match {
        std::process::exit(1);
    }
    Ok(())
}

/// Diff two configuration files and report behavioral changes.
///
/// Pure static analysis: loads and validates both configs, then reports routes,
/// upstreams, listeners, agents, and filters that changed behavior. Exits `2`
/// when any high-severity change is present so CI can gate on it.
fn diff_configs(old_path: &str, new_path: &str, json: bool) -> Result<()> {
    // Logs to stderr; the report goes to stdout (clean for `--json` piping).
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr)
        .init();

    let old = Config::from_file(old_path)
        .with_context(|| format!("Failed to load old config '{old_path}'"))?;
    let new = Config::from_file(new_path)
        .with_context(|| format!("Failed to load new config '{new_path}'"))?;

    old.validate().context("Old configuration is invalid")?;
    new.validate().context("New configuration is invalid")?;

    let diff = zentinel_config::validate::diff::diff(&old, &new);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&diff).context("Failed to serialize diff")?
        );
    } else {
        print!("{}", diff.render_text());
    }

    // Exit 2 when a high-severity change is present so CI can gate on it.
    if diff.has_high_severity() {
        std::process::exit(2);
    }
    Ok(())
}

/// State produced by ACME initialization, used to wire components into the proxy
struct AcmeState {
    /// Challenge manager for HTTP-01 challenge handling
    challenge_manager: Arc<ChallengeManager>,
    /// Renewal schedulers (one per ACME configuration block)
    schedulers: Vec<RenewalScheduler>,
}

/// Initialize ACME for all listeners and SNI certificates that have ACME configured
///
/// This function:
/// 1. Creates storage, client, and challenge manager for each ACME configuration
/// 2. Initializes (or loads) the ACME account with Let's Encrypt
/// 3. Obtains initial certificates if they don't exist yet
/// 4. Returns the ACME state for wiring into the proxy and background schedulers
///
/// For HTTP-01 challenges during initial issuance, a temporary HTTP server is
/// spawned to serve challenge responses (since Pingora isn't running yet).
async fn initialize_acme(
    config: &Config,
    sni_resolver: Option<Arc<HotReloadableSniResolver>>,
) -> Result<Option<AcmeState>, AcmeError> {
    // Collect all ACME configurations from listeners and SNI blocks
    let mut acme_configs: Vec<(String, AcmeConfig)> = Vec::new();

    for listener in &config.listeners {
        if listener.protocol == zentinel_config::ListenerProtocol::Https {
            if let Some(ref tls) = listener.tls {
                // Root-level ACME
                if let Some(ref acme) = tls.acme {
                    acme_configs.push((format!("listener '{}' (root)", listener.id), acme.clone()));
                }

                // SNI-level ACME
                for (i, sni) in tls.additional_certs.iter().enumerate() {
                    if let Some(ref acme) = sni.acme {
                        acme_configs.push((
                            format!("listener '{}' (sni cert #{})", listener.id, i),
                            acme.clone(),
                        ));
                    }
                }
            }
        }
    }

    if acme_configs.is_empty() {
        return Ok(None);
    }

    info!(
        config_count = acme_configs.len(),
        "Initializing ACME certificate management for multiple configurations"
    );

    // Shared challenge manager for all HTTP-01 challenges on this proxy instance
    let challenge_manager = Arc::new(ChallengeManager::new());
    let mut schedulers = Vec::new();

    for (description, acme_config) in acme_configs {
        info!(
            source = %description,
            domains = ?acme_config.domains,
            staging = acme_config.staging,
            challenge_type = ?acme_config.challenge_type,
            "Initializing ACME for {}", description
        );

        // Create storage
        let storage = Arc::new(CertificateStorage::new(&acme_config.storage)?);

        // Create client and initialize account
        let acme_client = Arc::new(AcmeClient::new(acme_config.clone(), Arc::clone(&storage)));
        acme_client.init_account().await?;

        // Create renewal scheduler
        let mut scheduler = RenewalScheduler::new(
            Arc::clone(&acme_client),
            Arc::clone(&challenge_manager),
            sni_resolver.clone(),
        );

        // If DNS-01, set up DNS challenge manager
        if acme_config.challenge_type == AcmeChallengeType::Dns01 {
            if let Some(ref dns_config) = acme_config.dns_provider {
                let provider = zentinel_proxy::acme::dns::create_provider(dns_config)?;

                let nameservers: Vec<std::net::IpAddr> = dns_config
                    .propagation
                    .nameservers
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();

                let propagation_config = zentinel_proxy::acme::dns::PropagationConfig {
                    initial_delay: std::time::Duration::from_secs(
                        dns_config.propagation.initial_delay_secs,
                    ),
                    check_interval: std::time::Duration::from_secs(
                        dns_config.propagation.check_interval_secs,
                    ),
                    timeout: std::time::Duration::from_secs(dns_config.propagation.timeout_secs),
                    nameservers,
                };

                let dns_manager = Arc::new(zentinel_proxy::acme::dns::Dns01ChallengeManager::new(
                    provider,
                    propagation_config,
                )?);
                scheduler = scheduler.with_dns_manager(dns_manager);
            }
        }

        // Check if initial certificate issuance is needed
        let primary_domain = acme_config.domains.first().ok_or_else(|| {
            AcmeError::OrderCreation(format!("No domains configured for ACME in {}", description))
        })?;

        if acme_client.needs_renewal(primary_domain)? {
            info!(
                source = %description,
                domain = %primary_domain,
                "Initial certificate issuance required"
            );

            match acme_config.challenge_type {
                AcmeChallengeType::Http01 => {
                    // Find an HTTP listener address for the temporary challenge server
                    let http_addr = config
                        .listeners
                        .iter()
                        .find(|l| l.protocol == zentinel_config::ListenerProtocol::Http)
                        .map(|l| l.address.clone())
                        .unwrap_or_else(|| "0.0.0.0:80".to_string());

                    info!(
                        address = %http_addr,
                        "Starting temporary HTTP challenge server for initial certificate acquisition"
                    );

                    // Start temporary challenge server
                    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                    let cm_clone = Arc::clone(&challenge_manager);
                    let _server_handle = tokio::spawn(async move {
                        zentinel_proxy::acme::challenge_server::run_challenge_server(
                            &http_addr,
                            cm_clone,
                            shutdown_rx,
                        )
                        .await
                    });

                    // Give the server a moment to bind
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                    // Obtain certificates
                    let result = scheduler.ensure_certificates().await;

                    // Shut down temporary server
                    let _ = shutdown_tx.send(true);
                    result?;
                }
                AcmeChallengeType::Dns01 => {
                    // DNS-01 doesn't need a temporary server
                    scheduler.ensure_certificates().await?;
                }
            }
        }

        schedulers.push(scheduler);
    }

    Ok(Some(AcmeState {
        challenge_manager,
        schedulers,
    }))
}

/// Run the proxy server
fn run_server(
    config_path: Option<String>,
    verbose: bool,
    daemon: bool,
    upgrade: bool,
) -> Result<()> {
    // Initialize logging based on verbose flag
    let log_level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    // Build Pingora options
    let mut pingora_opt = Opt::default();
    pingora_opt.daemon = daemon;
    pingora_opt.upgrade = upgrade;
    // Note: We'll configure threads via ServerConf after loading our config

    // Get config path with priority: CLI arg > env var > None (embedded default)
    let effective_config_path = config_path.or_else(|| std::env::var("ZENTINEL_CONFIG").ok());

    // Handle config file creation/loading
    let effective_config_path = match effective_config_path {
        Some(path) => {
            let config_path = std::path::Path::new(&path);
            if config_path.exists() {
                info!("Loading configuration from: {}", path);
                Some(path)
            } else {
                // Config file doesn't exist - create it with default content
                info!("Configuration file not found: {}", path);
                if let Err(e) = create_default_config_file(config_path) {
                    warn!("Failed to create default config file: {}", e);
                    info!("Using embedded default configuration instead");
                    None
                } else {
                    info!("Created default configuration at: {}", path);
                    Some(path)
                }
            }
        }
        None => {
            info!("No configuration specified, using embedded default configuration");
            None
        }
    };

    // Create signal manager for cross-thread communication
    let signal_manager = Arc::new(SignalManager::new());

    // Create runtime for async initialization and signal handling
    let runtime = tokio::runtime::Runtime::new()?;

    // Create proxy with configuration
    let mut proxy =
        runtime.block_on(async { ZentinelProxy::new(effective_config_path.as_deref()).await })?;

    // Get config manager for reload operations
    let config_manager = proxy.config_manager.clone();

    // Get initial config for server setup
    let config = proxy.config_manager.current();

    // Start the standalone Prometheus metrics server if enabled.
    // `observability.metrics.address` is a dedicated listener, separate from the
    // data-plane listeners, so the scrape endpoint is never exposed to client
    // traffic by accident.
    {
        let metrics_cfg = config.observability.metrics.clone();
        if metrics_cfg.enabled {
            let cache_stats = Some(proxy.http_cache_stats());
            runtime.spawn(async move {
                zentinel_proxy::metrics_server::run_metrics_server(
                    metrics_cfg.address,
                    metrics_cfg.path,
                    cache_stats,
                )
                .await;
            });
        } else {
            info!("Metrics server disabled (observability.metrics.enabled = false)");
        }
    }

    // Setup signal handlers (runs in separate thread, needs config for shutdown timeout)
    setup_signal_handlers(
        signal_manager.sender(),
        config.server.graceful_shutdown_timeout_secs,
    );

    // Initialize ACME if any listener has it configured
    let acme_state = runtime
        .block_on(async { initialize_acme(&config, None).await })
        .context("ACME initialization failed")?;

    // Wire ACME components into the proxy
    if let Some(ref state) = acme_state {
        proxy.acme_challenges = Some(Arc::clone(&state.challenge_manager));
        proxy.acme_clients = state
            .schedulers
            .iter()
            .map(|s| Arc::clone(s.client()))
            .collect();
    }

    // Initialize OpenTelemetry tracer if configured
    if let Some(ref tracing_config) = config.observability.tracing {
        match zentinel_proxy::otel::init_tracer(tracing_config) {
            Ok(()) => {
                info!(
                    backend = ?tracing_config.backend,
                    sampling_rate = tracing_config.sampling_rate,
                    service_name = %tracing_config.service_name,
                    "OpenTelemetry tracing enabled"
                );
            }
            Err(e) => {
                warn!("Failed to initialize OpenTelemetry tracer: {}", e);
                warn!("Distributed tracing will be disabled");
            }
        }
    }

    // Configure Pingora ServerConf with our settings
    let worker_threads = if config.server.worker_threads > 0 {
        config.server.worker_threads
    } else {
        num_cpus::get() // Default to CPU count
    };

    // Create Pingora ServerConf with performance settings
    let mut pingora_conf = pingora::server::configuration::ServerConf::default();
    pingora_conf.threads = worker_threads;
    pingora_conf.work_stealing = true;
    pingora_conf.upstream_keepalive_pool_size = 256; // Increase from default 128

    // Wire server config → Pingora ServerConf
    pingora_conf.graceful_shutdown_timeout_seconds =
        Some(config.server.graceful_shutdown_timeout_secs);
    if let Some(ref pid_path) = config.server.pid_file {
        pingora_conf.pid_file = pid_path.to_string_lossy().to_string();
    }
    if let Some(ref user) = config.server.user {
        pingora_conf.user = Some(user.clone());
    }
    if let Some(ref group) = config.server.group {
        pingora_conf.group = Some(group.clone());
    }

    info!(
        worker_threads = worker_threads,
        upstream_pool_size = pingora_conf.upstream_keepalive_pool_size,
        graceful_shutdown_timeout_secs = config.server.graceful_shutdown_timeout_secs,
        pid_file = ?config.server.pid_file,
        user = ?config.server.user,
        group = ?config.server.group,
        "Configuring Pingora server"
    );

    // Change working directory if configured (before bootstrap)
    if let Some(ref work_dir) = config.server.working_directory {
        std::env::set_current_dir(work_dir).with_context(|| {
            format!(
                "Failed to change working directory to '{}'",
                work_dir.display()
            )
        })?;
        info!(path = %work_dir.display(), "Changed working directory");
    }

    // Create Pingora server with our configuration
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), pingora_conf);
    server.bootstrap();

    // Determine keepalive request limit from listeners (use the most restrictive)
    let keepalive_request_limit = config
        .listeners
        .iter()
        .filter_map(|l| l.keepalive_max_requests)
        .min();

    // Create proxy service with server options (Pingora 0.8.0 builder pattern)
    let mut server_options = pingora_core::apps::HttpServerOptions::default();
    server_options.keepalive_request_limit = keepalive_request_limit;
    let mut proxy_service = pingora_proxy::ProxyServiceBuilder::new(&server.configuration, proxy)
        .name("Zentinel Proxy")
        .server_options(server_options)
        .build();

    // Configure listening addresses from config
    for listener in &config.listeners {
        match listener.protocol {
            zentinel_config::ListenerProtocol::Http => {
                proxy_service.add_tcp(&listener.address);
                info!("HTTP listening on: {}", listener.address);
            }
            zentinel_config::ListenerProtocol::Https => {
                match &listener.tls {
                    Some(tls_config) => {
                        // Determine certificate paths: manual or ACME-managed
                        let (cert_path, key_path) = if let (Some(ref cert), Some(ref key)) =
                            (&tls_config.cert_file, &tls_config.key_file)
                        {
                            // Manual certificates specified
                            (cert.clone(), key.clone())
                        } else if let Some(ref acme_config) = tls_config.acme {
                            // ACME-managed certificates
                            let acme_storage = &acme_config.storage;
                            let primary_domain = acme_config
                                .domains
                                .first()
                                .ok_or_else(|| {
                                    error!(
                                        listener_id = %listener.id,
                                        "ACME configuration has no domains"
                                    );
                                })
                                .unwrap_or(&"default".to_string())
                                .clone();

                            let cert_path = acme_storage
                                .join("domains")
                                .join(&primary_domain)
                                .join("cert.pem");
                            let key_path = acme_storage
                                .join("domains")
                                .join(&primary_domain)
                                .join("key.pem");

                            // If certs still don't exist after ACME init, something went wrong
                            if !cert_path.exists() || !key_path.exists() {
                                error!(
                                    listener_id = %listener.id,
                                    address = %listener.address,
                                    domains = ?acme_config.domains,
                                    cert_path = %cert_path.display(),
                                    "ACME certificate files not found after initialization"
                                );
                                continue;
                            }

                            (cert_path, key_path)
                        } else {
                            error!(
                                listener_id = %listener.id,
                                "TLS configuration requires either cert-file/key-file or acme block"
                            );
                            continue;
                        };

                        let cert_path_str = cert_path.to_string_lossy();
                        let key_path_str = key_path.to_string_lossy();

                        // Validate certificate files exist
                        if !cert_path.exists() {
                            error!(
                                listener_id = %listener.id,
                                cert_file = %cert_path_str,
                                "TLS certificate file not found"
                            );
                            continue;
                        }
                        if !key_path.exists() {
                            error!(
                                listener_id = %listener.id,
                                key_file = %key_path_str,
                                "TLS key file not found"
                            );
                            continue;
                        }

                        // TODO: Once the Pingora fork's TlsSettings supports accepting
                        // a pre-built rustls::ServerConfig, use tls::build_server_config()
                        // here to apply cipher_suites, min/max_version, and session_resumption.
                        // Currently Pingora's TlsSettings::build() creates its own ServerConfig
                        // with hardcoded defaults, ignoring our TLS hardening settings.
                        let mut tls_settings =
                            match pingora::listeners::tls::TlsSettings::intermediate(
                                &cert_path_str,
                                &key_path_str,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(
                                        listener_id = %listener.id,
                                        error = %e,
                                        "Failed to create TLS settings"
                                    );
                                    continue;
                                }
                            };
                        tls_settings.enable_h2();
                        proxy_service.add_tls_with_settings(&listener.address, None, tls_settings);
                        info!(
                            listener_id = %listener.id,
                            address = %listener.address,
                            cert_file = %cert_path_str,
                            min_tls_version = ?tls_config.min_version,
                            client_auth = tls_config.client_auth,
                            acme_enabled = tls_config.acme.is_some(),
                            "HTTPS (h2+http/1.1) listening on: {}", listener.address
                        );
                    }
                    None => {
                        error!(
                            listener_id = %listener.id,
                            address = %listener.address,
                            "HTTPS listener requires TLS configuration"
                        );
                    }
                }
            }
            _ => {
                warn!("Unsupported protocol: {:?}", listener.protocol);
            }
        }
    }

    // Add proxy service to server
    server.add_service(proxy_service);

    // Enable auto-reload file watching if configured
    let auto_reload_enabled = config.server.auto_reload;
    let has_config_file = effective_config_path.is_some();

    if auto_reload_enabled && has_config_file {
        let config_manager_watch = config_manager.clone();
        runtime.spawn(async move {
            if let Err(e) = config_manager_watch.start_watching().await {
                error!("Failed to start config file watcher: {}", e);
                error!("Auto-reload disabled, use SIGHUP for manual reload");
            }
        });
    } else if auto_reload_enabled && !has_config_file {
        warn!("auto-reload enabled but no config file specified (using embedded config)");
        warn!("Auto-reload requires a config file path");
    }

    // Spawn ACME renewal schedulers as background tasks
    if let Some(state) = acme_state {
        let scheduler_count = state.schedulers.len();
        for scheduler in state.schedulers {
            runtime.spawn(async move {
                scheduler.run().await;
            });
        }
        info!(
            count = scheduler_count,
            "ACME certificate renewal schedulers started"
        );
    }

    // Spawn signal handler task in the runtime
    let signal_manager_clone = signal_manager.clone();
    runtime.spawn(async move {
        run_signal_handler(signal_manager_clone, config_manager).await;
    });

    info!("Zentinel proxy started successfully");
    info!("Configuration hot reload enabled (SIGHUP)");
    if auto_reload_enabled && has_config_file {
        info!("Auto-reload enabled (watching config file)");
    }
    info!("Graceful shutdown enabled (SIGTERM/SIGINT)");

    // Run server forever
    server.run_forever();
}

/// Setup OS signal handlers
///
/// Registers handlers for SIGTERM, SIGINT, and SIGHUP and forwards them
/// to the async runtime via the signal manager.
fn setup_signal_handlers(
    signal_tx: std::sync::mpsc::Sender<SignalType>,
    graceful_shutdown_timeout_secs: u64,
) {
    use signal_hook::consts::signal::*;
    use signal_hook::iterator::Signals;
    use std::thread;

    let mut signals =
        Signals::new([SIGTERM, SIGINT, SIGHUP]).expect("Failed to register signal handlers");

    thread::spawn(move || {
        for sig in signals.forever() {
            let signal_type = match sig {
                SIGTERM | SIGINT => {
                    info!(
                        "Received shutdown signal ({}), initiating graceful shutdown",
                        if sig == SIGTERM { "SIGTERM" } else { "SIGINT" }
                    );
                    SignalType::Shutdown
                }
                SIGHUP => {
                    info!("Received SIGHUP, triggering configuration reload");
                    SignalType::Reload
                }
                _ => continue,
            };

            if signal_tx.send(signal_type).is_err() {
                // Channel closed, runtime is shutting down
                break;
            }

            // For shutdown, wait for graceful shutdown to complete before force-exiting
            if signal_type == SignalType::Shutdown {
                // Wait for the configured graceful shutdown timeout plus a small buffer
                let force_exit_secs = graceful_shutdown_timeout_secs.saturating_add(5);
                thread::sleep(std::time::Duration::from_secs(force_exit_secs));
                // Force exit if graceful shutdown takes too long
                error!(
                    timeout_secs = force_exit_secs,
                    "Graceful shutdown timeout exceeded, forcing exit"
                );
                std::process::exit(1);
            }
        }
    });
}

/// Create a default configuration file at the specified path
///
/// Creates parent directories if needed and writes the embedded default config.
fn create_default_config_file(path: &std::path::Path) -> Result<()> {
    use std::fs;
    use zentinel_config::DEFAULT_CONFIG_KDL;

    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }
    }

    // Write the default config
    fs::write(path, DEFAULT_CONFIG_KDL.trim_start())
        .with_context(|| format!("Failed to write default config to: {:?}", path))?;

    Ok(())
}

/// Async signal handler task
///
/// Receives signals from the signal manager and performs the appropriate action.
async fn run_signal_handler(
    signal_manager: Arc<SignalManager>,
    config_manager: Arc<zentinel_proxy::ConfigManager>,
) {
    loop {
        // Use spawn_blocking to wait for signals without blocking the async runtime
        let signal_manager_clone = signal_manager.clone();
        let signal =
            tokio::task::spawn_blocking(move || signal_manager_clone.recv_blocking()).await;

        match signal {
            Ok(Some(SignalType::Reload)) => {
                info!("Processing configuration reload request");
                match config_manager.reload(ReloadTrigger::Signal).await {
                    Ok(()) => {
                        info!("Configuration reloaded successfully");
                    }
                    Err(e) => {
                        error!("Configuration reload failed: {}", e);
                        error!("Continuing with previous configuration");
                    }
                }
            }
            Ok(Some(SignalType::Shutdown)) => {
                info!("Processing graceful shutdown request");
                // Shutdown OpenTelemetry tracer to flush pending spans
                zentinel_proxy::otel::shutdown_tracer();
                // Note: Connection draining is handled by Pingora's internal mechanisms
                // We give it a moment to start draining, then the signal thread will force exit
                info!("Shutdown initiated, draining connections...");
                // Exit cleanly - Pingora will handle connection draining
                std::process::exit(0);
            }
            Ok(None) => {
                // Channel closed
                info!("Signal channel closed, stopping signal handler");
                break;
            }
            Err(e) => {
                error!("Signal handler task panicked: {}", e);
                break;
            }
        }
    }
}
