//! Foreign proxy configuration importer (`zentinel import`).
//!
//! Converts Apache httpd configurations into Zentinel KDL. The mapped set is
//! deliberately small and explicit:
//!
//! - `<VirtualHost addr>` → listener (grouped by address) + routes
//! - `ServerName` / `ServerAlias` → `host` match conditions
//! - `ProxyPass` → upstream + route
//! - `SSLCertificateFile` / `SSLCertificateKeyFile` → listener TLS (with SNI
//!   blocks when multiple TLS vhosts share an address)
//!
//! Everything else is **never silently dropped**: unmapped directives are
//! collected with their line numbers, embedded as comments in the generated
//! KDL, and printed to stderr so operators know exactly what stays on the
//! backend.
//!
//! Generated output is gated before it is shown: it must round-trip through
//! [`Config::from_kdl`] and pass [`Config::validate`], otherwise the command
//! fails with an importer-bug error instead of emitting broken config.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use zentinel_config::Config;

/// Refuse inputs larger than this; Apache configs are text and small.
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Truncate reported directive text to keep the report readable.
const MAX_REPORT_TEXT: usize = 100;

/// Base route priority; the emitted priority is this plus the path-prefix
/// length so longer (more specific) prefixes are evaluated first.
const BASE_ROUTE_PRIORITY: usize = 50;

/// Arguments for the `import` subcommand.
#[derive(Args, Debug)]
pub struct ImportArgs {
    #[command(subcommand)]
    command: ImportCommand,
}

#[derive(Subcommand, Debug)]
enum ImportCommand {
    /// Convert an Apache httpd configuration to Zentinel KDL.
    Apache(ApacheArgs),
}

#[derive(Args, Debug)]
struct ApacheArgs {
    /// Path to the Apache configuration file (httpd.conf or a vhost file)
    file: PathBuf,

    /// Write the generated KDL here instead of stdout
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

/// Run the `import` subcommand.
///
/// # Errors
///
/// Returns an error if the input cannot be read, is malformed (unclosed
/// sections, invalid ports, certificate without key), contains no
/// `<VirtualHost>` blocks, or if the generated KDL fails the round-trip
/// parse/validate gate (an importer bug).
pub fn run_import_command(args: ImportArgs) -> Result<()> {
    match args.command {
        ImportCommand::Apache(apache) => import_apache(&apache.file, apache.output.as_deref()),
    }
}

/// A directive (or emission decision) that was not translated into KDL.
#[derive(Debug)]
struct Note {
    line: usize,
    directive: String,
    detail: String,
}

impl Note {
    fn new(line: usize, directive: &str, detail: impl Into<String>) -> Self {
        let mut directive = directive.trim().to_string();
        if directive.len() > MAX_REPORT_TEXT {
            let cut = directive
                .char_indices()
                .nth(MAX_REPORT_TEXT)
                .map_or(directive.len(), |(i, _)| i);
            directive.truncate(cut);
            directive.push('…');
        }
        Self {
            line,
            directive,
            detail: detail.into(),
        }
    }
}

/// One `ProxyPass` mapping that could be translated.
#[derive(Debug)]
struct ProxyPass {
    path: String,
    target: ProxyTarget,
}

/// Parsed `ProxyPass` target endpoint.
#[derive(Debug)]
struct ProxyTarget {
    tls: bool,
    host: String,
    port: u16,
}

/// One parsed `<VirtualHost>` block.
#[derive(Debug)]
struct VirtualHost {
    line: usize,
    address: String,
    server_name: Option<String>,
    aliases: Vec<String>,
    proxy_passes: Vec<ProxyPass>,
    cert_file: Option<String>,
    key_file: Option<String>,
    ssl_engine: bool,
}

impl VirtualHost {
    fn new(line: usize, address: String) -> Self {
        Self {
            line,
            address,
            server_name: None,
            aliases: Vec::new(),
            proxy_passes: Vec::new(),
            cert_file: None,
            key_file: None,
            ssl_engine: false,
        }
    }

    fn has_certs(&self) -> bool {
        self.cert_file.is_some() && self.key_file.is_some()
    }
}

fn import_apache(file: &Path, output: Option<&Path>) -> Result<()> {
    let content =
        fs::read_to_string(file).with_context(|| format!("failed to read {}", file.display()))?;
    if content.len() > MAX_INPUT_BYTES {
        bail!(
            "{} is {} bytes; refusing inputs larger than {} bytes",
            file.display(),
            content.len(),
            MAX_INPUT_BYTES
        );
    }

    let mut notes = Vec::new();
    let vhosts = parse_apache(&content, &mut notes)?;
    if vhosts.is_empty() {
        bail!(
            "no <VirtualHost> blocks found in {} — nothing to import",
            file.display()
        );
    }

    let kdl = emit_kdl(&vhosts, &mut notes, &file.display().to_string())?;

    // Round-trip gate: never show config the parser would reject.
    let config = Config::from_kdl(&kdl).map_err(|e| {
        anyhow!("generated KDL failed to parse — this is an importer bug, please report it:\n{e}")
    })?;
    config.validate().map_err(|e| {
        anyhow!(
            "generated config failed validation — this is an importer bug, please report it:\n{e}"
        )
    })?;

    match output {
        Some(path) => {
            fs::write(path, &kdl).with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!("Wrote {}", path.display());
        }
        None => print!("{kdl}"),
    }

    eprintln!(
        "Imported {} VirtualHost block(s): {} listener(s), {} route(s), {} upstream(s).",
        vhosts.len(),
        config.listeners.len(),
        config.routes.len(),
        config.upstreams.len()
    );
    if !notes.is_empty() {
        eprintln!(
            "NOT imported ({} item(s)) — stays on the backend or needs manual attention:",
            notes.len()
        );
        for note in &notes {
            eprintln!(
                "  line {:>4}: {} — {}",
                note.line, note.directive, note.detail
            );
        }
    }

    Ok(())
}

/// A physical-line-joined logical line of the config.
struct LogicalLine {
    number: usize,
    text: String,
}

/// Join backslash-continued lines, drop blanks and full-line comments.
fn logical_lines(content: &str) -> Vec<LogicalLine> {
    let mut out = Vec::new();
    let mut pending: Option<LogicalLine> = None;

    for (idx, raw) in content.lines().enumerate() {
        let number = idx + 1;
        let trimmed_end = raw.trim_end();
        let continued = trimmed_end.ends_with('\\');
        let piece = trimmed_end.trim_end_matches('\\').trim();

        match pending.take() {
            Some(mut line) => {
                if !piece.is_empty() {
                    line.text.push(' ');
                    line.text.push_str(piece);
                }
                if continued {
                    pending = Some(line);
                } else {
                    out.push(line);
                }
            }
            None => {
                // Apache comments occupy a whole line and cannot be continued.
                if piece.is_empty() || piece.starts_with('#') {
                    continue;
                }
                let line = LogicalLine {
                    number,
                    text: piece.to_string(),
                };
                if continued {
                    pending = Some(line);
                } else {
                    out.push(line);
                }
            }
        }
    }
    if let Some(line) = pending {
        out.push(line);
    }
    out
}

/// Split a directive line into arguments, honoring double quotes.
fn split_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in text.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Strip an optional scheme and port from a `ServerName`-style value.
fn clean_server_name(raw: &str) -> String {
    let without_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let host = without_scheme.split(':').next().unwrap_or(without_scheme);
    host.trim_end_matches('.').to_string()
}

fn parse_apache(content: &str, notes: &mut Vec<Note>) -> Result<Vec<VirtualHost>> {
    let mut vhosts: Vec<VirtualHost> = Vec::new();
    let mut current: Option<VirtualHost> = None;
    // (start line, tag name, nesting depth) of a section we skip wholesale.
    let mut skip: Option<(usize, String, usize)> = None;

    for line in logical_lines(content) {
        let text = line.text.as_str();

        if let Some((_, _, depth)) = &mut skip {
            if text.starts_with("</") {
                *depth -= 1;
                if *depth == 0 {
                    skip = None;
                }
            } else if text.starts_with('<') {
                *depth += 1;
            }
            continue;
        }

        if let Some(rest) = text.strip_prefix("</") {
            let tag = rest.trim_end_matches('>').trim();
            if tag.eq_ignore_ascii_case("virtualhost") {
                match current.take() {
                    Some(vhost) => vhosts.push(vhost),
                    None => bail!(
                        "line {}: </VirtualHost> without matching <VirtualHost>",
                        line.number
                    ),
                }
            } else {
                bail!("line {}: unexpected closing tag '</{}>'", line.number, tag);
            }
            continue;
        }

        if let Some(rest) = text.strip_prefix('<') {
            let mut parts = split_args(rest.trim_end_matches('>'));
            if parts.is_empty() {
                bail!("line {}: malformed section tag '{}'", line.number, text);
            }
            let tag = parts.remove(0);
            if tag.eq_ignore_ascii_case("virtualhost") {
                if current.is_some() {
                    bail!(
                        "line {}: nested <VirtualHost> is not valid Apache configuration",
                        line.number
                    );
                }
                let address = parts.first().cloned().ok_or_else(|| {
                    anyhow!("line {}: <VirtualHost> requires an address", line.number)
                })?;
                if parts.len() > 1 {
                    notes.push(Note::new(
                        line.number,
                        text,
                        format!("only the first address '{address}' is imported; extra addresses ignored"),
                    ));
                }
                current = Some(VirtualHost::new(line.number, address));
            } else {
                notes.push(Note::new(
                    line.number,
                    text,
                    format!(
                        "<{tag}> section skipped entirely, including every directive inside it"
                    ),
                ));
                skip = Some((line.number, tag, 1));
            }
            continue;
        }

        let mut args = split_args(text);
        if args.is_empty() {
            continue;
        }
        let name = args.remove(0);

        let Some(vhost) = current.as_mut() else {
            notes.push(Note::new(
                line.number,
                text,
                "outside <VirtualHost> — not imported",
            ));
            continue;
        };

        if name.eq_ignore_ascii_case("servername") {
            let value = args
                .first()
                .ok_or_else(|| anyhow!("line {}: ServerName requires a hostname", line.number))?;
            vhost.server_name = Some(clean_server_name(value));
        } else if name.eq_ignore_ascii_case("serveralias") {
            if args.is_empty() {
                bail!(
                    "line {}: ServerAlias requires at least one hostname",
                    line.number
                );
            }
            for alias in &args {
                let cleaned = clean_server_name(alias);
                if cleaned.contains('*') || cleaned.contains('?') {
                    notes.push(Note::new(
                        line.number,
                        text,
                        format!("wildcard alias '{cleaned}' emitted as-is — verify Zentinel host matching handles it"),
                    ));
                }
                vhost.aliases.push(cleaned);
            }
        } else if name.eq_ignore_ascii_case("proxypass") {
            parse_proxy_pass(&args, text, line.number, vhost, notes)?;
        } else if name.eq_ignore_ascii_case("sslcertificatefile") {
            let value = args.first().ok_or_else(|| {
                anyhow!("line {}: SSLCertificateFile requires a path", line.number)
            })?;
            vhost.cert_file = Some(value.clone());
        } else if name.eq_ignore_ascii_case("sslcertificatekeyfile") {
            let value = args.first().ok_or_else(|| {
                anyhow!(
                    "line {}: SSLCertificateKeyFile requires a path",
                    line.number
                )
            })?;
            vhost.key_file = Some(value.clone());
        } else if name.eq_ignore_ascii_case("sslengine") {
            vhost.ssl_engine = args.first().is_some_and(|v| v.eq_ignore_ascii_case("on"));
        } else {
            notes.push(Note::new(line.number, text, "stays on the backend"));
        }
    }

    if let Some(vhost) = current {
        bail!("unclosed <VirtualHost> started at line {}", vhost.line);
    }
    if let Some((start, tag, _)) = skip {
        bail!("unclosed <{tag}> section started at line {start}");
    }
    Ok(vhosts)
}

fn parse_proxy_pass(
    args: &[String],
    text: &str,
    line: usize,
    vhost: &mut VirtualHost,
    notes: &mut Vec<Note>,
) -> Result<()> {
    if args.len() < 2 {
        bail!("line {line}: ProxyPass requires <path> and <target-url>");
    }
    let path = args[0].clone();
    let target_raw = &args[1];

    if target_raw == "!" {
        notes.push(Note::new(
            line,
            text,
            "ProxyPass exclusion — replicate manually with a higher-priority route if needed",
        ));
        return Ok(());
    }
    if args.len() > 2 {
        notes.push(Note::new(
            line,
            text,
            format!("ProxyPass options not imported: {}", args[2..].join(" ")),
        ));
    }

    let Some((scheme, rest)) = target_raw.split_once("://") else {
        notes.push(Note::new(
            line,
            text,
            format!("target '{target_raw}' is not an http(s) URL — not imported"),
        ));
        return Ok(());
    };
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        other => {
            notes.push(Note::new(
                line,
                text,
                format!("scheme '{other}://' not supported (only http and https) — not imported"),
            ));
            return Ok(());
        }
    };

    let (host_port, target_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match split_host_port(host_port, default_port) {
        Ok(pair) => pair,
        Err(reason) => {
            notes.push(Note::new(line, text, format!("{reason} — not imported")));
            return Ok(());
        }
    };
    if host.is_empty() {
        notes.push(Note::new(
            line,
            text,
            "empty host in target URL — not imported",
        ));
        return Ok(());
    }

    // Apache substitutes the matched prefix with the target path; Zentinel
    // forwards the original request path. Warn whenever they would differ.
    if target_path.trim_end_matches('/') != path.trim_end_matches('/') {
        notes.push(Note::new(
            line,
            text,
            format!(
                "path mapping '{path}' → '{}' is not preserved; the upstream receives the original request path",
                if target_path.is_empty() { "/" } else { target_path }
            ),
        ));
    }

    vhost.proxy_passes.push(ProxyPass {
        path,
        target: ProxyTarget { tls, host, port },
    });
    Ok(())
}

/// Split `host[:port]` (with `[v6]` brackets) into parts.
fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(rest) = s.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("unclosed '[' in address '{s}'"));
        };
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| format!("invalid port '{p}' in address '{s}'"))?,
            None if after.is_empty() => default_port,
            None => return Err(format!("invalid address '{s}'")),
        };
        Ok((host.to_string(), port))
    } else if let Some((host, port)) = s.rsplit_once(':') {
        port.parse()
            .map(|p| (host.to_string(), p))
            .map_err(|_| format!("invalid port '{port}' in address '{s}'"))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// Normalize a `<VirtualHost>` address to a bindable `ip:port` string.
fn normalize_vhost_address(vhost: &VirtualHost, notes: &mut Vec<Note>) -> Result<(String, u16)> {
    let raw = vhost.address.as_str();
    let default_port = if vhost.has_certs() { 443u16 } else { 80u16 };

    let (host_raw, port) = if let Some(stripped) = raw.strip_suffix(":*") {
        (stripped, None)
    } else if raw.starts_with('[') || raw.contains(':') {
        let (host, port) = split_host_port(raw, default_port)
            .map_err(|reason| anyhow!("line {}: {reason}", vhost.line))?;
        // split_host_port applies the default silently; detect whether a port
        // was actually written so the assumption can be reported.
        let had_port = raw.ends_with(&format!(":{port}"));
        return finish_address(
            vhost,
            &host,
            if had_port { Some(port) } else { None },
            default_port,
            notes,
        );
    } else {
        (raw, None)
    };
    finish_address(vhost, host_raw, port, default_port, notes)
}

fn finish_address(
    vhost: &VirtualHost,
    host_raw: &str,
    port: Option<u16>,
    default_port: u16,
    notes: &mut Vec<Note>,
) -> Result<(String, u16)> {
    let host = if host_raw == "*" || host_raw.eq_ignore_ascii_case("_default_") {
        "0.0.0.0".to_string()
    } else if host_raw.parse::<std::net::IpAddr>().is_ok() {
        host_raw.to_string()
    } else {
        notes.push(Note::new(
            vhost.line,
            &format!("<VirtualHost {}>", vhost.address),
            format!("address '{host_raw}' is a hostname; listener bound to 0.0.0.0 — restrict manually if needed"),
        ));
        "0.0.0.0".to_string()
    };

    let port = match port {
        Some(p) => p,
        None => {
            notes.push(Note::new(
                vhost.line,
                &format!("<VirtualHost {}>", vhost.address),
                format!("no port in address; assumed {default_port}"),
            ));
            default_port
        }
    };

    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok((address, port))
}

/// Escape a string for use inside a KDL quoted string.
fn kdl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Lowercase, keep alphanumerics, collapse everything else to single dashes.
fn sanitize_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out
    }
}

/// Return `base`, or `base-2`, `base-3`, … until unused.
fn unique_id(base: &str, used: &mut BTreeSet<String>) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}-{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

fn emit_kdl(vhosts: &[VirtualHost], notes: &mut Vec<Note>, source: &str) -> Result<String> {
    // Certificate sanity first: fail loudly on half-configured TLS.
    for vhost in vhosts {
        match (&vhost.cert_file, &vhost.key_file) {
            (Some(_), None) => bail!(
                "line {}: SSLCertificateFile without SSLCertificateKeyFile",
                vhost.line
            ),
            (None, Some(_)) => bail!(
                "line {}: SSLCertificateKeyFile without SSLCertificateFile",
                vhost.line
            ),
            _ => {}
        }
        if vhost.ssl_engine && !vhost.has_certs() {
            notes.push(Note::new(
                vhost.line,
                &format!("<VirtualHost {}>", vhost.address),
                "SSLEngine on but no SSLCertificateFile — TLS not emitted for this vhost",
            ));
        }
    }

    // Group vhosts by normalized listener address.
    let mut groups: BTreeMap<String, (u16, Vec<usize>)> = BTreeMap::new();
    for (idx, vhost) in vhosts.iter().enumerate() {
        let (address, port) = normalize_vhost_address(vhost, notes)?;
        groups
            .entry(address)
            .or_insert_with(|| (port, Vec::new()))
            .1
            .push(idx);
    }

    // Listeners.
    let mut listeners_kdl = String::new();
    let mut used_listener_ids = BTreeSet::new();
    for (address, (port, indices)) in &groups {
        let tls_vhosts: Vec<&VirtualHost> = indices
            .iter()
            .map(|&i| &vhosts[i])
            .filter(|v| v.has_certs())
            .collect();
        let protocol = if tls_vhosts.is_empty() {
            "http"
        } else {
            "https"
        };
        if !tls_vhosts.is_empty() && tls_vhosts.len() < indices.len() {
            let plain = vhosts[*indices
                .iter()
                .find(|&&i| !vhosts[i].has_certs())
                .expect("mixed group must contain a plain vhost")]
            .line;
            notes.push(Note::new(
                plain,
                &format!("<VirtualHost on {address}>"),
                "shares an address with TLS vhosts; this vhost is served over HTTPS too",
            ));
        }

        let id = unique_id(&format!("apache-{port}"), &mut used_listener_ids);
        writeln!(listeners_kdl, "    listener \"{id}\" {{")?;
        writeln!(listeners_kdl, "        address \"{}\"", kdl_escape(address))?;
        writeln!(listeners_kdl, "        protocol \"{protocol}\"")?;
        if let Some(first) = tls_vhosts.first() {
            let (default_cert, default_key) = (
                first.cert_file.as_deref().expect("checked above"),
                first.key_file.as_deref().expect("checked above"),
            );
            writeln!(listeners_kdl, "        tls {{")?;
            writeln!(
                listeners_kdl,
                "            cert-file \"{}\"",
                kdl_escape(default_cert)
            )?;
            writeln!(
                listeners_kdl,
                "            key-file \"{}\"",
                kdl_escape(default_key)
            )?;
            for extra in &tls_vhosts[1..] {
                let (cert, key) = (
                    extra.cert_file.as_deref().expect("checked above"),
                    extra.key_file.as_deref().expect("checked above"),
                );
                if cert == default_cert && key == default_key {
                    continue;
                }
                let mut hostnames: Vec<&str> = Vec::new();
                if let Some(name) = &extra.server_name {
                    hostnames.push(name);
                }
                hostnames.extend(extra.aliases.iter().map(String::as_str));
                if hostnames.is_empty() {
                    notes.push(Note::new(
                        extra.line,
                        &format!("<VirtualHost {}>", extra.address),
                        "has its own certificate but no ServerName — SNI certificate NOT emitted",
                    ));
                    continue;
                }
                let quoted: Vec<String> = hostnames
                    .iter()
                    .map(|h| format!("\"{}\"", kdl_escape(h)))
                    .collect();
                writeln!(listeners_kdl, "            sni {{")?;
                writeln!(
                    listeners_kdl,
                    "                hostnames {}",
                    quoted.join(" ")
                )?;
                writeln!(
                    listeners_kdl,
                    "                cert-file \"{}\"",
                    kdl_escape(cert)
                )?;
                writeln!(
                    listeners_kdl,
                    "                key-file \"{}\"",
                    kdl_escape(key)
                )?;
                writeln!(listeners_kdl, "            }}")?;
            }
            writeln!(listeners_kdl, "        }}")?;
        }
        writeln!(listeners_kdl, "    }}")?;
    }

    // Routes + upstream registry.
    let mut routes_kdl = String::new();
    let mut upstream_names: BTreeMap<(String, u16, bool), String> = BTreeMap::new();
    let mut used_upstream_names = BTreeSet::new();
    let mut used_route_ids = BTreeSet::new();
    let mut route_count = 0usize;

    for vhost in vhosts {
        if vhost.proxy_passes.is_empty() {
            notes.push(Note::new(
                vhost.line,
                &format!("<VirtualHost {}>", vhost.address),
                "no importable ProxyPass — no route emitted (static serving is not imported)",
            ));
            continue;
        }

        let mut hosts: Vec<Option<&str>> = Vec::new();
        if let Some(name) = &vhost.server_name {
            hosts.push(Some(name));
        }
        for alias in &vhost.aliases {
            if vhost.server_name.as_deref() != Some(alias.as_str()) {
                hosts.push(Some(alias));
            }
        }
        if hosts.is_empty() {
            notes.push(Note::new(
                vhost.line,
                &format!("<VirtualHost {}>", vhost.address),
                "no ServerName — routes match every host on the listener",
            ));
            hosts.push(None);
        }

        for pass in &vhost.proxy_passes {
            let key = (pass.target.host.clone(), pass.target.port, pass.target.tls);
            let upstream = upstream_names
                .entry(key)
                .or_insert_with(|| {
                    unique_id(
                        &sanitize_id(&format!("{}-{}", pass.target.host, pass.target.port)),
                        &mut used_upstream_names,
                    )
                })
                .clone();

            for host in &hosts {
                let mut base = sanitize_id(host.unwrap_or("any"));
                if !pass.path.trim_end_matches('/').is_empty() {
                    base = format!("{base}-{}", sanitize_id(&pass.path));
                }
                let id = unique_id(&base, &mut used_route_ids);
                let priority = BASE_ROUTE_PRIORITY + pass.path.len().min(400);

                writeln!(routes_kdl, "    route \"{id}\" {{")?;
                writeln!(routes_kdl, "        priority {priority}")?;
                writeln!(routes_kdl, "        matches {{")?;
                if let Some(host) = host {
                    writeln!(routes_kdl, "            host \"{}\"", kdl_escape(host))?;
                }
                writeln!(
                    routes_kdl,
                    "            path-prefix \"{}\"",
                    kdl_escape(&pass.path)
                )?;
                writeln!(routes_kdl, "        }}")?;
                writeln!(routes_kdl, "        upstream \"{upstream}\"")?;
                writeln!(routes_kdl, "    }}")?;
                route_count += 1;
            }
        }
    }

    // Upstreams.
    let mut upstreams_kdl = String::new();
    for ((host, port, tls), name) in &upstream_names {
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        writeln!(upstreams_kdl, "    upstream \"{name}\" {{")?;
        writeln!(
            upstreams_kdl,
            "        target \"{}\" weight=1",
            kdl_escape(&target)
        )?;
        if *tls {
            writeln!(upstreams_kdl, "        tls {{")?;
            writeln!(upstreams_kdl, "            sni \"{}\"", kdl_escape(host))?;
            writeln!(upstreams_kdl, "        }}")?;
        }
        writeln!(upstreams_kdl, "    }}")?;
    }

    notes.sort_by_key(|n| n.line);

    // Header: provenance, scope, and the loud unmapped report.
    let mut out = String::new();
    writeln!(
        out,
        "// Zentinel configuration generated by `zentinel import apache`."
    )?;
    writeln!(out, "// Source: {source}")?;
    writeln!(out, "//")?;
    writeln!(
        out,
        "// Imported: <VirtualHost>, ServerName/ServerAlias, ProxyPass,"
    )?;
    writeln!(
        out,
        "// SSLCertificateFile/SSLCertificateKeyFile. Zentinel defaults apply to"
    )?;
    writeln!(
        out,
        "// everything else (timeouts, limits, health checks, observability)."
    )?;
    writeln!(
        out,
        "// Route priority is {BASE_ROUTE_PRIORITY} + path-prefix length so longer prefixes win."
    )?;
    writeln!(out, "// Review before production use.")?;
    if !notes.is_empty() {
        writeln!(out, "//")?;
        writeln!(
            out,
            "// NOT IMPORTED (stays on the backend / needs manual attention):"
        )?;
        for note in notes.iter() {
            writeln!(
                out,
                "//   line {}: {} — {}",
                note.line, note.directive, note.detail
            )?;
        }
    }
    writeln!(out)?;
    // Apache has no equivalent of these; explicit values beat hidden defaults.
    writeln!(out, "system {{")?;
    writeln!(out, "    worker-threads 0 // 0 = auto-detect CPU count")?;
    writeln!(out, "    max-connections 10000")?;
    writeln!(out, "}}")?;
    writeln!(out)?;
    writeln!(out, "listeners {{")?;
    out.push_str(&listeners_kdl);
    writeln!(out, "}}")?;
    if route_count > 0 {
        writeln!(out)?;
        writeln!(out, "routes {{")?;
        out.push_str(&routes_kdl);
        writeln!(out, "}}")?;
    }
    if !upstream_names.is_empty() {
        writeln!(out)?;
        writeln!(out, "upstreams {{")?;
        out.push_str(&upstreams_kdl);
        writeln!(out, "}}")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# global directives are reported, not imported
ServerRoot "/etc/httpd"
Listen 80
Listen 443

<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
    ProxyPass /api/ https://api.internal:9443/api/
    ProxyPass / http://127.0.0.1:8080/
    RewriteEngine on
    RewriteRule ^/old$ /new [R=301]
</VirtualHost>
"#;

    fn import(content: &str) -> (Vec<VirtualHost>, Vec<Note>, String) {
        let mut notes = Vec::new();
        let vhosts = parse_apache(content, &mut notes).expect("parse should succeed");
        let kdl = emit_kdl(&vhosts, &mut notes, "test.conf").expect("emit should succeed");
        (vhosts, notes, kdl)
    }

    #[test]
    fn parse_extracts_vhost_with_all_mapped_directives() {
        let mut notes = Vec::new();
        let vhosts = parse_apache(SAMPLE, &mut notes).unwrap();

        assert_eq!(vhosts.len(), 2);
        let https = &vhosts[1];
        assert_eq!(https.server_name.as_deref(), Some("example.com"));
        assert_eq!(https.cert_file.as_deref(), Some("/etc/ssl/example.crt"));
        assert_eq!(https.key_file.as_deref(), Some("/etc/ssl/example.key"));
        assert!(https.ssl_engine);
        assert_eq!(https.proxy_passes.len(), 2);
        assert_eq!(https.proxy_passes[0].path, "/api/");
        assert!(https.proxy_passes[0].target.tls);
        assert_eq!(https.proxy_passes[0].target.host, "api.internal");
        assert_eq!(https.proxy_passes[0].target.port, 9443);
    }

    #[test]
    fn parse_records_unmapped_directives_with_line_numbers() {
        let mut notes = Vec::new();
        parse_apache(SAMPLE, &mut notes).unwrap();

        let directives: Vec<&str> = notes.iter().map(|n| n.directive.as_str()).collect();
        assert!(directives.iter().any(|d| d.starts_with("ServerRoot")));
        assert!(directives.iter().any(|d| d.starts_with("ProxyPassReverse")));
        assert!(directives.iter().any(|d| d.starts_with("RewriteRule")));
        let rewrite = notes
            .iter()
            .find(|n| n.directive.starts_with("RewriteRule"))
            .unwrap();
        assert_eq!(rewrite.line, 22);
    }

    #[test]
    fn parse_skips_nested_sections_entirely() {
        let conf = r#"
<VirtualHost *:80>
    ServerName example.com
    <IfModule mod_proxy.c>
        <Location /admin>
            ProxyPass / http://hidden:9999/
        </Location>
    </IfModule>
    ProxyPass / http://visible:8080/
</VirtualHost>
"#;
        let mut notes = Vec::new();
        let vhosts = parse_apache(conf, &mut notes).unwrap();

        assert_eq!(vhosts[0].proxy_passes.len(), 1);
        assert_eq!(vhosts[0].proxy_passes[0].target.host, "visible");
        let section_notes: Vec<_> = notes
            .iter()
            .filter(|n| n.detail.contains("section skipped"))
            .collect();
        assert_eq!(section_notes.len(), 1);
        assert!(section_notes[0].directive.contains("IfModule"));
    }

    #[test]
    fn parse_joins_line_continuations() {
        let conf = "<VirtualHost *:80>\nServerName example.com\nProxyPass \\\n    /app \\\n    http://backend:8080/app\n</VirtualHost>\n";
        let mut notes = Vec::new();
        let vhosts = parse_apache(conf, &mut notes).unwrap();

        assert_eq!(vhosts[0].proxy_passes.len(), 1);
        assert_eq!(vhosts[0].proxy_passes[0].path, "/app");
    }

    #[test]
    fn parse_fails_on_unclosed_virtualhost() {
        let mut notes = Vec::new();
        let err = parse_apache("<VirtualHost *:80>\nServerName x.com\n", &mut notes).unwrap_err();
        assert!(err.to_string().contains("unclosed <VirtualHost>"));
    }

    #[test]
    fn parse_fails_on_stray_closing_tag() {
        let mut notes = Vec::new();
        let err = parse_apache("</VirtualHost>\n", &mut notes).unwrap_err();
        assert!(err.to_string().contains("without matching"));
    }

    #[test]
    fn server_name_is_stripped_of_scheme_and_port() {
        let conf = "<VirtualHost *:80>\nServerName https://example.com:443\nProxyPass / http://b:8080\n</VirtualHost>\n";
        let mut notes = Vec::new();
        let vhosts = parse_apache(conf, &mut notes).unwrap();
        assert_eq!(vhosts[0].server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn emitted_kdl_round_trips_through_config_parser() {
        let (_, _, kdl) = import(SAMPLE);

        let config = Config::from_kdl(&kdl).expect("generated KDL must parse");
        config.validate().expect("generated config must validate");

        assert_eq!(config.listeners.len(), 2);
        assert_eq!(config.routes.len(), 4);
        assert_eq!(config.upstreams.len(), 2);

        let https = config
            .listeners
            .iter()
            .find(|l| l.address.ends_with(":443"))
            .expect("https listener");
        let tls = https.tls.as_ref().expect("tls block");
        assert_eq!(
            tls.cert_file.as_deref(),
            Some(Path::new("/etc/ssl/example.crt"))
        );
        assert!(kdl.contains("host \"example.com\""));
        assert!(kdl.contains("host \"www.example.com\""));
    }

    #[test]
    fn https_vhosts_on_same_address_emit_sni_certificates() {
        let conf = r#"
<VirtualHost *:443>
    ServerName a.example.com
    SSLCertificateFile /etc/ssl/a.crt
    SSLCertificateKeyFile /etc/ssl/a.key
    ProxyPass / http://a-backend:8080
</VirtualHost>
<VirtualHost *:443>
    ServerName b.example.com
    ServerAlias b-alt.example.com
    SSLCertificateFile /etc/ssl/b.crt
    SSLCertificateKeyFile /etc/ssl/b.key
    ProxyPass / http://b-backend:8080
</VirtualHost>
"#;
        let (_, _, kdl) = import(conf);

        let config = Config::from_kdl(&kdl).expect("generated KDL must parse");
        assert_eq!(config.listeners.len(), 1);
        let tls = config.listeners[0].tls.as_ref().expect("tls block");
        assert_eq!(tls.cert_file.as_deref(), Some(Path::new("/etc/ssl/a.crt")));
        assert_eq!(tls.additional_certs.len(), 1);
        assert_eq!(
            tls.additional_certs[0].hostnames,
            vec!["b.example.com".to_string(), "b-alt.example.com".to_string()]
        );
        assert_eq!(
            tls.additional_certs[0].cert_file.as_deref(),
            Some(Path::new("/etc/ssl/b.crt"))
        );
    }

    #[test]
    fn proxy_pass_path_mismatch_is_reported() {
        let conf = "<VirtualHost *:80>\nServerName x.com\nProxyPass /api http://b:8080/app\n</VirtualHost>\n";
        let (_, notes, _) = import(conf);

        assert!(notes.iter().any(|n| n.detail.contains("not preserved")));
    }

    #[test]
    fn balancer_target_is_reported_not_dropped() {
        let conf = "<VirtualHost *:80>\nServerName x.com\nProxyPass / balancer://cluster/\n</VirtualHost>\n";
        let (_, notes, kdl) = import(conf);

        assert!(notes.iter().any(|n| n.detail.contains("balancer")));
        assert!(notes
            .iter()
            .any(|n| n.detail.contains("no importable ProxyPass")));
        let config = Config::from_kdl(&kdl).expect("generated KDL must parse");
        assert!(config.routes.is_empty());
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn cert_without_key_fails_loudly() {
        let conf = "<VirtualHost *:443>\nServerName x.com\nSSLCertificateFile /a.crt\nProxyPass / http://b:8080\n</VirtualHost>\n";
        let mut notes = Vec::new();
        let vhosts = parse_apache(conf, &mut notes).unwrap();
        let err = emit_kdl(&vhosts, &mut notes, "test.conf").unwrap_err();
        assert!(err.to_string().contains("SSLCertificateKeyFile"));
    }

    #[test]
    fn longer_prefixes_get_higher_priority() {
        let (_, _, kdl) = import(SAMPLE);

        let config = Config::from_kdl(&kdl).expect("generated KDL must parse");
        let api = config
            .routes
            .iter()
            .find(|r| r.id.contains("api"))
            .expect("api route");
        let root = config
            .routes
            .iter()
            .find(|r| r.id == "example-com-2")
            .expect("root https route");
        assert!(api.priority > root.priority);
    }
}
