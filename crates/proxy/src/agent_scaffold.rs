//! `zentinel agent new` — scaffold a minimal external agent project.
//!
//! Generates a self-contained Rust agent crate (echo-style, based on
//! `agents/echo/`) so a third party goes from "read the protocol docs" to "edit
//! one function". The generated project depends on the published
//! `zentinel-agent-protocol` crate, implements [`AgentHandlerV2`] with a single
//! `on_request_headers` method to edit, and builds a dual-transport binary that
//! serves over a Unix socket or gRPC.
//!
//! [`AgentHandlerV2`]: zentinel_agent_protocol::v2::AgentHandlerV2

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};

/// The published `zentinel-*` crate version the scaffold depends on. Kept in
/// step with the workspace version so a freshly scaffolded agent resolves
/// against a real crates.io release.
const CRATE_VERSION_REQ: &str = "0.6";

/// `zentinel agent ...` — scaffold and manage external agents.
#[derive(Args, Debug)]
pub struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand, Debug)]
enum AgentCommand {
    /// Scaffold a new external agent project.
    New(NewArgs),
}

#[derive(Args, Debug)]
struct NewArgs {
    /// Agent name (lowercase, e.g. "my-waf"); used as the crate name and agent id.
    name: String,

    /// Parent directory to create the project directory in.
    #[arg(long, default_value = ".")]
    path: PathBuf,

    /// Write into the target directory even if it already exists and is non-empty.
    #[arg(long)]
    force: bool,
}

/// Entry point for the `agent` subcommand.
///
/// # Errors
///
/// Returns an error if the name is invalid, the target directory exists and is
/// non-empty without `--force`, or a file cannot be written.
pub fn run_agent_command(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::New(new) => new_agent(&new.name, &new.path, new.force),
    }
}

fn new_agent(name: &str, parent: &Path, force: bool) -> Result<()> {
    validate_name(name)?;
    let pascal = to_pascal_case(name);
    let dir = parent.join(name);

    if dir_is_nonempty(&dir)? && !force {
        bail!(
            "target directory '{}' already exists and is not empty; pass --force to overwrite",
            dir.display()
        );
    }

    let src = dir.join("src");
    fs::create_dir_all(&src).with_context(|| format!("creating {}", src.display()))?;

    write_file(&dir.join("Cargo.toml"), &render(CARGO_TOML, name, &pascal))?;
    write_file(&src.join("main.rs"), &render(MAIN_RS, name, &pascal))?;
    write_file(
        &dir.join("zentinel-agent.toml"),
        &render(MANIFEST_TOML, name, &pascal),
    )?;
    write_file(&dir.join("Dockerfile"), &render(DOCKERFILE, name, &pascal))?;
    write_file(&dir.join("README.md"), &render(README_MD, name, &pascal))?;
    write_file(&dir.join(".gitignore"), "/target\n")?;

    print_next_steps(name, &dir);
    Ok(())
}

/// Validate that `name` is a legal crate name: lowercase ASCII letters, digits
/// and single hyphens, starting with a letter, 1–64 characters.
fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!(
            "invalid agent name '{name}': use lowercase letters, digits and single hyphens, \
             starting with a letter (e.g. 'my-waf')"
        );
    }
    Ok(())
}

/// Convert a hyphen/underscore-separated name to `PascalCase` for a Rust type
/// identifier (`my-waf` -> `MyWaf`).
fn to_pascal_case(name: &str) -> String {
    name.split(['-', '_'])
        .filter(|seg| !seg.is_empty())
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// True if `dir` exists and contains at least one entry.
fn dir_is_nonempty(dir: &Path) -> Result<bool> {
    if !dir.exists() {
        return Ok(false);
    }
    let mut entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    Ok(entries.next().is_some())
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Substitute the template placeholders. Placeholders are chosen so they never
/// collide with Rust/TOML syntax in the template bodies.
fn render(template: &str, name: &str, pascal: &str) -> String {
    template
        .replace("__NAME__", name)
        .replace("__PASCAL__", pascal)
        .replace("__VERSION_REQ__", CRATE_VERSION_REQ)
}

fn print_next_steps(name: &str, dir: &Path) {
    println!("Created agent '{name}' in {}", dir.display());
    println!();
    println!("Next steps:");
    println!("  cd {}", dir.display());
    println!("  cargo build --release");
    println!("  ./target/release/{name} --grpc 0.0.0.0:50051");
    println!();
    println!("Edit `on_request_headers` in src/main.rs — that is where your policy lives.");
    println!("Registration snippet and Docker usage are in the generated README.md.");
}

// ============================================================================
// Templates
// ============================================================================

const CARGO_TOML: &str = r#"[package]
name = "__NAME__"
version = "0.1.0"
edition = "2021"
description = "__NAME__ — a Zentinel external agent"
license = "MIT OR Apache-2.0"

# An empty [workspace] table makes this project self-contained even when it is
# generated inside an existing Cargo workspace.
[workspace]

[[bin]]
name = "__NAME__"
path = "src/main.rs"

[dependencies]
zentinel-agent-protocol = "__VERSION_REQ__"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
clap = { version = "4", features = ["derive", "env"] }
"#;

const MAIN_RS: &str = r#"//! __NAME__ — a Zentinel external agent.
//!
//! The whole policy lives in `on_request_headers`. Edit that one method; the
//! protocol handshake, framing, health checks and draining are handled for you.

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use zentinel_agent_protocol::v2::server::GrpcAgentServerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::{AgentCapabilities, AgentHandlerV2};
use zentinel_agent_protocol::{AgentResponse, EventType, RequestHeadersEvent};

/// Stable identifier the proxy uses for this agent.
const AGENT_ID: &str = "__NAME__";

#[derive(Parser, Debug)]
#[command(author, version, about = "__NAME__ — a Zentinel external agent", long_about = None)]
struct Args {
    /// Unix socket path to listen on (mutually exclusive with --grpc).
    #[arg(short, long, env = "AGENT_SOCKET", conflicts_with = "grpc")]
    socket: Option<PathBuf>,

    /// gRPC address to listen on, e.g. "0.0.0.0:50051" (mutually exclusive with --socket).
    #[arg(short, long, env = "AGENT_GRPC", conflicts_with = "socket")]
    grpc: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short, long, env = "AGENT_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

/// Your agent. Add any state it needs as fields.
struct __PASCAL__Agent;

#[async_trait]
impl AgentHandlerV2 for __PASCAL__Agent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(AGENT_ID, "__NAME__", env!("CARGO_PKG_VERSION"))
            .with_event(EventType::RequestHeaders)
    }

    /// Decide what to do with each incoming request. This is the one method to edit.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // TODO: inspect the request and return a decision. For example:
        //
        //     if event.headers.contains_key("x-blocked") {
        //         return AgentResponse::block(403, Some("blocked by __NAME__".to_string()));
        //     }
        let _ = event;
        AgentResponse::default_allow()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let agent = Box::new(__PASCAL__Agent);

    match (args.socket, args.grpc) {
        (Some(socket), None) => {
            info!(socket = ?socket, "__NAME__ listening on Unix socket");
            UdsAgentServerV2::new(AGENT_ID, socket, agent)
                .run()
                .await
                .context("agent Unix-socket server failed")?;
        }
        (None, Some(grpc_addr)) => {
            let addr = grpc_addr
                .parse()
                .context("invalid --grpc address (expected host:port)")?;
            info!(grpc = %grpc_addr, "__NAME__ listening on gRPC");
            GrpcAgentServerV2::new(AGENT_ID, agent)
                .run(addr)
                .await
                .context("agent gRPC server failed")?;
        }
        _ => anyhow::bail!("specify exactly one of --socket or --grpc"),
    }

    Ok(())
}
"#;

const MANIFEST_TOML: &str = r#"# Zentinel Agent Registry Manifest
[agent]
name = "__NAME__"
version = "0.1.0"
description = "__NAME__ — a Zentinel external agent"
license = "MIT OR Apache-2.0"

[protocol]
version = "2"
events = ["request_headers"]

[compatibility]
zentinel-agent-protocol = "__VERSION_REQ__"
"#;

const DOCKERFILE: &str = r#"# Build stage
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:stable-slim
COPY --from=build /src/target/release/__NAME__ /usr/local/bin/__NAME__
# Serve over gRPC by default; override AGENT_GRPC or pass --socket for a Unix socket.
ENV AGENT_GRPC=0.0.0.0:50051
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/__NAME__"]
"#;

const README_MD: &str = r#"# __NAME__

A minimal [Zentinel](https://github.com/zentinelproxy/zentinel) external agent.
All the policy lives in `on_request_headers` in `src/main.rs` — edit that one
method; the protocol handshake, framing, health and drain are handled for you.

## Build & run

```bash
cargo build --release

# Listen on a Unix socket:
./target/release/__NAME__ --socket /tmp/__NAME__.sock

# ...or on gRPC:
./target/release/__NAME__ --grpc 0.0.0.0:50051
```

## Register with Zentinel

Add the agent to your `zentinel.kdl` and reference it from a route.

Unix socket:

```kdl
agents {
    agent "__NAME__" {
        unix-socket "/tmp/__NAME__.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"
    }
}
```

gRPC:

```kdl
agents {
    agent "__NAME__" {
        grpc address="http://localhost:50051"
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"
    }
}
```

## Conformance

Verify protocol compliance with the Zentinel conformance suite:
<https://github.com/zentinelproxy/zentinel/tree/main/conformance>.

## Docker

```bash
docker build -t __NAME__ .
docker run -p 50051:50051 __NAME__
```
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pascal_case_from_hyphens_and_underscores() {
        assert_eq!(to_pascal_case("my-waf"), "MyWaf");
        assert_eq!(to_pascal_case("rate_limit"), "RateLimit");
        assert_eq!(to_pascal_case("auth"), "Auth");
        assert_eq!(to_pascal_case("a-b-c"), "ABC");
    }

    #[test]
    fn name_validation_accepts_legal_names() {
        for name in ["auth", "my-waf", "geo2", "a"] {
            assert!(validate_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn name_validation_rejects_illegal_names() {
        for name in [
            "",
            "My-Waf",
            "9lives",
            "trailing-",
            "double--dash",
            "has space",
            "under_score",
        ] {
            assert!(validate_name(name).is_err(), "{name} should be rejected");
        }
    }

    #[test]
    fn generates_a_complete_project() {
        let tmp = tempfile::tempdir().unwrap();
        new_agent("my-waf", tmp.path(), false).unwrap();
        let dir = tmp.path().join("my-waf");

        for f in [
            "Cargo.toml",
            "src/main.rs",
            "zentinel-agent.toml",
            "Dockerfile",
            "README.md",
            ".gitignore",
        ] {
            assert!(dir.join(f).is_file(), "missing generated file: {f}");
        }

        let cargo = fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("name = \"my-waf\""));
        assert!(cargo.contains("zentinel-agent-protocol = \"0.6\""));

        let main = fs::read_to_string(dir.join("src/main.rs")).unwrap();
        assert!(main.contains("struct MyWafAgent;"));
        assert!(main.contains("impl AgentHandlerV2 for MyWafAgent"));
        assert!(main.contains("async fn on_request_headers"));
        assert!(main.contains("const AGENT_ID: &str = \"my-waf\";"));

        let readme = fs::read_to_string(dir.join("README.md")).unwrap();
        assert!(readme.contains("agent \"my-waf\""));
        assert!(readme.contains("unix-socket \"/tmp/my-waf.sock\""));
    }

    #[test]
    fn no_placeholders_leak_into_output() {
        let tmp = tempfile::tempdir().unwrap();
        new_agent("edge-guard", tmp.path(), false).unwrap();
        let dir = tmp.path().join("edge-guard");
        for f in [
            "Cargo.toml",
            "src/main.rs",
            "zentinel-agent.toml",
            "Dockerfile",
            "README.md",
        ] {
            let body = fs::read_to_string(dir.join(f)).unwrap();
            assert!(!body.contains("__NAME__"), "unrendered __NAME__ in {f}");
            assert!(!body.contains("__PASCAL__"), "unrendered __PASCAL__ in {f}");
            assert!(
                !body.contains("__VERSION_REQ__"),
                "unrendered __VERSION_REQ__ in {f}"
            );
        }
    }

    #[test]
    fn refuses_to_overwrite_non_empty_dir_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("taken");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("keep.txt"), "important").unwrap();

        let err = new_agent("taken", tmp.path(), false).unwrap_err();
        assert!(err.to_string().contains("already exists and is not empty"));
        // The pre-existing file is untouched.
        assert_eq!(
            fs::read_to_string(dir.join("keep.txt")).unwrap(),
            "important"
        );

        // With --force it proceeds.
        new_agent("taken", tmp.path(), true).unwrap();
        assert!(dir.join("Cargo.toml").is_file());
    }
}
