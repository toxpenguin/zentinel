# Fuzzing

Bounded-time fuzzing of Zentinel's highest-value parsers with
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). This crate
is **excluded from the workspace** and requires a **nightly** toolchain.

## Targets

| Target | Exercises | Invariant |
|--------|-----------|-----------|
| `kdl_config` | `Config::from_kdl` — the KDL config grammar | never panics on arbitrary input |
| `agent_request_headers` | `BinaryRequestHeaders::decode` (v2 wire) | never panics on arbitrary bytes |
| `agent_body_chunk` | `BinaryBodyChunk::decode` (v2 wire) | never panics on arbitrary bytes |
| `agent_response` | `BinaryAgentResponse::decode` (v2 wire) | never panics on arbitrary bytes |
| `proxy_protocol` | `proxy_protocol::parse` — HAProxy PROXY v1/v2 header | never panics; v2 encode/decode round-trips |

The agent-protocol decoders are network-facing, so a decoder panic on crafted
bytes is a denial-of-service vector; the config parser takes complex,
untrusted-ish operator input. The PROXY protocol parser reads bytes straight off
an accepted connection before any HTTP parsing, so it is directly attacker-facing
the moment inbound PROXY support is enabled.

## Running

```bash
# Install cargo-fuzz (once) and a nightly toolchain.
cargo install cargo-fuzz --locked
rustup toolchain install nightly

# Seed the KDL corpus from the example configs (optional but faster to explore).
mkdir -p fuzz/corpus/kdl_config && cp config/examples/*.kdl fuzz/corpus/kdl_config/

# Run a target for a bounded time.
cargo +nightly fuzz run kdl_config -- -max_total_time=180

# Reproduce and minimize a crash, if one is found.
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash-file>
```

CI runs each target nightly (bounded) via `.github/workflows/fuzz.yml`.

## Round-trip invariant

The agent targets also assert encode/decode **symmetry**: a successfully decoded
frame, re-encoded and decoded again, yields identical bytes. This requires
deterministic encoding — the v2 encoders sort header/param maps by key before
serializing (`binary.rs`), so `HashMap` iteration order can no longer make the
same logical frame encode to different bytes. (This invariant was originally
surfaced by these fuzz targets and is now enforced.)
