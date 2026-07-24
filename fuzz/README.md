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

The agent-protocol decoders are network-facing, so a decoder panic on crafted
bytes is a denial-of-service vector; the config parser takes complex,
untrusted-ish operator input.

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

## Known finding (not yet fixed)

The v2 encoders serialize header maps in **`HashMap` iteration order**, so
encoding the same logical frame twice can produce different bytes
(`BinaryRequestHeaders::encode` at `binary.rs`, and the `Decision::Block` /
`Decision::Challenge` header/param maps in `BinaryAgentResponse::encode`). The
decoders are order-independent, so this is semantically benign for HTTP, but the
non-canonical encoding breaks byte-level reproducibility (frame hashing/caching,
signing) and prevents a `decode(encode(x))` round-trip invariant. Fix: sort map
entries by key before encoding — then a round-trip stability assertion can be
added to these targets.
