# Benchmarks & the regression gate

The agent-protocol crate carries the request hot path, so it owns Zentinel's
only Criterion benchmark suite (`benches/hot_path.rs`) and the CI regression
gate that guards it.

## What the gate does

`.github/workflows/bench.yml` runs on pull requests touching
`crates/agent-protocol/**` (or the gate itself). It benchmarks the PR
**merge-base** and the PR **head** back-to-back on the *same* runner, then fails
the check if a gated benchmark regressed by more than the threshold
(`BENCH_REGRESSION_THRESHOLD`, default **+20%**).

This makes "production correctness beats feature breadth" an enforced budget
rather than a review-time hope (IDEAS.md #10).

### Why same-runner, back-to-back

GitHub-hosted runners vary by up to ~2x across CPU generations. Comparing a run
against a baseline captured in a *prior* CI run (a cache or a `gh-pages` data
branch) bakes that between-machine variance into the number — the gate goes
flaky. Measuring base and head on one physical runner cancels the
between-machine term. It also keeps the gate self-contained: no external action,
no state branch (Manifesto: no hidden control planes, no vendor lock-in).

### Posture: generous hard-fail

The threshold is deliberately loose (+20%). Microbenchmarks on shared CI are
noisy; a tight gate cries wolf, gets muted, and ends up worse than no gate
(Manifesto: calm, no surprises; repo rule: no flaky tests). To make the gate
advisory instead of blocking, add `continue-on-error: true` to the workflow's
"Evaluate regression gate" step.

## What is (and isn't) gated

`hot_path.rs` mixes two kinds of benchmarks:

- **Production-representative** — measure the real per-request path.
- **Comparative** — `vec` vs `smallvec`, `atomic` vs `rwlock`, `json` vs
  `msgpack`. These justify a design choice; a "regression" in the arm we did
  **not** pick is meaningless, so they are **not** gated.

Gated today (see `GATED_BENCHES` in `scripts/bench-gate.py`):

| Benchmark | Why |
|-----------|-----|
| `full_request_path/json_path` | Full per-request path (agent lookup, affinity, health check, counters, serialize) using the **production** wire codec — `UdsEncoding` defaults to JSON; MessagePack is behind the `binary-uds` feature. |

Sub-microsecond and comparative arms (`protocol_metrics`, `health_cache`,
`header_*`, `serialization`/`deserialization`, `msgpack_path`) are excluded:
at CI scale they are noise, not signal.

When proxy routing/filtering benches land, add their ids to `GATED_BENCHES` and
the `BENCH_FILTER` regex in `bench.yml`.

## How the gate reads the result

Criterion writes the baseline comparison to
`target/criterion/<group>/<function>/change/estimates.json` when `cargo bench`
runs with `--baseline`. `scripts/bench-gate.py` reads `mean.point_estimate`
(a fraction: `0.20` == +20% slower), compares it to the threshold, prints a
Markdown table to the GitHub Actions step summary, and exits non-zero on
regression. Missing comparison data is a **hard error** (fail loud) — it means
the benchmark was renamed or the filter drifted, not that nothing regressed.

## Running the gate locally

```bash
# 1. Baseline the code you're comparing against (e.g. main), naming it "base".
git stash                                   # or checkout the base ref
cargo bench -p zentinel-agent-protocol --bench hot_path -- \
    --save-baseline base full_request_path

# 2. Restore your changes and compare against that baseline.
git stash pop                               # or checkout your branch
cargo bench -p zentinel-agent-protocol --bench hot_path -- \
    --baseline base full_request_path

# 3. Evaluate the same gate CI uses.
python3 scripts/bench-gate.py
```

Tune with `BENCH_REGRESSION_THRESHOLD=0.10 python3 scripts/bench-gate.py`.

## Running the full suite

```bash
cargo bench -p zentinel-agent-protocol            # every group
cargo bench -p zentinel-agent-protocol --bench hot_path -- full_request_path
```
