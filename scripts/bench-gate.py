#!/usr/bin/env python3
"""Benchmark regression gate for Zentinel's agent-protocol hot path.

Reads Criterion's baseline-comparison output (written when ``cargo bench`` runs
with ``--baseline``) and fails if any gated benchmark regressed beyond the
threshold. Emits a Markdown table to the GitHub Actions step summary.

Invoked by ``.github/workflows/bench.yml`` after benchmarking the PR merge-base
and head back-to-back on the same runner. See
``crates/agent-protocol/docs/benchmarks.md`` for the rationale and local usage.

No third-party dependencies (stdlib only) so it runs on a bare runner.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Criterion benchmark IDs (``group/function``) to gate. These are the
# production-representative hot-path benches, NOT the vec-vs-smallvec /
# atomic-vs-rwlock / json-vs-msgpack comparison arms in ``hot_path.rs`` (those
# exist to justify a design choice; a "regression" in the arm we did NOT pick is
# meaningless). ``json_path`` is the production wire codec (``UdsEncoding``
# defaults to JSON; MessagePack is behind the ``binary-uds`` feature). The
# ``route_match`` arms are the per-request routing decision from
# ``crates/proxy/benches/routing.rs``: LRU steady state and full-table
# evaluation. Which benches actually ran depends on which crate paths the PR
# touched (see bench.yml); benches whose crate was not benched are reported as
# skipped, not failed.
GATED_BENCHES = [
    "full_request_path/json_path",  # full per-request path, production JSON codec
    "route_match/cache_hit",  # routing steady state (LRU hit)
    "route_match/cache_miss",  # routing worst case (full table evaluation)
]

CRITERION_ROOT = Path(os.environ.get("CRITERION_ROOT", "target/criterion"))
# Fail if relative regression exceeds this fraction (0.20 = 20% slower).
# Generous on purpose: microbenchmarks on shared CI runners are noisy, and a
# tight gate that cries wolf gets muted — worse than no gate (Manifesto: calm,
# no surprises; repo rule: no flaky tests).
THRESHOLD = float(os.environ.get("BENCH_REGRESSION_THRESHOLD", "0.20"))


def _mean_point(estimates_path: Path) -> float | None:
    """Return the ``mean.point_estimate`` from a Criterion estimates file, or None."""
    try:
        data = json.loads(estimates_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return float(data["mean"]["point_estimate"])
    except (KeyError, TypeError, ValueError):
        return None


def _fmt_ns(ns: float | None) -> str:
    if ns is None:
        return "n/a"
    if ns >= 1000.0:
        return f"{ns / 1000.0:.2f} µs"
    return f"{ns:.1f} ns"


def main() -> int:
    rows: list[tuple[str, str, str, str, str]] = []
    failures: list[tuple[str, float]] = []
    missing: list[str] = []

    for bench in GATED_BENCHES:
        bench_dir = CRITERION_ROOT / bench
        if not bench_dir.exists():
            # The whole bench group never ran this job — its crate was not in
            # the PR's bench scope (see the path filters in bench.yml). That is
            # expected, not a gate failure.
            rows.append((bench, "—", "—", "—", "⏭️ skipped (crate not benched)"))
            continue

        # ``change/estimates.json`` holds the relative diff vs the baseline;
        # ``mean.point_estimate`` is a fraction (0.20 == +20% slower).
        change = _mean_point(bench_dir / "change" / "estimates.json")
        new_ns = _mean_point(bench_dir / "new" / "estimates.json")
        base_ns = _mean_point(bench_dir / "base" / "estimates.json")

        if change is None:
            # Fail loud: no comparison data means the gate did not actually run
            # for this bench (renamed? filter wrong? baseline missing?).
            missing.append(bench)
            rows.append((bench, _fmt_ns(base_ns), _fmt_ns(new_ns), "—", "⚠️ no data"))
            continue

        pct = change * 100.0
        regressed = change > THRESHOLD
        if regressed:
            verdict = "❌ regressed"
            failures.append((bench, pct))
        elif change >= 0:
            verdict = "✅ ok"
        else:
            verdict = "✅ faster"
        rows.append((bench, _fmt_ns(base_ns), _fmt_ns(new_ns), f"{pct:+.1f}%", verdict))

    lines = [
        f"## Hot-path benchmark gate (threshold: +{THRESHOLD * 100:.0f}%)",
        "",
        "| Benchmark | Base | PR | Change (mean) | Verdict |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, base, new, change_str, verdict in rows:
        lines.append(f"| `{name}` | {base} | {new} | {change_str} | {verdict} |")
    lines.append("")
    if missing:
        lines.append(
            "> ⚠️ No comparison data for: "
            + ", ".join(f"`{b}`" for b in missing)
            + ". Did the bench filter or name change?"
        )
    if failures:
        lines.append("")
        lines.append("**Regression gate FAILED:**")
        for name, pct in failures:
            lines.append(f"- `{name}` regressed {pct:+.1f}% (> +{THRESHOLD * 100:.0f}%)")

    report = "\n".join(lines)
    print(report)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")

    if missing:
        print(
            f"\nERROR: missing comparison data for {len(missing)} gated bench(es).",
            file=sys.stderr,
        )
        return 2
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
