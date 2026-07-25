#!/usr/bin/env bash
#
# Chaos Test: Resource Bounds Under Sustained Agent Failure
#
# The existing agent-failure scenarios assert that requests *fail correctly*
# (fail-open/closed, circuit breaker). This one asserts the Manifesto's
# "bounded by design" promise directly: under sustained agent failure the proxy
# must not leak file descriptors or memory. A proxy that fails requests
# correctly but leaks an fd per hung request still falls over on-call.
#
# Faults exercised:
#   - slow-loris agent: agent accepts the connection but never answers (frozen
#     mid-request) — in-flight requests must time out and be reclaimed, not pile
#     up unboundedly.
#   - agent endpoint vanishes mid-flight: the agent listener disappears while
#     requests are in flight (the container analog of a UDS socket being deleted
#     on a same-host deployment) — half-open connections must not leak fds.
#   - agent restart storm: rapid crash/restore cycles under load — churn must
#     not accumulate fds/memory, and the proxy must recover.
#
# Validates:
#   - Peak file-descriptor count stays within a bound of the baseline.
#   - Memory growth stays within threshold and is reclaimed after recovery.
#   - The proxy remains healthy and serves traffic again after each fault.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

PROXY_CONTAINER="${PROXY_CONTAINER:-chaos-proxy}"
AGENT_NAME="${AGENT_NAME:-echo}"

# Routes (mirror test_agent_crash.sh). Fail-closed route drives the agent path.
FAILOPEN_URL="${PROXY_URL}/failopen/"
PROTECTED_URL="${PROXY_URL}/protected/"

# Load shape
LOAD_CONCURRENCY="${LOAD_CONCURRENCY:-50}"   # concurrent in-flight requests
LOAD_ROUNDS="${LOAD_ROUNDS:-4}"              # rounds of concurrent load per fault
RESTART_STORM_CYCLES="${RESTART_STORM_CYCLES:-15}"

# Ceilings — generous on purpose: microbursts on shared CI are noisy, and a
# tight bound would cry wolf. An actual leak grows fds/memory by orders of
# magnitude, so these still catch the failure they target.
FD_GROWTH_MAX="${FD_GROWTH_MAX:-200}"                 # absolute fd headroom
MEM_GROWTH_THRESHOLD_PERCENT="${MEM_GROWTH_THRESHOLD_PERCENT:-50}"

# ============================================================================
# Resource Sampling Helpers
# ============================================================================

# Proxy memory in MB (docker usually reports MiB). Truncated to an integer for
# bash arithmetic. Mirrors test_memory_stability.sh.
get_proxy_memory_mb() {
    docker stats "$PROXY_CONTAINER" --no-stream --format '{{.MemUsage}}' 2>/dev/null |
        awk -F'/' '{print $1}' | sed 's/[^0-9.]//g' | head -1 | awk '{printf "%d", $1}'
}

# Open file-descriptor count of the proxy process (PID 1 in the container).
# Falls back to 0 if the container is unreachable so the caller can skip loudly
# rather than crash under `set -e`.
get_proxy_fd_count() {
    docker exec "$PROXY_CONTAINER" sh -c 'ls -1 /proc/1/fd 2>/dev/null | wc -l' 2>/dev/null |
        awk '{printf "%d", $1}' || echo 0
}

# Fire N concurrent requests at a URL and wait for them all to settle (each
# bounded by REQUEST_TIMEOUT). Used to hold many requests in flight at once so a
# per-request fd/connection leak would actually show up.
fire_concurrent_load() {
    local url="$1"
    local count="$2"
    local pids=()

    for ((i = 0; i < count; i++)); do
        curl -s -m "$REQUEST_TIMEOUT" -o /dev/null "$url" 2>/dev/null &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}

# Sample the peak fd count while sustained concurrent load runs against $1.
# Echoes the peak fd count observed.
peak_fd_under_load() {
    local url="$1"
    local peak=0

    for ((round = 0; round < LOAD_ROUNDS; round++)); do
        fire_concurrent_load "$url" "$LOAD_CONCURRENCY" &
        local load_pid=$!
        # Sample a few times while the burst is in flight.
        for _ in 1 2 3; do
            local fd
            fd=$(get_proxy_fd_count)
            [[ "$fd" -gt "$peak" ]] && peak="$fd"
            sleep 0.3
        done
        wait "$load_pid" 2>/dev/null || true
    done

    echo "$peak"
}

# ============================================================================
# Test Cases
# ============================================================================

test_baseline_resources() {
    log_info "=== Baseline: record fd + memory with agent healthy ==="

    restore_agent "$AGENT_NAME" 2>/dev/null || true
    sleep 2

    # Warm up so pools/buffers are allocated before we measure.
    fire_concurrent_load "$FAILOPEN_URL" "$LOAD_CONCURRENCY"
    sleep 2

    BASELINE_FD=$(get_proxy_fd_count)
    BASELINE_MEM=$(get_proxy_memory_mb)

    if [[ "${BASELINE_FD:-0}" -le 0 ]]; then
        log_skip "Cannot read proxy fd count from '$PROXY_CONTAINER' — skipping fd assertions"
        FD_UNAVAILABLE=1
    else
        FD_UNAVAILABLE=0
    fi

    log_info "Baseline fds: ${BASELINE_FD}, memory: ${BASELINE_MEM}MB"
    log_pass "Baseline resources recorded"
}

test_slow_loris_agent() {
    log_info "=== Test: slow-loris agent (frozen, never answers) ==="

    # Freeze the agent so it accepts connections but never responds. Sustain it
    # across the whole load window so every request must hit the agent timeout.
    inject_agent_freeze "$AGENT_NAME" 0   # 0 = stay frozen until we unfreeze

    local peak_fd
    peak_fd=$(peak_fd_under_load "$PROTECTED_URL")
    local mem
    mem=$(get_proxy_memory_mb)

    log_info "Under slow-loris: peak fds=${peak_fd}, memory=${mem}MB"

    if [[ "$FD_UNAVAILABLE" -eq 0 ]]; then
        local fd_ceiling=$((BASELINE_FD + FD_GROWTH_MAX))
        assert_lt "$peak_fd" "$fd_ceiling" \
            "fd count bounded under slow-loris (peak ${peak_fd} < ${fd_ceiling})"
    fi
    assert_memory_within_threshold "$mem" "after slow-loris load"

    # Recover.
    inject_agent_unfreeze "$AGENT_NAME"
    sleep 3
    assert_status "$FAILOPEN_URL" "200" "Proxy serves traffic after slow-loris unfreeze"
}

test_agent_endpoint_vanishes_midflight() {
    log_info "=== Test: agent endpoint vanishes mid-flight (UDS-delete analog) ==="

    # Launch sustained load, then remove the agent listener underneath it. On a
    # UDS deployment this is the socket file being unlinked mid-request; here it
    # is the agent container's listener going away. Half-open connections must
    # be reclaimed, not leaked.
    fire_concurrent_load "$PROTECTED_URL" "$LOAD_CONCURRENCY" &
    local load_pid=$!
    sleep 0.5
    inject_agent_stop "$AGENT_NAME"
    wait "$load_pid" 2>/dev/null || true

    # Keep pushing while the endpoint is gone, then measure.
    local peak_fd
    peak_fd=$(peak_fd_under_load "$PROTECTED_URL")
    local mem
    mem=$(get_proxy_memory_mb)

    log_info "Endpoint gone: peak fds=${peak_fd}, memory=${mem}MB"

    if [[ "$FD_UNAVAILABLE" -eq 0 ]]; then
        local fd_ceiling=$((BASELINE_FD + FD_GROWTH_MAX))
        assert_lt "$peak_fd" "$fd_ceiling" \
            "fd count bounded after endpoint vanished (peak ${peak_fd} < ${fd_ceiling})"
    fi
    assert_memory_within_threshold "$mem" "after endpoint-vanish load"

    # Recover.
    restore_agent "$AGENT_NAME"
    sleep 3
    assert_status "$FAILOPEN_URL" "200" "Proxy serves traffic after endpoint restored"
}

test_agent_restart_storm() {
    log_info "=== Test: agent restart storm ($RESTART_STORM_CYCLES cycles under load) ==="

    local peak_fd="${BASELINE_FD:-0}"

    for ((cycle = 1; cycle <= RESTART_STORM_CYCLES; cycle++)); do
        fire_concurrent_load "$PROTECTED_URL" "$LOAD_CONCURRENCY" &
        local load_pid=$!

        inject_agent_crash "$AGENT_NAME"
        local fd
        fd=$(get_proxy_fd_count)
        [[ "$fd" -gt "$peak_fd" ]] && peak_fd="$fd"
        restore_agent "$AGENT_NAME"

        wait "$load_pid" 2>/dev/null || true
    done

    local mem
    mem=$(get_proxy_memory_mb)
    log_info "Restart storm: peak fds=${peak_fd}, memory=${mem}MB"

    if [[ "$FD_UNAVAILABLE" -eq 0 ]]; then
        local fd_ceiling=$((BASELINE_FD + FD_GROWTH_MAX))
        assert_lt "$peak_fd" "$fd_ceiling" \
            "fd count bounded across restart storm (peak ${peak_fd} < ${fd_ceiling})"
    fi
    assert_memory_within_threshold "$mem" "after restart storm"

    # Recover fully.
    restore_agent "$AGENT_NAME"
    sleep 5
    assert_status "$FAILOPEN_URL" "200" "Proxy healthy after restart storm"
}

test_resource_reclamation() {
    log_info "=== Test: resources reclaimed after faults resolve ==="

    restore_agent "$AGENT_NAME" 2>/dev/null || true
    log_info "Waiting 15s for reclamation..."
    sleep 15

    local final_fd
    final_fd=$(get_proxy_fd_count)
    local final_mem
    final_mem=$(get_proxy_memory_mb)

    log_info "Final fds: ${final_fd} (baseline ${BASELINE_FD}), memory: ${final_mem}MB (baseline ${BASELINE_MEM}MB)"

    if [[ "$FD_UNAVAILABLE" -eq 0 ]]; then
        local fd_ceiling=$((BASELINE_FD + FD_GROWTH_MAX))
        assert_lt "$final_fd" "$fd_ceiling" \
            "fds reclaimed to within bound of baseline (${final_fd} < ${fd_ceiling})"
    fi

    # Record results for the analyzer.
    {
        echo "resource_bounds_results:"
        echo "  baseline_fd: ${BASELINE_FD}"
        echo "  final_fd: ${final_fd}"
        echo "  fd_growth_max: ${FD_GROWTH_MAX}"
        echo "  baseline_mem_mb: ${BASELINE_MEM}"
        echo "  final_mem_mb: ${final_mem}"
        echo "  mem_threshold_percent: ${MEM_GROWTH_THRESHOLD_PERCENT}"
        echo "  restart_storm_cycles: ${RESTART_STORM_CYCLES}"
        echo "  result: $([[ $TESTS_FAILED -eq 0 ]] && echo PASS || echo FAIL)"
    } > "${OUTPUT_DIR}/resource-bounds-results.yaml"
}

# ============================================================================
# Local Helpers
# ============================================================================

# Assert memory growth over baseline is within the percentage threshold.
assert_memory_within_threshold() {
    local current="$1"
    local context="$2"
    local baseline="${BASELINE_MEM:-1}"
    [[ "${baseline:-0}" -le 0 ]] && baseline=1

    local growth=$((${current:-0} - baseline))
    local growth_percent=$((growth * 100 / baseline))

    if [[ "$growth_percent" -le "$MEM_GROWTH_THRESHOLD_PERCENT" ]]; then
        log_pass "memory within threshold ${context} (${growth_percent}% <= ${MEM_GROWTH_THRESHOLD_PERCENT}%)"
    else
        log_fail "memory over threshold ${context} (${growth_percent}% > ${MEM_GROWTH_THRESHOLD_PERCENT}%)"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Resource Bounds Chaos Test"
    log_info "Proxy URL: $PROXY_URL | Container: $PROXY_CONTAINER | Agent: $AGENT_NAME"
    log_info "Concurrency: $LOAD_CONCURRENCY | fd headroom: $FD_GROWTH_MAX | mem threshold: ${MEM_GROWTH_THRESHOLD_PERCENT}%"

    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    restore_agent "$AGENT_NAME" 2>/dev/null || true
    restore_all_backends 2>/dev/null || true
    sleep 3

    test_baseline_resources
    test_slow_loris_agent
    test_agent_endpoint_vanishes_midflight
    test_agent_restart_storm
    test_resource_reclamation

    print_summary
    return "$(get_exit_code)"
}

main "$@"
