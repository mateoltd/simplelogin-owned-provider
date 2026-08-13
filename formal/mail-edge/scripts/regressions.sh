#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=tooling.sh
source "$SCRIPT_DIR/tooling.sh"

log_dir=$(mktemp -d "${TMPDIR:-/tmp}/mail-edge-tlc-regressions.XXXXXX")
configs=(
    regressions/ambiguous-resend.cfg
    regressions/duplicate-event.cfg
    regressions/dual-active-generation.cfg
    regressions/reroute-submission.cfg
    regressions/reinject-processed.cfg
    regressions/default-unknown-route.cfg
    regressions/early-blob-delete.cfg
)
invariants=(
    AmbiguousSendIsNeverResentOrRerouted
    ProviderEventAppliedAtMostOnce
    AtMostOneActiveGeneration
    SubmissionKeepsFrozenRoute
    ProcessedIngressIsNotReinjected
    UnknownDomainsHaveNoDefaultRoute
    QueuedBytesRetainedUntilDefinitiveDisposition
)

for index in "${!configs[@]}"; do
    config=${configs[$index]}
    invariant=${invariants[$index]}
    name=$(basename "$config" .cfg)
    log="$log_dir/$name.log"
    printf 'Counterexample %s\n' "$config"

    set +e
    run_tlc MailEdgeRegressions.tla "$config" >"$log" 2>&1
    status=$?
    set -e

    if [[ $status -eq 0 ]]; then
        printf 'expected TLC to reject %s, but it passed\n' "$config" >&2
        tail -n 80 "$log" >&2
        exit 1
    fi
    if ! grep -Fq "Invariant $invariant is violated" "$log"; then
        printf 'TLC failed for the wrong reason in %s\n' "$config" >&2
        tail -n 80 "$log" >&2
        exit 1
    fi
    grep -F "Invariant $invariant is violated" "$log"
done

printf 'All intentional defects produced the expected counterexample. Logs: %s\n' "$log_dir"
