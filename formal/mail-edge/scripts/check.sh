#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=tooling.sh
source "$SCRIPT_DIR/tooling.sh"

log_dir=$(mktemp -d "${TMPDIR:-/tmp}/mail-edge-tlc.XXXXXX")
configs=(
    configs/core-safety.cfg
    configs/binding-independence.cfg
    configs/dedupe-ordering.cfg
    configs/unknown-domain.cfg
    configs/liveness.cfg
)

for config in "${configs[@]}"; do
    name=$(basename "$config" .cfg)
    log="$log_dir/$name.log"
    printf 'TLC %s\n' "$config"
    if ! run_tlc MailEdge.tla "$config" >"$log" 2>&1; then
        tail -n 80 "$log" >&2
        exit 1
    fi
    grep -E 'states generated|distinct states found|Model checking completed|Finished checking temporal properties' "$log" || tail -n 20 "$log"
done

printf 'All positive TLC configurations passed. Logs: %s\n' "$log_dir"
