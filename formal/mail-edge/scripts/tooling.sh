#!/usr/bin/env bash
set -euo pipefail

FORMAL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

TLA_TOOLS_VERSION=1.7.3
TLA_TOOLS_SHA256=ae7a33bbe99e5a3783c28d826d20e0028fc87f5a8cc8f9520afab00eabbc0bb1
TLA_TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v${TLA_TOOLS_VERSION}/tla2tools.jar"
TLC_IMAGE="docker.io/library/eclipse-temurin:21.0.8_9-jre-jammy@sha256:db1689535962d757a5adabf57387584ed543d38c0b9d1fe870123ea362ad73b0"

tool_cache=${MAIL_EDGE_TLA_CACHE:-${TMPDIR:-/tmp}/mail-edge-formal-tools}
mkdir -p "$tool_cache"
tool_cache=$(cd "$tool_cache" && pwd -P)
TLA_TOOLS_JAR="$tool_cache/tla2tools-${TLA_TOOLS_VERSION}.jar"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

fetch_tla_tools() {
    local actual

    if [[ ! -f "$TLA_TOOLS_JAR" ]]; then
        curl --fail --location --silent --show-error --retry 3 \
            --output "$TLA_TOOLS_JAR" "$TLA_TOOLS_URL"
    fi

    actual=$(sha256_file "$TLA_TOOLS_JAR")
    if [[ "$actual" != "$TLA_TOOLS_SHA256" ]]; then
        printf 'tla2tools.jar checksum mismatch: expected %s, got %s\n' \
            "$TLA_TOOLS_SHA256" "$actual" >&2
        return 1
    fi
}

host_java_available() {
    command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1
}

run_tlc() {
    local module=$1
    local config=$2
    local runtime=${TLC_RUNTIME:-auto}
    local host_metadir
    local -a tlc_args

    fetch_tla_tools
    tlc_args=(
        -XX:+UseParallelGC
        -cp /tools/tla2tools.jar
        tlc2.TLC
        -workers 1
        -fp 0
        -metadir /tmp/tlc-states
        -config "/work/$config"
        "/work/$module"
    )

    if [[ "$runtime" == host ]] || { [[ "$runtime" == auto ]] && host_java_available; }; then
        host_metadir=$(mktemp -d "${TMPDIR:-/tmp}/mail-edge-tlc-states.XXXXXX")
        java -XX:+UseParallelGC \
            -cp "$TLA_TOOLS_JAR" \
            tlc2.TLC \
            -workers 1 \
            -fp 0 \
            -metadir "$host_metadir" \
            -config "$FORMAL_DIR/$config" \
            "$FORMAL_DIR/$module"
        return
    fi

    if [[ "$runtime" != auto && "$runtime" != docker ]]; then
        printf 'TLC_RUNTIME must be auto, host, or docker\n' >&2
        return 2
    fi

    docker run --rm \
        --mount "type=bind,src=$FORMAL_DIR,dst=/work,readonly" \
        --mount "type=bind,src=$TLA_TOOLS_JAR,dst=/tools/tla2tools.jar,readonly" \
        "$TLC_IMAGE" java "${tlc_args[@]}"
}
