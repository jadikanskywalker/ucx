#!/bin/bash
#
# Submit the full ucx_perftest test matrix once per transport (cxi/cxi0 and
# tcp/hsn0 by default) via bench/scripts/run_perftest.sh, so results for both
# transports land side by side under bench/out/ for comparison.
#
# Usage:
#   bench/scripts/sweep_perftest.sh [options]
#
# Options:
#   --dry-run              Print the sbatch commands instead of submitting.
#   --tests LIST            Comma-separated test names to run (default: all
#                            tests below). Must be names from the TESTS table.
#   --transports LIST       Comma-separated transport labels to run
#                            (default: cxi,tcp). Must be labels from the
#                            TRANSPORTS table.
#   --layout LAYOUT         short, bcopy, or zcopy (default: short)
#   --log-level LEVEL       UCX_LOG_LEVEL value (default: warn)
#   --sleep SECONDS         Delay between sbatch submissions (default: 0.2)
#   --cxi-device DEVICE     Override the cxi transport's device (default: cxi0)
#   --tcp-device DEVICE     Override the tcp transport's device (default: hsn0
#                            -- the Slingshot NIC over TCP/IP, for a same-
#                            fabric comparison; pass e.g. eth0 to instead
#                            compare against a separate management NIC).
#   -h, --help              Show this help and exit.
#
# Each test's API (UCT vs UCP) is looked up from the TESTS table below,
# mirrored from the `tests[]` table in src/tools/perf/perftest.c -- update
# both if that table changes.
#
# Not every test is expected to succeed on every transport: TCP's UCT
# transport only implements AM (and PUT_ZCOPY when enabled), so GET/ADD/
# FADD/SWAP/CSWAP jobs submitted for tcp will fail fast with an
# "unsupported" error from ucx_perftest -- that failure is itself useful
# signal, so it is submitted anyway rather than silently skipped.
#
# A manifest of jobid -> test/type/transport/device/layout is appended to
# bench/out/manifest.<timestamp>.tsv so results can be correlated after the
# sweep completes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UCX="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUN_SCRIPT="$SCRIPT_DIR/run_perftest.sh"

# name:api, in the order they appear in src/tools/perf/perftest.c's tests[].
ALL_TESTS=(
    "am_lat:UCT"
    "put_lat:UCT"
    "add_lat:UCT"
    "get:UCT"
    "fadd:UCT"
    "swap:UCT"
    "cswap:UCT"
    "am_bw:UCT"
    "put_bw:UCT"
    "get_bw:UCT"
    "add_mr:UCT"
    "tag_lat:UCP"
    "tag_bw:UCP"
    "tag_sync_lat:UCP"
    "tag_sync_bw:UCP"
    "ucp_put_lat:UCP"
    "ucp_put_bw:UCP"
    "ucp_get:UCP"
    "ucp_add:UCP"
    "ucp_fadd:UCP"
    "ucp_swap:UCP"
    "ucp_cswap:UCP"
    "stream_bw:UCP"
    "stream_lat:UCP"
    "ucp_am_lat:UCP"
    "ucp_am_bw:UCP"
)

# label:transport:device
ALL_TRANSPORTS=(
    "cxi:cxi:cxi0"
    "tcp:tcp:hsn0"
)

DRY_RUN=0
TESTS_FILTER=""
TRANSPORTS_FILTER=""
LAYOUT="short"
LOG_LEVEL="warn"
SLEEP="0.2"
CXI_DEVICE_OVERRIDE=""
TCP_DEVICE_OVERRIDE=""

usage() {
    sed -n '2,39p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)      DRY_RUN=1; shift ;;
        --tests)        TESTS_FILTER="$2"; shift 2 ;;
        --transports)   TRANSPORTS_FILTER="$2"; shift 2 ;;
        --layout)       LAYOUT="$2"; shift 2 ;;
        --log-level)    LOG_LEVEL="$2"; shift 2 ;;
        --sleep)        SLEEP="$2"; shift 2 ;;
        --cxi-device)   CXI_DEVICE_OVERRIDE="$2"; shift 2 ;;
        --tcp-device)   TCP_DEVICE_OVERRIDE="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Error: unknown option '$1'" >&2; usage; exit 1 ;;
    esac
done

# lookup NAME ENTRY... - find "NAME:value" in a list of "key:value" entries
# and print the value.
lookup() {
    local name="$1" entry key value
    shift
    for entry in "$@"; do
        key="${entry%%:*}"
        value="${entry#*:}"
        if [[ "$key" == "$name" ]]; then
            echo "$value"
            return 0
        fi
    done
    return 1
}

TESTS=()
if [[ -n "$TESTS_FILTER" ]]; then
    IFS=',' read -ra names <<< "$TESTS_FILTER"
    for name in "${names[@]}"; do
        api="$(lookup "$name" "${ALL_TESTS[@]}")" || {
            echo "Error: unknown test '$name' (not in the TESTS table)" >&2
            exit 1
        }
        TESTS+=("$name:$api")
    done
else
    TESTS=("${ALL_TESTS[@]}")
fi

TRANSPORTS=()
if [[ -n "$TRANSPORTS_FILTER" ]]; then
    IFS=',' read -ra labels <<< "$TRANSPORTS_FILTER"
    for label in "${labels[@]}"; do
        entry="$(printf '%s\n' "${ALL_TRANSPORTS[@]}" | grep "^${label}:")" || {
            echo "Error: unknown transport '$label' (not in the TRANSPORTS table)" >&2
            exit 1
        }
        TRANSPORTS+=("$entry")
    done
else
    TRANSPORTS=("${ALL_TRANSPORTS[@]}")
fi

if [[ -n "$CXI_DEVICE_OVERRIDE" || -n "$TCP_DEVICE_OVERRIDE" ]]; then
    for i in "${!TRANSPORTS[@]}"; do
        label="${TRANSPORTS[$i]%%:*}"
        rest="${TRANSPORTS[$i]#*:}"
        transport="${rest%%:*}"
        if [[ "$label" == "cxi" && -n "$CXI_DEVICE_OVERRIDE" ]]; then
            TRANSPORTS[$i]="$label:$transport:$CXI_DEVICE_OVERRIDE"
        elif [[ "$label" == "tcp" && -n "$TCP_DEVICE_OVERRIDE" ]]; then
            TRANSPORTS[$i]="$label:$transport:$TCP_DEVICE_OVERRIDE"
        fi
    done
fi

mkdir -p "$UCX/bench/out"
MANIFEST="$UCX/bench/out/manifest.$(date +%Y%m%d-%H%M%S).tsv"
if [[ "$DRY_RUN" -eq 0 ]]; then
    printf 'jobid\ttest\ttype\ttransport\tdevice\tlayout\n' > "$MANIFEST"
fi

total=$(( ${#TESTS[@]} * ${#TRANSPORTS[@]} ))
echo "Sweeping ${#TESTS[@]} test(s) x ${#TRANSPORTS[@]} transport(s) = $total job(s)"
[[ "$DRY_RUN" -eq 1 ]] && echo "(dry run -- nothing will be submitted)"
echo

n=0
for transport_entry in "${TRANSPORTS[@]}"; do
    label="${transport_entry%%:*}"
    rest="${transport_entry#*:}"
    transport="${rest%%:*}"
    device="${rest#*:}"

    for test_entry in "${TESTS[@]}"; do
        test="${test_entry%%:*}"
        type="${test_entry#*:}"
        n=$((n + 1))

        cmd=(sbatch --parsable
             --job-name="pt-${test}-${label}"
             "$RUN_SCRIPT" "$test" "$type" "$transport" "$device" "$LAYOUT" "$LOG_LEVEL")

        printf '[%d/%d] %s %s %s ' "$n" "$total" "$test" "$type" "$label"
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%s\n' "-> ${cmd[*]}"
            continue
        fi

        jobid="$("${cmd[@]}")"
        printf '%s\n' "-> job $jobid"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$jobid" "$test" "$type" "$transport" "$device" "$LAYOUT" >> "$MANIFEST"

        sleep "$SLEEP"
    done
done

if [[ "$DRY_RUN" -eq 0 ]]; then
    echo
    echo "Manifest: $MANIFEST"
fi
