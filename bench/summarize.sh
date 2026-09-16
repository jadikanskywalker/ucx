#!/bin/bash
# Parses bench/out/*/client.out (one dir per (type,test,layout,transport)
# combination, named by run_perftest.sh) for each run's "Final:" summary
# line and emits a Markdown tcp-vs-cxi comparison table.
#
# Usage: bench/summarize.sh [MANIFEST]
#   MANIFEST  sweep manifest tsv produced by run_sweep.sh
#             (default: most recent bench/out/sweep_manifest.*.tsv)
#
# ucx_perftest's client-side "Final:" line has the columns:
#   Final: <iterations> <p50> <avg_time> <overall_time> \
#          <avg_bw> <overall_bw> <avg_rate> <overall_rate>
# (time is "latency" for pingpong tests, "overhead" for streaming tests;
# same column position either way.) This script reports the "overall"
# columns (time, bandwidth, message rate).

set -u

UCX=/cosmos/nfs/home/jadhicks/ucx
OUT_DIR="$UCX/bench/out"

MANIFEST="${1:-}"
if [[ -z "$MANIFEST" ]]; then
    MANIFEST=$(ls -t "$OUT_DIR"/sweep_manifest.*.tsv 2>/dev/null | head -1)
fi
if [[ -z "$MANIFEST" || ! -f "$MANIFEST" ]]; then
    echo "Error: no manifest found. Pass one explicitly or run run_sweep.sh first." >&2
    exit 1
fi

declare -A TIME_US BW_MBS RATE ALL_KEYS

while IFS=$'\t' read -r jobid type test layout transport; do
    [[ "$jobid" == "job_id" ]] && continue
    dir="$OUT_DIR/${type}_${test}_${layout}_${transport}"
    line=$(grep -m1 '^Final:' "$dir/client.out" 2>/dev/null)
    key="${type}|${test}|${layout}"
    ALL_KEYS["$key"]=1

    if [[ -n "$line" ]]; then
        TIME_US["$key,$transport"]=$(awk '{print $5}' <<< "$line")
        BW_MBS["$key,$transport"]=$(awk '{print $7}' <<< "$line")
        RATE["$key,$transport"]=$(awk '{print $9}' <<< "$line")
    else
        TIME_US["$key,$transport"]="FAILED"
        BW_MBS["$key,$transport"]="FAILED"
        RATE["$key,$transport"]="FAILED"
    fi
done < "$MANIFEST"

{
    echo "| Type | Test | Layout | cxi time (us) | tcp time (us) | cxi BW (MB/s) | tcp BW (MB/s) | cxi msg/s | tcp msg/s |"
    echo "|------|------|--------|---------------|---------------|---------------|---------------|-----------|-----------|"
    for key in "${!ALL_KEYS[@]}"; do
        IFS='|' read -r type test layout <<< "$key"
        echo "| $type | $test | $layout" \
             "| ${TIME_US[$key,cxi]:-N/A} | ${TIME_US[$key,tcp]:-N/A}" \
             "| ${BW_MBS[$key,cxi]:-N/A} | ${BW_MBS[$key,tcp]:-N/A}" \
             "| ${RATE[$key,cxi]:-N/A} | ${RATE[$key,tcp]:-N/A} |"
    done | sort -t'|' -k2,2 -k3,3 -k4,4
}
