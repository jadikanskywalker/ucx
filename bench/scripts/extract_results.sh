#!/bin/bash
#
# Extract ucx_perftest "Final:" results from bench/out/<combo>/client.out
# for every run recorded in one or more sweep manifests, into a single TSV
# for comparing tests and transports side by side.
#
# Usage:
#   bench/scripts/extract_results.sh [--manifest FILE]... [--out FILE]
#
# Options:
#   --manifest FILE   A bench/out/manifest.*.tsv from sweep_perftest.sh.
#                      Repeatable. Default: every bench/out/manifest.*.tsv.
#   --out FILE         Output TSV path (default:
#                       bench/out/results.<timestamp>.tsv).
#   -h, --help          Show this help and exit.
#
# Per manifest row (test, type, transport, device, layout, exit_code), reads
# bench/out/<test>_<type>_<transport>_<device>_<layout>.<jobid>/client.out
# and pulls out the metrics from its "Final:" line -- iterations, latency
# percentile/average/overall, bandwidth average/overall, message rate
# average/overall -- keyed off the column layout on the preceding
# "| Stage ... |" (or "| Test ... |") header line, so a change to
# ucx_perftest's percentile-rank config (-p) is reflected in pctile_rank
# without changing the output schema.
#
# Not every run is expected to have a Final: line (see sweep_perftest.sh:
# tcp jobs for ops it doesn't support will error out or hit their timeout).
# Those rows are still emitted, with empty metric fields, a status of
# no_final_line/missing_client_out/unexpected_final_format, and -- when
# available -- the last line of client.err as a hint.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UCX="$(cd "$SCRIPT_DIR/../.." && pwd)"

MANIFESTS=()
OUT_FILE=""

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest) MANIFESTS+=("$2"); shift 2 ;;
        --out)      OUT_FILE="$2"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "Error: unknown option '$1'" >&2; usage; exit 1 ;;
    esac
done

if [[ ${#MANIFESTS[@]} -eq 0 ]]; then
    shopt -s nullglob
    MANIFESTS=("$UCX"/bench/out/manifest.*.tsv)
    shopt -u nullglob
fi

if [[ ${#MANIFESTS[@]} -eq 0 ]]; then
    echo "Error: no manifest files found (looked for bench/out/manifest.*.tsv)." >&2
    echo "Pass --manifest FILE explicitly, or run sweep_perftest.sh first." >&2
    exit 1
fi

OUT_FILE="${OUT_FILE:-$UCX/bench/out/results.$(date +%Y%m%d-%H%M%S).tsv}"
mkdir -p "$(dirname "$OUT_FILE")"

printf 'test\ttype\ttransport\tdevice\tlayout\tjobid\texit_code\tstatus\titerations\tpctile_rank\tlatency_pctile_usec\tlatency_avg_usec\tlatency_overall_usec\tbw_avg_MBps\tbw_overall_MBps\tmsgrate_avg_pps\tmsgrate_overall_pps\terror\n' \
    > "$OUT_FILE"

# parse_client_out FILE - emit KEY<TAB>VALUE lines for the fields extracted
# from one client.out: PCTILE_RANK, STATUS, and (when STATUS is ok)
# ITER/LAT_PCTILE/LAT_AVG/LAT_OVERALL/BW_AVG/BW_OVERALL/MR_AVG/MR_OVERALL.
#
# Column order below is fixed by print_progress()/print_header() in
# src/tools/perf/perftest_run.c, not re-derived from the (ambiguous --
# "average"/"overall" repeat 3x) header text; only the percentile-rank
# label is read back out of the header, since -p can change it per run.
parse_client_out() {
    awk '
    /^\|[ \t]*(Stage|Test)[ \t]*\|/ {
        n = split($0, f, "|")
        for (i = 1; i <= n; i++) { gsub(/^[ \t]+|[ \t]+$/, "", f[i]) }
        pctile_label = f[4]
        have_header = 1
    }
    /^Final:/ {
        line = $0
        sub(/^Final:[ \t]*/, "", line)
        gsub(/[ \t]+/, " ", line)
        gsub(/^ +| +$/, "", line)
        n = split(line, v, " ")
        final_n = n
        for (i = 1; i <= n; i++) { final[i] = v[i] }
        have_final = 1
    }
    END {
        pr = pctile_label
        gsub(/[^0-9.]/, "", pr)
        print "PCTILE_RANK\t" pr
        if (have_final && final_n == 8) {
            print "STATUS\tok"
            print "ITER\t" final[1]
            print "LAT_PCTILE\t" final[2]
            print "LAT_AVG\t" final[3]
            print "LAT_OVERALL\t" final[4]
            print "BW_AVG\t" final[5]
            print "BW_OVERALL\t" final[6]
            print "MR_AVG\t" final[7]
            print "MR_OVERALL\t" final[8]
        } else if (have_final) {
            print "STATUS\tunexpected_final_format(" final_n ")"
        } else {
            print "STATUS\tno_final_line"
        }
    }
    ' "$1"
}

for manifest in "${MANIFESTS[@]}"; do
    [[ -f "$manifest" ]] || { echo "Warning: manifest not found: $manifest" >&2; continue; }

    # Process substitution, not a trailing pipe: a pipe would run this loop
    # in a subshell, which is harmless here since nothing needs to escape
    # it, but process substitution avoids surprises under set -o pipefail
    # and keeps `read` fed from the manifest instead of stdin.
    while IFS=$'\t' read -r jobid test type transport device layout exit_code; do
        [[ -z "$test" ]] && continue

        combo="${test}_${type}_${transport}_${device}_${layout}"
        dir="$UCX/bench/out/$combo.$jobid"
        client_out="$dir/client.out"
        client_err="$dir/client.err"

        status="ok"
        iter="" pctile_rank="" lat_pctile="" lat_avg="" lat_overall=""
        bw_avg="" bw_overall="" mr_avg="" mr_overall="" error=""

        if [[ ! -f "$client_out" ]]; then
            status="missing_client_out"
        else
            while IFS=$'\t' read -r key value; do
                case "$key" in
                    PCTILE_RANK) pctile_rank="$value" ;;
                    STATUS)      status="$value" ;;
                    ITER)        iter="$value" ;;
                    LAT_PCTILE)  lat_pctile="$value" ;;
                    LAT_AVG)     lat_avg="$value" ;;
                    LAT_OVERALL) lat_overall="$value" ;;
                    BW_AVG)      bw_avg="$value" ;;
                    BW_OVERALL)  bw_overall="$value" ;;
                    MR_AVG)      mr_avg="$value" ;;
                    MR_OVERALL)  mr_overall="$value" ;;
                esac
            done < <(parse_client_out "$client_out")
        fi

        if [[ "$status" != "ok" && -f "$client_err" ]]; then
            error="$(tail -n1 "$client_err" 2>/dev/null || true)"
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$test" "$type" "$transport" "$device" "$layout" "$jobid" "$exit_code" "$status" \
            "$iter" "$pctile_rank" "$lat_pctile" "$lat_avg" "$lat_overall" \
            "$bw_avg" "$bw_overall" "$mr_avg" "$mr_overall" "$error" \
            >> "$OUT_FILE"

        printf '[%s/%s/%s] %s\n' "$test" "$transport" "$device" "$status"
    done < <(tail -n +2 "$manifest")
done

echo
echo "Results: $OUT_FILE"
echo
echo "Status summary:"
tail -n +2 "$OUT_FILE" | cut -f8 | sort | uniq -c | sort -rn
