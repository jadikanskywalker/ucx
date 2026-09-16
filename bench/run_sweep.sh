#!/bin/bash
# Submits the full tcp-vs-cxi ucx_perftest comparison matrix via
# bench/run_perftest.sh, one sbatch job per (test, layout, transport)
# combination. See bench/README.md for the matrix definition.
#
# Usage: bench/run_sweep.sh [LOG_LEVEL]

set -u

UCX=/cosmos/nfs/home/jadhicks/ucx
RUN="$UCX/bench/run_perftest.sh"
LOG_LEVEL="${1:-warn}"

mkdir -p "$UCX/bench/out/slurm"
MANIFEST="$UCX/bench/out/sweep_manifest.$(date +%Y%m%d_%H%M%S).tsv"
echo -e "job_id\ttype\ttest\tlayout\ttransport" > "$MANIFEST"

TRANSPORTS=(cxi tcp)

# RMA + AM tests: layout (-D) is meaningful, sweep short/bcopy/zcopy.
UCT_LAYOUT_TESTS=(put_lat put_bw get get_bw am_lat am_bw)
LAYOUTS=(short)

# AMO tests: fixed-width ops, -D has no effect. Single run per transport.
UCT_SINGLE_TESTS=(add_lat add_mr fadd swap cswap)

# UCP-layer tests (application-facing numbers). Excludes ucp_am_bw, which
# is known to deadlock over cxi after a PT_DISABLED burst (see REPORT.md).
UCP_SINGLE_TESTS=(tag_lat tag_bw ucp_put_lat ucp_put_bw ucp_get ucp_add
                   ucp_fadd ucp_swap ucp_cswap ucp_am_lat)

njobs=0

submit() {
    local test="$1" type="$2" layout="$3" transport="$4"
    local name="${type}_${test}_${layout}_${transport}"
    local jobid
    jobid=$(sbatch --parsable \
        --job-name="$name" \
        --output="$UCX/bench/out/slurm/${name}-%j.out" \
        "$RUN" "$test" "$type" "$layout" "$LOG_LEVEL" "$transport")
    echo -e "${jobid}\t${type}\t${test}\t${layout}\t${transport}" >> "$MANIFEST"
    echo "submitted $name -> job $jobid"
    njobs=$((njobs + 1))
}

for transport in "${TRANSPORTS[@]}"; do
    for test in "${UCT_LAYOUT_TESTS[@]}"; do
        for layout in "${LAYOUTS[@]}"; do
            submit "$test" UCT "$layout" "$transport"
        done
    done
    for test in "${UCT_SINGLE_TESTS[@]}"; do
        submit "$test" UCT short "$transport"
    done
    for test in "${UCP_SINGLE_TESTS[@]}"; do
        submit "$test" UCP short "$transport"
    done
done

echo ""
echo "Submitted $njobs jobs. Manifest: $MANIFEST"
echo "Monitor with: squeue -u \$USER"
echo "Once complete, run: bench/summarize.sh $MANIFEST"
