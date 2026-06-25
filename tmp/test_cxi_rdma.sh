#!/bin/bash
#SBATCH --job-name=ucx-cxi-rdma
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --time=00:05:00

# Two-process cross-node CXI UCT data-integrity test.
#
# Build the test binary once before submitting:
#   bash ucx/tmp/test_cxi_rdma.sh --build
#
# Then submit:
#   sbatch ucx/tmp/test_cxi_rdma.sh
#
# Output lands in ucx/tmp/cxi_rdma.<jobid>.<node>.{out,err}

UCX=/cosmos/nfs/home/jadhicks/ucx
BIN=$UCX/tmp/cxi_two_proc_test

if [[ "${1}" == "--build" ]]; then
    set -euo pipefail
    echo "Building $BIN ..."
    cc -O2 -g \
        -I"$UCX/src" \
        -I"$UCX/build" \
        -I"$UCX/build/src" \
        -L"$UCX/build/lib" \
        -o "$BIN" \
        "$UCX/tmp/cxi_two_proc_test.c" \
        -luct -lucs \
        -Wl,-rpath,"$UCX/build/lib" \
        -Wl,-rpath,"$UCX/build/lib/ucx"
    echo "Built: $BIN"
    exit 0
fi

srun --output="$UCX/tmp/cxi_rdma.%j.%N.out" \
     "$BIN" cxi0
