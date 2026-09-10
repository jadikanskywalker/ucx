#!/bin/bash
#SBATCH --job-name=ucx-cxi-tag-race
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --time=00:05:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/tag-race-%j.out

# Deterministic overflow/search-on-append race reproducer for
# unexpected_hdr_disable. See cxi_two_proc_tag_test.c's file header for
# the full design.
#
# Build once:
#   bash ucx/tmp/test_cxi_tag_race.sh --build
#
# Then submit, one combination at a time (defaults in cxi_tag.c: OVF=1,
# PRI=0 unless overridden here):
#   UCX_CXI_TAG_TEST_OVF_UHD=1 UCX_CXI_TAG_TEST_PRI_UHD=0 sbatch ucx/tmp/test_cxi_tag_race.sh
#   UCX_CXI_TAG_TEST_OVF_UHD=0 UCX_CXI_TAG_TEST_PRI_UHD=1 sbatch ucx/tmp/test_cxi_tag_race.sh
#   UCX_CXI_TAG_TEST_OVF_UHD=1 UCX_CXI_TAG_TEST_PRI_UHD=1 sbatch ucx/tmp/test_cxi_tag_race.sh
#   UCX_CXI_TAG_TEST_OVF_UHD=0 UCX_CXI_TAG_TEST_PRI_UHD=0 sbatch ucx/tmp/test_cxi_tag_race.sh
#
# sbatch inherits the submitting shell's exported env vars by default, so
# the UCX_CXI_TAG_TEST_* settings above reach both ranks. Rebuild the
# transport (cd src/uct/cxi && make && make install) if you've edited
# cxi_tag.c since the last run -- these env vars are read at LE-append
# time, no rebuild needed for that, but always rebuild after any other
# code change.

UCX=/cosmos/nfs/home/jadhicks/ucx
BIN=$UCX/tmp/cxi_two_proc_tag_test

if [[ "${1}" == "--build" ]]; then
    set -euo pipefail
    echo "Building $BIN ..."
    cc -O2 -g \
        -I"$UCX/src" \
        -I"$UCX/build" \
        -I"$UCX/build/src" \
        -L"$UCX/build/lib" \
        -o "$BIN" \
        "$UCX/tmp/cxi_two_proc_tag_test.c" \
        -luct -lucs \
        -Wl,-rpath,"$UCX/build/lib" \
        -Wl,-rpath,"$UCX/build/lib/ucx"
    echo "Built: $BIN"
    exit 0
fi

mkdir -p "$UCX/tmp/out"

echo "=== config: UCX_CXI_TAG_TEST_OVF_UHD=${UCX_CXI_TAG_TEST_OVF_UHD:-<default=1>} UCX_CXI_TAG_TEST_PRI_UHD=${UCX_CXI_TAG_TEST_PRI_UHD:-<default=0>} ==="

srun --output="$UCX/tmp/out/tag-race.%j.%N.out" \
     --export=ALL,UCX_LOG_LEVEL=debug \
     "$BIN" cxi0
