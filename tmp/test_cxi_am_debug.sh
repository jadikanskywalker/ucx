#!/bin/bash
#SBATCH --job-name=ucx-cxi-am-debug
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --time=00:05:00

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/am_debug.%j.%N.out" \
    bash -c "UCX_LOG_LEVEL=info $UCX/test/gtest/gtest \
        --gtest_filter='cxi/test_cxi_am.am_short_multiple/0' 2>&1"
