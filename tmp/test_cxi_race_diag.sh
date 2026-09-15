#!/bin/bash
#SBATCH --job-name=ucx-cxi-race-diag
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:15:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_race_diag-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_race_diag.%j.%N.out" \
    bash -c "
ulimit -c unlimited
cd \$UCX/tmp/out
UCX_HANDLE_ERRORS=bt UCX_LOG_LEVEL=debug \
    timeout 180 stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*forced_race*' 2>&1
echo \"exit status: \$?\"
"
