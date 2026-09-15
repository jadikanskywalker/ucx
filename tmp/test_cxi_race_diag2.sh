#!/bin/bash
#SBATCH --job-name=ucx-cxi-race-diag2
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:10:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_race_diag2-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_race_diag2.%j.%N.out" \
    bash -c "
ulimit -c unlimited
cd \$UCX/tmp/out
UCX_HANDLE_ERRORS=bt \
    timeout 120 stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*forced_race*' 2>&1
echo \"exit status: \$?\"
"
