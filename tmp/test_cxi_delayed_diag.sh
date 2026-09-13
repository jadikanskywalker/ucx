#!/bin/bash
#SBATCH --job-name=ucx-cxi-delayed-diag
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:05:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_delayed_diag-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_delayed_diag.%j.%N.out" \
    bash -c "
echo '=== env ==='
echo \"host: \$(hostname)  rank: \$SLURM_PROCID\"

ulimit -c unlimited
cd \$UCX/tmp/out

echo ''
echo '=== gtest delayed-match diagnostics ==='
UCX_HANDLE_ERRORS=bt UCX_LOG_LEVEL=debug \
    stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*delayed_match*' 2>&1
echo \"exit status: \$?\"
"
