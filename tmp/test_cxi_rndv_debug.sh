#!/bin/bash
#SBATCH --job-name=ucx-cxi-rndv-dbg
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:02:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_rndv_dbg-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_rndv_dbg.%j.%N.out" \
    bash -c "
echo '=== env ==='
echo \"host: \$(hostname)  rank: \$SLURM_PROCID\"

ulimit -c unlimited
cd \$UCX/tmp/out

echo ''
echo '=== gtest *cxi_tag_rndv* ==='
UCX_HANDLE_ERRORS=bt UCX_LOG_LEVEL=debug \
    stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*cxi_tag_rndv*' 2>&1
echo \"exit status: \$?\"
"
