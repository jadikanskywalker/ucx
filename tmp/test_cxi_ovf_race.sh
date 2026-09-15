#!/bin/bash
#SBATCH --job-name=ucx-cxi-ovf-race
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:15:00
#SBATCH --output=/cosmos/nfs/home/jadhicks/ucx/tmp/out/slurm/test_cxi_ovf_race-%j.out

UCX=/cosmos/nfs/home/jadhicks/ucx
mkdir -p "$UCX/tmp/out"

srun --output="$UCX/tmp/out/test_cxi_ovf_race.%j.%N.out" \
    bash -c "
echo '=== env ==='
echo \"host: \$(hostname)  rank: \$SLURM_PROCID\"

ulimit -c unlimited
cd \$UCX/tmp/out

echo ''
echo '=== gtest test_cxi_tag_ovf (ref-count / repost-timing) ==='
UCX_HANDLE_ERRORS=bt UCX_LOG_LEVEL=info \
    stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*test_cxi_tag_ovf*' 2>&1
echo \"exit status: \$?\"

echo ''
echo '=== gtest forced_race_search_delete_vs_priority_append ==='
UCX_HANDLE_ERRORS=bt UCX_LOG_LEVEL=info \
    timeout 120 stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*forced_race*' 2>&1
echo \"exit status: \$?\"

echo ''
echo '=== gtest full *cxi* regression ==='
UCX_HANDLE_ERRORS=bt \
    timeout 300 stdbuf -o0 -e0 $UCX/test/gtest/gtest \
    --gtest_filter='*cxi*' 2>&1
echo \"exit status: \$?\"
"
